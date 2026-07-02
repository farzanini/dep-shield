//go:build wails

// Package main — Wails application backend.
//
// App is the single struct bound to the Wails frontend.  Every exported
// method on *App becomes a callable function in the frontend's TypeScript
// bindings.
//
// Scan pipeline (mirrors cmd/scan.go, but event-driven):
//
//	StartScan(path)
//	    │
//	    ▼ goroutine
//	scanner.New → emits scan:progress{phase:"walking", …}
//	    │
//	    ▼
//	parser.Dispatcher → emits scan:progress{phase:"parsing", …}
//	    │
//	    ▼
//	cve.Client → emits scan:progress{phase:"querying", …}
//	    │
//	    ▼
//	scorer.Scorer → emits scan:complete
//	    │
//	    ▼
//	results stored in app.results (retrieved later via GetResults)
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	wailsrt "github.com/wailsapp/wails/v2/pkg/runtime"
	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/cve"
	"github.com/dep-shield/dep-shield/internal/models"
	"github.com/dep-shield/dep-shield/internal/parser"
	"github.com/dep-shield/dep-shield/internal/reporter"
	"github.com/dep-shield/dep-shield/internal/scanner"
	"github.com/dep-shield/dep-shield/internal/scorer"
)

// ── Shared types (serialised to JSON for the frontend) ────────────────────────

// ScanProgress is emitted on the "scan:progress" event while a scan is running.
type ScanProgress struct {
	Phase   string  `json:"phase"`   // "walking" | "parsing" | "querying" | "scoring" | "done" | "error"
	Found   int     `json:"found"`   // dependency directories located so far
	Parsed  int     `json:"parsed"`  // packages successfully parsed
	Queried int     `json:"queried"` // packages queried against CVE databases
	Percent float64 `json:"percent"` // 0–100; approximate
	Current string  `json:"current"` // path or package name currently being processed
	Message string  `json:"message"` // human-readable status line
	Error   string  `json:"error,omitempty"`
}

// ScoredVuln is the flattened, JSON-friendly representation of one finding
// returned by GetResults.  It merges models.Vulnerability with the extra
// fields computed by the scorer so the frontend never needs to join data.
type ScoredVuln struct {
	ID                 string   `json:"id"`
	CVE                string   `json:"cve"`         // "CVE-2021-44228" or "" for GHSA-only entries
	Severity           string   `json:"severity"`    // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
	CVSS               float64  `json:"cvss"`
	NormScore          float64  `json:"normScore"`
	Package            string   `json:"package"`
	Version            string   `json:"version"`
	Ecosystem          string   `json:"ecosystem"`
	FixedIn            string   `json:"fixedIn"`
	HasFix             bool     `json:"hasFix"`
	FixAdvice          string   `json:"fixAdvice"`
	Summary            string   `json:"summary"`
	References         []string `json:"references"`
	DaysSincePublished int      `json:"daysSincePublished"`
	Source             string   `json:"source"`      // "project" | "vscode-ext" | "cursor-ext" | "global" | "system"
	SourceLabel        string   `json:"sourceLabel"` // human-readable label
	Path               string   `json:"path"`        // where the package was found (e.g. the node_modules dir)
	RepoPath           string   `json:"repoPath"`    // directory the fix command should be run in (project root)
}

// FixSuggestion is returned by GetSuggestedFix.
type FixSuggestion struct {
	Package     string `json:"package"`
	Current     string `json:"current"`
	Recommended string `json:"recommended"`
	ChangeType  string `json:"changeType"` // "patch" | "minor" | "major" | "unknown"
	Advice      string `json:"advice"`
}

// ── App ───────────────────────────────────────────────────────────────────────

// App holds all state for the Wails application.
// The wails runtime context is stored in ctx so that goroutines started by
// App methods can emit events back to the frontend.
type App struct {
	ctx        context.Context    // set by startup(); used for wails runtime calls
	log        *zap.Logger
	mu         sync.RWMutex
	results    []models.Vulnerability // protected by mu
	rawPkgs    []parser.Package       // protected by mu; kept for GetSuggestedFix
	scanCancel context.CancelFunc     // cancels the running scan, if any
}

// NewApp constructs the App.  Called once from main_wails.go.
func NewApp() *App {
	log, _ := zap.NewDevelopment()
	return &App{log: log}
}

// startup is called by the Wails runtime after the window is ready.
// The ctx it receives is the Wails runtime context — it must be stored here
// and used in EventsEmit calls.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// shutdown is called by the Wails runtime when the window closes.
func (a *App) shutdown(_ context.Context) {
	if a.scanCancel != nil {
		a.scanCancel()
	}
	_ = a.log.Sync()
}

// ── Exported methods (bound to the frontend) ──────────────────────────────────

// StartScan begins an asynchronous scan of path.
//
// The method returns immediately; progress is streamed to the frontend via
// Wails events:
//
//	"scan:progress"  — ScanProgress payload, emitted frequently
//	"scan:complete"  — emitted once when the scan finishes (or fails)
//
// Calling StartScan while a scan is already running cancels the existing scan
// before starting the new one.
func (a *App) StartScan(path string) {
	// Cancel any in-progress scan.
	if a.scanCancel != nil {
		a.scanCancel()
	}

	a.mu.Lock()
	a.results = nil
	a.rawPkgs = nil
	a.mu.Unlock()

	scanCtx, cancel := context.WithCancel(context.Background())
	a.scanCancel = cancel

	go a.runScan(scanCtx, path)
}

// StartScanRepo clones a remote git repository and scans the checkout. url may
// be an https:// URL (token used for private repos) or an SSH URL (git@… /
// ssh://…, authenticated via the user's SSH keys). Progress is streamed via the
// same "scan:progress" / "scan:complete" events as StartScan.
func (a *App) StartScanRepo(url, token string) {
	if a.scanCancel != nil {
		a.scanCancel()
	}

	a.mu.Lock()
	a.results = nil
	a.rawPkgs = nil
	a.mu.Unlock()

	scanCtx, cancel := context.WithCancel(context.Background())
	a.scanCancel = cancel

	go a.runRepoScan(scanCtx, url, token)
}

// runRepoScan clones url into a temp directory, scans it, then removes it.
func (a *App) runRepoScan(ctx context.Context, url, token string) {
	a.emit("scan:progress", ScanProgress{
		Phase:   "cloning",
		Percent: 0,
		Message: "Cloning repository…",
		Current: url,
	})

	dir, cleanup, err := cloneRepo(ctx, url, token, a.log)
	if err != nil {
		a.emit("scan:progress", ScanProgress{
			Phase:   "error",
			Message: "Could not clone repository",
			Error:   err.Error(),
			Percent: 0,
		})
		a.emit("scan:complete", false)
		a.log.Error("clone failed", zap.Error(err))
		return
	}
	defer cleanup()

	a.runScan(ctx, dir)
}

// GetResults returns the vulnerability findings from the most recent completed
// scan.  Returns nil (JSON: null) if no scan has completed yet.
func (a *App) GetResults() []ScoredVuln {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.results == nil {
		return nil
	}

	out := make([]ScoredVuln, 0, len(a.results))
	for _, v := range a.results {
		out = append(out, toScoredVuln(v))
	}
	return out
}

// OpenInBrowser opens url in the system's default browser.
// Used by the frontend to let users navigate to CVE references.
func (a *App) OpenInBrowser(url string) {
	wailsrt.BrowserOpenURL(a.ctx, url)
}

// SelectDirectory shows a native OS folder-picker dialog and returns the
// selected path, or "" if the user cancelled.
func (a *App) SelectDirectory() (string, error) {
	home, _ := os.UserHomeDir()
	dir, err := wailsrt.OpenDirectoryDialog(a.ctx, wailsrt.OpenDialogOptions{
		Title:            "Select project directory",
		DefaultDirectory: home,
	})
	if err != nil {
		return "", err
	}
	return dir, nil
}

// RepoHit describes one package-repository directory found by DiscoverRepos.
type RepoHit struct {
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem"` // "npm" | "Go" | "crates.io" | "PyPI" | "RubyGems"
	Label     string `json:"label"`     // short human description
}

// DiscoverRepos does a shallow walk of root looking for package-repository
// directories or lockfiles and returns them sorted by path.
// Depth is limited to 6 levels so it remains fast even on large trees.
// Returns an error if root does not exist or cannot be read.
func (a *App) DiscoverRepos(root string) ([]RepoHit, error) {
	// Expand ~ and $HOME/$USERPROFILE.
	home, _ := os.UserHomeDir()
	if home != "" {
		root = strings.ReplaceAll(root, "~", home)
	}
	root = os.ExpandEnv(root)

	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("path does not exist: %s", root)
	}

	var hits []RepoHit
	seen := map[string]bool{}

	const maxDepth = 6

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			full := filepath.Join(dir, name)

			// Skip hidden dirs (except known package-cache parents) and
			// common noise directories that would slow down the walk.
			if name == ".git" || name == ".idea" || name == "__pycache__" ||
				name == ".DS_Store" || name == "dist" || name == "build" ||
				name == ".cache" || name == "tmp" || name == "temp" {
				continue
			}

			if !e.IsDir() {
				// Detect lockfiles in the current dir.
				switch name {
				case "go.mod":
					if !seen[dir] {
						seen[dir] = true
						hits = append(hits, RepoHit{Path: dir, Ecosystem: "Go", Label: "Go module"})
					}
				case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
					if !seen[dir] {
						seen[dir] = true
						hits = append(hits, RepoHit{Path: dir, Ecosystem: "npm", Label: "Node project (lockfile)"})
					}
				case "Cargo.lock":
					if !seen[dir] {
						seen[dir] = true
						hits = append(hits, RepoHit{Path: dir, Ecosystem: "crates.io", Label: "Rust project"})
					}
				case "requirements.txt", "Pipfile.lock", "pyproject.toml":
					if !seen[dir] {
						seen[dir] = true
						hits = append(hits, RepoHit{Path: dir, Ecosystem: "PyPI", Label: "Python project"})
					}
				case "Gemfile.lock":
					if !seen[dir] {
						seen[dir] = true
						hits = append(hits, RepoHit{Path: dir, Ecosystem: "RubyGems", Label: "Ruby project"})
					}
				}
				continue
			}

			// Detect package-store directories by name.
			switch name {
			case "node_modules":
				if !seen[full] {
					seen[full] = true
					src, lbl := deriveSource(full)
					_ = src
					hits = append(hits, RepoHit{Path: full, Ecosystem: "npm", Label: lbl + " (node_modules)"})
				}
				// Don't recurse into node_modules — it can be enormous.
				continue
			case "vendor":
				// vendor alongside go.mod = Go vendor tree.
				if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
					if !seen[full] {
						seen[full] = true
						hits = append(hits, RepoHit{Path: full, Ecosystem: "Go", Label: "Go vendor"})
					}
					continue
				}
			case "site-packages", ".venv":
				if !seen[full] {
					seen[full] = true
					hits = append(hits, RepoHit{Path: full, Ecosystem: "PyPI", Label: "Python virtualenv"})
				}
				continue
			}

			walk(full, depth+1)
		}
	}

	walk(root, 0)

	// Collapse npm duplicates: a project that has both a lockfile and its own
	// node_modules produces two hits for the same project. The lockfile hit
	// points at the project root (which already covers node_modules when
	// scanned), so drop the redundant node_modules hit whenever a sibling
	// lockfile hit exists. A node_modules with no lockfile is kept.
	lockDirs := map[string]bool{}
	for _, h := range hits {
		if h.Ecosystem == "npm" && filepath.Base(h.Path) != "node_modules" {
			lockDirs[h.Path] = true
		}
	}
	filtered := hits[:0]
	for _, h := range hits {
		if h.Ecosystem == "npm" && filepath.Base(h.Path) == "node_modules" && lockDirs[filepath.Dir(h.Path)] {
			continue
		}
		filtered = append(filtered, h)
	}
	hits = filtered

	return hits, nil
}

// LocationHint is a well-known directory where third-party packages tend to
// accumulate — editor extensions, global package installs, language caches —
// that a user might not think to scan but where vulnerable code often hides.
type LocationHint struct {
	Label string `json:"label"`
	Path  string `json:"path"`
	Note  string `json:"note"` // ecosystem hint, e.g. "npm", "Go"
}

// CommonLocations returns dependency hot-spots that actually exist on the
// current machine, so the UI can offer them as one-click scan targets. Only
// existing directories are returned — the list never contains a dead path.
func (a *App) CommonLocations() []LocationHint {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	j := filepath.Join

	type cand struct{ label, path, note string }
	cands := []cand{
		{"VS Code extensions", j(home, ".vscode", "extensions"), "npm"},
		{"VS Code Insiders extensions", j(home, ".vscode-insiders", "extensions"), "npm"},
		{"VS Code Server extensions (remote/WSL)", j(home, ".vscode-server", "extensions"), "npm"},
		{"Cursor extensions", j(home, ".cursor", "extensions"), "npm"},
		{"Windsurf extensions", j(home, ".windsurf", "extensions"), "npm"},
		{"VSCodium extensions", j(home, ".vscode-oss", "extensions"), "npm"},
		{"npx package cache", j(home, ".npm", "_npx"), "npm"},
		{"Cargo registry", j(home, ".cargo", "registry"), "crates.io"},
		{"Python user packages", j(home, ".local", "lib"), "PyPI"},
	}

	// Go module cache: honour GOPATH if set, else the ~/go default.
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = j(home, "go")
	}
	cands = append(cands, cand{"Go module cache", j(goPath, "pkg", "mod"), "Go"})

	// Global npm installs: Homebrew (Apple Silicon / Intel), /usr/local, and
	// the Windows per-user store under %APPDATA%.
	cands = append(cands,
		cand{"Global npm (Homebrew, Apple Silicon)", "/opt/homebrew/lib/node_modules", "npm"},
		cand{"Global npm (/usr/local)", "/usr/local/lib/node_modules", "npm"},
	)
	if appData := os.Getenv("APPDATA"); appData != "" {
		cands = append(cands, cand{"Global npm (Windows)", j(appData, "npm", "node_modules"), "npm"})
	}

	// nvm keeps a separate global node_modules per installed Node version; offer
	// the newest (versions sort lexically, newest last).
	if matches, _ := filepath.Glob(j(home, ".nvm", "versions", "node", "*", "lib", "node_modules")); len(matches) > 0 {
		latest := matches[len(matches)-1]
		ver := filepath.Base(filepath.Dir(filepath.Dir(latest))) // …/node/<ver>/lib/node_modules
		cands = append(cands, cand{"Global npm (nvm " + ver + ")", latest, "npm"})
	}

	out := make([]LocationHint, 0, len(cands))
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c.path] {
			continue
		}
		if info, err := os.Stat(c.path); err == nil && info.IsDir() {
			seen[c.path] = true
			out = append(out, LocationHint{Label: c.label, Path: c.path, Note: c.note})
		}
	}
	return out
}

// ExportReport prompts the user for a save location and writes an HTML report.
// Returns the path written on success, or an empty string if the user cancelled.
func (a *App) ExportReport() string {
	dest, err := wailsrt.SaveFileDialog(a.ctx, wailsrt.SaveDialogOptions{
		Title:           "Export vulnerability report",
		DefaultFilename: "dep-shield-report.html",
		Filters: []wailsrt.FileFilter{
			{DisplayName: "HTML files", Pattern: "*.html"},
		},
	})
	if err != nil || dest == "" {
		return ""
	}

	a.mu.RLock()
	vulns := make([]models.Vulnerability, len(a.results))
	copy(vulns, a.results)
	a.mu.RUnlock()

	rpt := reporter.New(reporter.Options{Format: string(reporter.FormatHTML), Log: a.log})
	result := models.ScanResult{Vulnerabilities: vulns, TotalPackages: len(vulns)}
	if err := rpt.WriteFile(dest, reporter.FormatHTML, result); err != nil {
		a.log.Error("ExportReport WriteFile failed", zap.Error(err))
		return ""
	}
	return dest
}

// GetSuggestedFix returns a FixSuggestion for the given package+version.
// It searches the most recent scan results for a matching vulnerability and
// derives an upgrade suggestion from the FixedIn field.
func (a *App) GetSuggestedFix(pkgName, version string) FixSuggestion {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, v := range a.results {
		if v.AffectedPkg.Name == pkgName && v.AffectedPkg.Version == version && v.FixedIn != "" {
			return FixSuggestion{
				Package:     pkgName,
				Current:     version,
				Recommended: v.FixedIn,
				ChangeType:  classifyVersionBump(version, v.FixedIn),
				Advice:      buildAdvice(v),
			}
		}
	}

	// No fix found in results — return a generic response.
	return FixSuggestion{
		Package: pkgName,
		Current: version,
		Advice:  fmt.Sprintf("No fix information available for %s@%s.", pkgName, version),
	}
}

// ── Scan pipeline (private) ───────────────────────────────────────────────────

// emit is a helper that fires a Wails event only when the Wails context is set.
// It is safe to call from any goroutine.
func (a *App) emit(event string, data any) {
	if a.ctx != nil {
		wailsrt.EventsEmit(a.ctx, event, data)
	}
}

// runScan executes the full scan pipeline and emits progress events throughout.
// It is called in a goroutine by StartScan.
func (a *App) runScan(ctx context.Context, path string) {
	// Helper: emit progress and log simultaneously.
	progress := func(p ScanProgress) {
		a.emit("scan:progress", p)
		a.log.Info("scan progress",
			zap.String("phase", p.Phase),
			zap.String("message", p.Message))
	}

	fail := func(msg string, err error) {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		a.emit("scan:progress", ScanProgress{
			Phase:   "error",
			Message: msg,
			Error:   errStr,
			Percent: 0,
		})
		a.emit("scan:complete", false)
		a.log.Error(msg, zap.Error(err))
	}

	// ── Phase 1: Walk filesystem ──────────────────────────────────────────────
	progress(ScanProgress{
		Phase:   "walking",
		Percent: 0,
		Message: "Scanning directories…",
		Current: path,
	})

	if path == "" {
		var err error
		path, err = os.UserHomeDir()
		if err != nil {
			fail("Cannot resolve home directory", err)
			return
		}
	}

	w := scanner.New(scanner.Options{
		Roots:      []string{path},
		SkipGlobal: true, // UI scans project dirs, not global caches
		Workers:    runtime.NumCPU(),
		Log:        a.log,
	})

	// Drain the streaming channel so we can report live progress.
	var hits []scanner.DirHit
	found := 0
	for result := range w.Scan(ctx) {
		if ctx.Err() != nil {
			fail("Scan cancelled", ctx.Err())
			return
		}
		found++
		hits = append(hits, scanner.DirHit{
			Path:      result.AbsPath,
			Ecosystem: result.Ecosystem,
		})
		progress(ScanProgress{
			Phase:   "walking",
			Found:   found,
			Percent: 10,
			Message: fmt.Sprintf("Found %d dependency director%s…", found, plural(found, "y", "ies")),
			Current: result.AbsPath,
		})
	}

	// Also detect projects by their committed manifests/lockfiles (go.mod,
	// package-lock.json, Cargo.lock, requirements.txt, …). This catches
	// checkouts — e.g. a freshly cloned repo — that have lockfiles but no
	// installed node_modules/site-packages for the store-based walk to find.
	hits = mergeHits(hits, manifestHits(ctx, path, 8))
	if len(hits) != found {
		found = len(hits)
		progress(ScanProgress{
			Phase:   "walking",
			Found:   found,
			Percent: 15,
			Message: fmt.Sprintf("Found %d dependency location%s…", found, plural(found, "", "s")),
			Current: path,
		})
	}

	if len(hits) == 0 {
		fail("No dependency directories found in "+path, nil)
		return
	}

	// ── Phase 2: Parse lockfiles ──────────────────────────────────────────────
	progress(ScanProgress{
		Phase:   "parsing",
		Found:   found,
		Percent: 25,
		Message: fmt.Sprintf("Parsing lockfiles across %d director%s…", found, plural(found, "y", "ies")),
	})

	p := parser.New(a.log)
	pkgs, err := p.ParseAll(ctx, hits)
	if err != nil && ctx.Err() != nil {
		fail("Scan cancelled during parsing", ctx.Err())
		return
	}

	progress(ScanProgress{
		Phase:   "parsing",
		Found:   found,
		Parsed:  len(pkgs),
		Percent: 40,
		Message: fmt.Sprintf("Parsed %d package%s", len(pkgs), plural(len(pkgs), "", "s")),
	})

	a.mu.Lock()
	a.rawPkgs = pkgs
	a.mu.Unlock()

	// ── Phase 3: Query CVE databases ──────────────────────────────────────────
	progress(ScanProgress{
		Phase:   "querying",
		Found:   found,
		Parsed:  len(pkgs),
		Percent: 50,
		Message: fmt.Sprintf("Querying CVE databases for %d package%s…", len(pkgs), plural(len(pkgs), "", "s")),
	})

	cveClient := cve.NewClient(cve.Options{
		Workers:     runtime.NumCPU() * 2,
		HTTPTimeout: 0, // use cve package default (15 s)
		Log:         a.log,
	})

	modelPkgs := parser.ToModels(pkgs)
	vulns, err := cveClient.QueryAll(ctx, modelPkgs)
	if err != nil && ctx.Err() != nil {
		fail("Scan cancelled during CVE query", ctx.Err())
		return
	}

	progress(ScanProgress{
		Phase:   "querying",
		Found:   found,
		Parsed:  len(pkgs),
		Queried: len(vulns),
		Percent: 80,
		Message: fmt.Sprintf("Found %d potential vulnerabilit%s", len(vulns), plural(len(vulns), "y", "ies")),
	})

	// ── Phase 4: Score and sort ───────────────────────────────────────────────
	progress(ScanProgress{
		Phase:   "scoring",
		Found:   found,
		Parsed:  len(pkgs),
		Queried: len(vulns),
		Percent: 90,
		Message: "Scoring and sorting findings…",
	})

	sc := scorer.New(a.log)
	result, err := sc.Score(vulns, models.SeverityLow)
	if err != nil {
		fail("Scoring failed", err)
		return
	}

	a.mu.Lock()
	a.results = result.Vulnerabilities
	a.mu.Unlock()

	finalCount := len(result.Vulnerabilities)
	progress(ScanProgress{
		Phase:   "done",
		Found:   found,
		Parsed:  len(pkgs),
		Queried: finalCount,
		Percent: 100,
		Message: fmt.Sprintf("Scan complete — %d vulnerabilit%s found across %d package%s",
			finalCount, plural(finalCount, "y", "ies"),
			len(pkgs), plural(len(pkgs), "", "s")),
	})

	a.emit("scan:complete", true)
}

// ── Conversion helpers ────────────────────────────────────────────────────────

// deriveSource classifies a package path into a source type and human label.
// Because scanner.DirHit only carries Path+Ecosystem, we re-derive the source
// from well-known path patterns rather than touching internal/.
func deriveSource(path string) (source, label string) {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "/.vscode/extensions") ||
		strings.Contains(lower, `\.vscode\extensions`):
		return "vscode-ext", "VS Code extension"
	case strings.Contains(lower, "/.cursor/extensions") ||
		strings.Contains(lower, `\.cursor\extensions`):
		return "cursor-ext", "Cursor extension"
	case strings.Contains(lower, "/go/pkg/mod") ||
		strings.Contains(lower, `\go\pkg\mod`) ||
		strings.Contains(lower, "/.cargo/registry") ||
		strings.Contains(lower, `\.cargo\registry`) ||
		strings.Contains(lower, "/.npm/_npx") ||
		strings.Contains(lower, "/site-packages"):
		return "global", "Global cache"
	case strings.Contains(lower, "/usr/") ||
		strings.Contains(lower, "/opt/") ||
		strings.Contains(lower, `/windows/`):
		return "system", "System"
	default:
		return "project", "Project"
	}
}

// toScoredVuln flattens a models.Vulnerability into the JSON type the
// frontend consumes.
func toScoredVuln(v models.Vulnerability) ScoredVuln {
	cveID := ""
	if strings.HasPrefix(v.ID, "CVE-") {
		cveID = v.ID
	} else {
		// Look for a CVE alias in the references list.
		for _, ref := range v.References {
			if idx := strings.Index(ref, "CVE-"); idx >= 0 {
				// Grab "CVE-YYYY-NNNNN" (up to 20 chars to be safe).
				end := idx + 20
				if end > len(ref) {
					end = len(ref)
				}
				candidate := ref[idx:end]
				// Trim anything after the last digit run.
				for i, ch := range candidate {
					if ch != '-' && (ch < '0' || ch > '9') && i > 4 {
						candidate = candidate[:i]
						break
					}
				}
				if strings.HasPrefix(candidate, "CVE-") {
					cveID = candidate
					break
				}
			}
		}
	}

	refs := v.References
	if refs == nil {
		refs = []string{}
	}

	src, srcLabel := deriveSource(v.AffectedPkg.Path)

	// FixAdvice is populated by the scorer; fall back to deriving it locally
	// for any vulnerability that never passed through Score() (e.g. tests).
	advice := v.FixAdvice
	if advice == "" {
		advice = buildAdvice(v)
	}

	return ScoredVuln{
		ID:                 v.ID,
		CVE:                cveID,
		Severity:           string(v.Severity),
		CVSS:               v.CVSS,
		NormScore:          v.NormScore,
		Package:            v.AffectedPkg.Name,
		Version:            v.AffectedPkg.Version,
		Ecosystem:          string(v.AffectedPkg.Ecosystem),
		FixedIn:            v.FixedIn,
		HasFix:             v.FixedIn != "",
		FixAdvice:          advice,
		Summary:            v.Summary,
		References:         refs,
		DaysSincePublished: v.DaysSincePublished,
		Source:             src,
		SourceLabel:        srcLabel,
		Path:               v.AffectedPkg.Path,
		RepoPath:           fixDir(v.AffectedPkg.Path),
	}
}

// fixDir returns the directory a fix command (e.g. `npm install …`) should be
// run in. The npm scanner records the node_modules directory, so the project
// root — where package.json lives — is its parent. For Go/Cargo/PyPI the
// recorded path is already the manifest/project directory, so it's used as-is.
func fixDir(pkgPath string) string {
	if pkgPath == "" {
		return ""
	}
	sep := string(filepath.Separator)
	if i := strings.LastIndex(pkgPath, sep+"node_modules"); i >= 0 {
		return pkgPath[:i]
	}
	if filepath.Base(pkgPath) == "node_modules" {
		return filepath.Dir(pkgPath)
	}
	return pkgPath
}

func buildAdvice(v models.Vulnerability) string {
	if v.FixedIn == "" {
		return fmt.Sprintf("No fix available — consider replacing %s", v.AffectedPkg.Name)
	}
	return fmt.Sprintf("Upgrade %s from %s to %s",
		v.AffectedPkg.Name, v.AffectedPkg.Version, v.FixedIn)
}

// classifyVersionBump returns "patch", "minor", "major", or "unknown" by
// comparing the leading semver components of from and to.
func classifyVersionBump(from, to string) string {
	clean := func(s string) string {
		s = strings.TrimPrefix(s, "v")
		s = strings.TrimPrefix(s, "=")
		if i := strings.IndexAny(s, "-+"); i >= 0 {
			s = s[:i]
		}
		return s
	}
	fromParts := strings.SplitN(clean(from), ".", 3)
	toParts := strings.SplitN(clean(to), ".", 3)
	if len(fromParts) < 3 || len(toParts) < 3 {
		return "unknown"
	}
	if fromParts[0] != toParts[0] {
		return "major"
	}
	if fromParts[1] != toParts[1] {
		return "minor"
	}
	return "patch"
}

// plural returns singular when n == 1, otherwise plural.
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}
