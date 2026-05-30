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
	"runtime"
	"strings"
	"sync"

	wailsrt "github.com/wailsapp/wails/v2/pkg/runtime"
	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/cve"
	"github.com/dep-shield/dep-shield/internal/models"
	"github.com/dep-shield/dep-shield/internal/parser"
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
	CVE                string   `json:"cve"`     // "CVE-2021-44228" or "" for GHSA-only entries
	Severity           string   `json:"severity"` // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
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

	return ScoredVuln{
		ID:        v.ID,
		CVE:       cveID,
		Severity:  string(v.Severity),
		CVSS:      v.CVSS,
		NormScore: v.CVSS, // scorer currently stores NormalisedScore back through Vulnerability
		Package:   v.AffectedPkg.Name,
		Version:   v.AffectedPkg.Version,
		Ecosystem: string(v.AffectedPkg.Ecosystem),
		FixedIn:   v.FixedIn,
		HasFix:    v.FixedIn != "",
		FixAdvice: buildAdvice(v),
		Summary:   v.Summary,
		References: refs,
	}
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
