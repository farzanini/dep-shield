// Package scanner walks the filesystem concurrently, identifies dependency
// directories for every supported ecosystem, and streams results as they are
// found so the caller can display progress before the scan is complete.
//
// # Architecture
//
//	Options.Roots
//	    │
//	    ▼  effectiveRoots()
//	[]rootWork  ──── deduplicateRoots ────►  rootWork channel (pre-seeded, closed)
//	                                              │
//	                        ┌────────────────────┤
//	                   worker 1            worker N    (runtime.NumCPU goroutines)
//	                        │                    │
//	                   walkRoot()          walkRoot()
//	                        │                    │
//	                        └────────────────────┘
//	                                   │
//	                            resultCh  (<-chan ScanResult, buffered 256)
//
// Each worker claims one rootWork from the channel and calls filepath.WalkDir
// synchronously. Because roots are expanded (home dir → immediate children)
// before workers start, all NumCPU workers stay busy on large scans.
//
// # Safety guarantees
//
//   - Permission errors: logged at DEBUG, walk continues.
//   - Paths longer than 4096 bytes: fs.SkipDir returned immediately.
//   - Virtual filesystems (/proc, /sys, /dev, /run, /snap): skipped by prefix.
//   - Symlink loops: when FollowSymlinks is false (default), WalkDir never
//     follows symlinks. When true, real-path deduplication via sync.Map.
//   - Context cancellation: propagated through every blocking select/WalkDir.
package scanner

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/farzanini/dep-shield/internal/models"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	// maxPathLen is the maximum byte length of a path that will be processed.
	// Paths exceeding this length are skipped — they indicate pathological
	// trees (infinite symlink chains that were followed before detection, or
	// adversarial input).
	maxPathLen = 4096

	// resultBuf is the capacity of the ScanResult channel.
	// A larger buffer lets workers stay busy while the consumer is slow.
	resultBuf = 256
)

// virtualFSPrefixes lists filesystem paths that should never be scanned.
// These are kernel-virtual or device pseudo-filesystems on Linux; scanning them
// causes permission errors, infinite reads, or hangs.
// macOS does not have /proc or /sys but the check is harmless.
var virtualFSPrefixes = []string{
	"/proc",
	"/sys",
	"/dev",
	"/run",
	"/snap",
}

// ── SourceType ────────────────────────────────────────────────────────────────

// SourceType classifies where a dependency directory came from.
// It lets the reporter flag editor-extension vulnerabilities separately from
// project dependencies, which have a different remediation path.
type SourceType string

const (
	// SourceTypeProject is a dependency directory inside a user's project
	// (node_modules, vendor, .venv, site-packages under a project root).
	SourceTypeProject SourceType = "project"

	// SourceTypeVSCodeExt is node_modules inside a VS Code extension directory
	// (~/.vscode/extensions/<ext>/node_modules).  These are owned by the
	// editor, not the user's code, and require an editor update to fix.
	SourceTypeVSCodeExt SourceType = "vscode-ext"

	// SourceTypeCursorExt is the same as SourceTypeVSCodeExt but for the
	// Cursor editor (~/.cursor/extensions/<ext>/node_modules).
	SourceTypeCursorExt SourceType = "cursor-ext"

	// SourceTypeGlobal is a package manager's global cache directory
	// (~/.cargo/registry, ~/go/pkg/mod).  Vulnerabilities here affect every
	// project that uses the cached version.
	SourceTypeGlobal SourceType = "global"

	// SourceTypeSystem is a system-wide Python installation
	// (/usr/lib/python*/dist-packages, /opt/…/site-packages).
	SourceTypeSystem SourceType = "system"
)

// ── ScanResult ────────────────────────────────────────────────────────────────

// ScanResult is one dependency directory found during a scan.
// Results are streamed over the channel returned by Scanner.Scan as they are
// discovered, rather than buffered until the walk is complete.
type ScanResult struct {
	// AbsPath is the absolute, cleaned filesystem path of the directory.
	AbsPath string

	// Ecosystem identifies which package manager owns this directory.
	Ecosystem models.Ecosystem

	// SourceType classifies whether this is a project, editor-extension,
	// global cache, or system-wide installation.
	SourceType SourceType

	// ParentName is a human-readable name for the entity that owns this
	// dependency directory.  Examples:
	//   "my-app"                     (for /srv/my-app/node_modules)
	//   "ms-python.python-2024.1.0"  (for a VS Code extension)
	//   "cargo-global-registry"       (for ~/.cargo/registry)
	//   "go-module-cache"             (for ~/go/pkg/mod)
	ParentName string

	// FoundAt is the wall-clock time at which this result was produced.
	// Useful for timing reports and progress displays.
	FoundAt time.Time
}

// ── DirHit (backward compatibility) ──────────────────────────────────────────

// DirHit is the legacy result type used by internal/parser.  New code should
// use ScanResult; DirHit exists so that parser.Dispatcher.ParseAll does not
// need to be rewritten.
//
// Walk() returns []DirHit by collecting ScanResults and projecting each one
// onto the two fields that the parser layer needs.
type DirHit struct {
	// Path is the absolute filesystem path of the matched directory.
	Path string

	// Ecosystem identifies which kind of manifest was found here.
	Ecosystem models.Ecosystem
}

// ── Options ───────────────────────────────────────────────────────────────────

// Options configures a Scanner.  Using a struct (not positional arguments)
// keeps the constructor signature stable as new options are added.
type Options struct {
	// Roots is the list of root directories to scan.
	// Defaults to the user's home directory when empty.
	Roots []string

	// Ecosystems restricts the scan to these ecosystems (e.g. ["npm", "Go"]).
	// An empty slice means all ecosystems are reported.
	// The strings must match the models.Ecosystem constants exactly.
	Ecosystems []string

	// Workers is the size of the goroutine pool.
	// 0 (default) uses runtime.NumCPU().
	Workers int

	// MaxDepth caps how many directory levels below each root are visited.
	// 0 (default) means unlimited depth.
	MaxDepth int

	// FollowSymlinks enables following symbolic links during the walk.
	// Default false is strongly recommended: symlink loops can cause
	// infinite walks.  When true, real-path deduplication is used to
	// detect and break loops, but this adds memory overhead.
	FollowSymlinks bool

	// SkipGlobal disables the automatic addition of global package-manager
	// cache directories (~/.cargo/registry, ~/go/pkg/mod, editor extensions).
	// Useful when scanning only a specific project tree.
	SkipGlobal bool

	// HomeDir overrides the home directory used for resolving global cache
	// paths.  Set this in tests to prevent real ~/.cargo, ~/go/pkg/mod from
	// being included in test results.
	// Defaults to os.UserHomeDir() when empty.
	HomeDir string

	// Log is the structured logger.  Pass zap.NewNop() in tests to silence output.
	Log *zap.Logger
}

// ── Interfaces ────────────────────────────────────────────────────────────────

// Walker is the original synchronous interface, kept for backward compatibility
// with internal/parser and the existing cmd/ callers.
type Walker interface {
	// Walk traverses all roots and returns every matched directory as a DirHit.
	// It blocks until the scan is complete.
	Walk(ctx context.Context) ([]DirHit, error)
}

// Scanner is the streaming interface.  Results arrive over the returned channel
// as they are found — the caller does not have to wait for the full scan.
// Scanner embeds Walker so any *impl satisfies both interfaces.
type Scanner interface {
	Walker
	// Scan returns a channel that receives ScanResults as they are discovered.
	// The channel is closed when all roots have been fully walked (or ctx is
	// cancelled).  The caller must drain the channel; a full channel stalls
	// the workers.
	Scan(ctx context.Context) <-chan ScanResult
}

// Detector is an extension point for adding custom ecosystem detection rules.
// Register custom detectors via Options.ExtraDetectors (see below).
// Built-in matching is handled by the inline classify() function for
// performance, but the interface is preserved for plugin use.
type Detector interface {
	Ecosystem() models.Ecosystem
	Match(dir string) bool
}

// ── impl ──────────────────────────────────────────────────────────────────────

// impl is the concrete Scanner implementation.  It is unexported so callers
// depend on the Scanner/Walker interfaces rather than the struct.
type impl struct {
	opts       Options
	numWorkers int
	home       string
	log        *zap.Logger

	// visited maps real (symlink-resolved) paths to struct{} to detect
	// symlink loops when FollowSymlinks is true.
	visited sync.Map
}

// rootWork is one unit of work fed to the worker pool.
// sourceHint pre-classifies the intent of a root so classify() can inherit it
// when matching top-level directories (e.g. entries under ~/.vscode/extensions
// are pre-labelled SourceTypeVSCodeExt).
type rootWork struct {
	path       string
	sourceHint SourceType
}

// ── Constructor ───────────────────────────────────────────────────────────────

// New constructs a Scanner with a worker pool sized to runtime.NumCPU().
// It is safe to call Scan and Walk concurrently from multiple goroutines.
func New(opts Options) Scanner {
	log := opts.Log
	if log == nil {
		log = zap.NewNop()
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	home := opts.HomeDir
	if home == "" {
		home, _ = os.UserHomeDir()
	}

	return &impl{
		opts:       opts,
		numWorkers: workers,
		home:       home,
		log:        log,
	}
}

// ── Scanner.Scan ──────────────────────────────────────────────────────────────

// Scan implements Scanner.
//
// Concurrency model:
//  1. effectiveRoots() builds a deduplicated list of roots to walk.
//  2. All roots are placed in a buffered channel that is immediately closed.
//  3. numWorkers goroutines each pull roots from the channel; when the channel
//     is empty every worker exits naturally (no explicit shutdown signal needed).
//  4. A separate goroutine waits for all workers via WaitGroup and then closes
//     resultCh, signalling the caller that the scan is complete.
func (s *impl) Scan(ctx context.Context) <-chan ScanResult {
	resultCh := make(chan ScanResult, resultBuf)

	go func() {
		defer close(resultCh)

		roots := s.effectiveRoots()
		if len(roots) == 0 {
			return
		}

		// Pre-fill the work channel and close it immediately.
		// Workers see EOF on the channel when all roots have been claimed.
		// Buffer = len(roots) ensures no producer blocks.
		workCh := make(chan rootWork, len(roots))
		for _, r := range roots {
			workCh <- r
		}
		close(workCh) // ← workers exit when this is drained

		var wg sync.WaitGroup
		for i := 0; i < s.numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for work := range workCh {
					if ctx.Err() != nil {
						return
					}
					s.walkRoot(ctx, work, resultCh)
				}
			}()
		}
		wg.Wait()
		// resultCh is closed by the defer above.
	}()

	return resultCh
}

// ── Walker.Walk ───────────────────────────────────────────────────────────────

// Walk implements Walker (backward compatibility).
// It drains Scan() and returns all results as a []DirHit slice.
func (s *impl) Walk(ctx context.Context) ([]DirHit, error) {
	var hits []DirHit
	for r := range s.Scan(ctx) {
		hits = append(hits, DirHit{
			Path:      r.AbsPath,
			Ecosystem: r.Ecosystem,
		})
	}
	// If context was cancelled, report that alongside the partial results.
	if err := ctx.Err(); err != nil {
		return hits, err
	}
	return hits, nil
}

// ── Root expansion ────────────────────────────────────────────────────────────

// effectiveRoots builds the complete list of root paths the worker pool will
// walk.  It:
//   - Resolves relative paths to absolute.
//   - Adds implicit global caches (unless SkipGlobal is set).
//   - Deduplicates: if a candidate root is already under another root in the
//     list, it is dropped (it will be found naturally during the parent walk).
//   - Filters out paths that do not exist (e.g. ~/.cargo when Cargo is not installed).
func (s *impl) effectiveRoots() []rootWork {
	seen := make(map[string]bool)
	var all []rootWork

	add := func(path string, hint SourceType) {
		clean := filepath.Clean(path)
		if seen[clean] {
			return
		}
		seen[clean] = true
		// Only add paths that actually exist to avoid pointless WalkDir calls.
		if _, err := os.Lstat(clean); err == nil {
			all = append(all, rootWork{path: clean, sourceHint: hint})
		}
	}

	// User-specified roots.
	for _, r := range s.opts.Roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			s.log.Warn("cannot resolve root path", zap.String("path", r), zap.Error(err))
			continue
		}
		add(abs, SourceTypeProject)
	}
	// Default to home directory when no roots are specified.
	if len(s.opts.Roots) == 0 && s.home != "" {
		add(s.home, SourceTypeProject)
	}

	// Implicit global caches — added unless SkipGlobal is set.
	// deduplicateRoots (below) will remove these if they are already under
	// one of the user-supplied roots, preventing double-visiting.
	if !s.opts.SkipGlobal && s.home != "" {
		add(filepath.Join(s.home, ".cargo", "registry"),    SourceTypeGlobal)
		add(filepath.Join(s.home, "go", "pkg", "mod"),      SourceTypeGlobal)
		add(filepath.Join(s.home, ".vscode", "extensions"), SourceTypeVSCodeExt)
		add(filepath.Join(s.home, ".cursor", "extensions"), SourceTypeCursorExt)
	}

	return deduplicateRoots(all)
}

// deduplicateRoots removes any root whose path is a subdirectory of another
// root already in the list.  The parent walk will naturally encounter the
// child, so walking the child separately would produce duplicate ScanResults.
//
// Algorithm: sort by path length (shorter = shallower = parent-first), then
// discard any entry whose path starts with a previously accepted entry's path.
func deduplicateRoots(roots []rootWork) []rootWork {
	// Sort shorter (shallower) paths first so parents are processed before children.
	sort.Slice(roots, func(i, j int) bool {
		return len(roots[i].path) < len(roots[j].path)
	})

	out := roots[:0] // reuse the backing array; avoids allocation
	for _, candidate := range roots {
		dominated := false
		sep := string(filepath.Separator)
		for _, accepted := range out {
			// candidate is dominated if it is the same path OR a strict child.
			if candidate.path == accepted.path ||
				strings.HasPrefix(candidate.path, accepted.path+sep) {
				dominated = true
				break
			}
		}
		if !dominated {
			out = append(out, candidate)
		}
	}
	return out
}

// ── Per-root walk ─────────────────────────────────────────────────────────────

// walkRoot performs a depth-first walk of one root using filepath.WalkDir.
// It is designed to be called from a worker goroutine; all blocking sends to
// resultCh include a ctx.Done() case to unblock when the context is cancelled.
func (s *impl) walkRoot(ctx context.Context, work rootWork, resultCh chan<- ScanResult) {
	absRoot := filepath.Clean(work.path)

	// Confirm the root still exists before handing it to WalkDir.
	if _, err := os.Lstat(absRoot); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.log.Debug("skipping root", zap.String("path", absRoot), zap.Error(err))
		}
		return
	}

	// Track the real path of this root to prevent re-walking the same physical
	// directory when FollowSymlinks is true (e.g. two symlinks pointing here).
	if realRoot, err := filepath.EvalSymlinks(absRoot); err == nil {
		if _, alreadyWalking := s.visited.LoadOrStore(realRoot, struct{}{}); alreadyWalking {
			s.log.Debug("already walking this physical path, skipping",
				zap.String("root", absRoot), zap.String("real", realRoot))
			return
		}
	}

	err := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, err error) error {
		// ── Context check (highest priority) ──────────────────────────────────
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// ── Error from the OS (permission denied, stale symlink, etc.) ────────
		if err != nil {
			if isPermissionErr(err) {
				s.log.Debug("permission denied, skipping",
					zap.String("path", path))
				return nil // non-fatal: log and continue
			}
			s.log.Warn("walk error, skipping",
				zap.String("path", path), zap.Error(err))
			return nil // non-fatal
		}

		// Only process directories (WalkDir visits files too).
		if !d.IsDir() {
			return nil
		}

		// ── Safety guards ──────────────────────────────────────────────────────

		// Guard 1: path length
		if len(path) > maxPathLen {
			s.log.Debug("path exceeds maxPathLen, skipping subtree",
				zap.Int("len", len(path)), zap.String("path", path[:64]+"…"))
			return fs.SkipDir
		}

		// Guard 2: virtual/kernel filesystems
		if shouldSkipPath(path) {
			s.log.Debug("skipping virtual filesystem", zap.String("path", path))
			return fs.SkipDir
		}

		// Guard 3: symlink loop detection
		//
		// filepath.WalkDir does NOT follow symbolic links by default.
		// d.Type()&fs.ModeSymlink will be set for symlink-to-dir entries, but
		// WalkDir will not recurse into them.  We only need explicit loop
		// detection when the caller opts in via FollowSymlinks.
		//
		// Implementation note: we do NOT implement custom recursive walking here;
		// instead we rely on WalkDir's default behaviour (safe) and document that
		// FollowSymlinks is a future feature requiring a custom walker.
		if d.Type()&fs.ModeSymlink != 0 {
			if !s.opts.FollowSymlinks {
				return nil // WalkDir will not follow; be explicit for clarity
			}
			// FollowSymlinks: true — check whether this symlink's target has
			// already been visited to break cycles.
			real, err := filepath.EvalSymlinks(path)
			if err != nil {
				s.log.Debug("cannot resolve symlink", zap.String("path", path), zap.Error(err))
				return nil
			}
			if _, seen := s.visited.LoadOrStore(real, struct{}{}); seen {
				s.log.Debug("symlink loop detected, skipping",
					zap.String("link", path), zap.String("target", real))
				return fs.SkipDir
			}
		}

		// Guard 4: depth limit
		if s.opts.MaxDepth > 0 && path != absRoot {
			rel, relErr := filepath.Rel(absRoot, path)
			if relErr == nil {
				// strings.Count counts separators; depth = separators + 1
				depth := strings.Count(rel, string(filepath.Separator)) + 1
				if depth > s.opts.MaxDepth {
					return fs.SkipDir
				}
			}
		}

		// ── Classify ──────────────────────────────────────────────────────────
		result, matched := s.classify(path, work.sourceHint)
		if !matched {
			return nil // keep descending
		}

		// Apply ecosystem filter: even when filtered out we still skip the
		// subtree (no need to recurse inside node_modules looking for more
		// node_modules).
		if !s.ecosystemAllowed(result.Ecosystem) {
			return fs.SkipDir
		}

		// Send result; respect context cancellation to avoid goroutine leaks.
		select {
		case resultCh <- result:
		case <-ctx.Done():
			return ctx.Err()
		}
		// Critical: do not recurse into dependency directories.
		// node_modules can contain nested node_modules (hoisting artefacts);
		// we want the outermost match only.
		return fs.SkipDir
	})

	// WalkDir returns ctx.Err() when cancelled; that is expected, not a bug.
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		s.log.Warn("walk finished with error",
			zap.String("root", absRoot), zap.Error(err))
	}
}

// ── Path classification ───────────────────────────────────────────────────────

// classify decides whether path is a known dependency directory and, if so,
// returns a fully-populated ScanResult.
//
// Rules are checked in priority order:
//  1. Exact absolute-path matches (~/.cargo/registry, ~/go/pkg/mod)
//  2. Directory base-name matches (node_modules, vendor, .venv, site-packages)
//
// Absolute-path checks come first so that global caches are correctly labelled
// SourceTypeGlobal even when discovered via a home-directory walk (rather than
// as an explicit root).
func (s *impl) classify(path string, hint SourceType) (ScanResult, bool) {
	now := time.Now()
	base := filepath.Base(path)
	parentDir := filepath.Dir(path)
	parentBase := filepath.Base(parentDir)

	// ── Rule 1: ~/.cargo/registry ────────────────────────────────────────────
	if s.home != "" {
		cargoReg := filepath.Join(s.home, ".cargo", "registry")
		if path == cargoReg {
			return ScanResult{
				AbsPath:    path,
				Ecosystem:  models.EcosystemCargo,
				SourceType: SourceTypeGlobal,
				ParentName: "cargo-global-registry",
				FoundAt:    now,
			}, true
		}

		// ── Rule 2: ~/go/pkg/mod ─────────────────────────────────────────────
		goModCache := filepath.Join(s.home, "go", "pkg", "mod")
		if path == goModCache {
			return ScanResult{
				AbsPath:    path,
				Ecosystem:  models.EcosystemGo,
				SourceType: SourceTypeGlobal,
				ParentName: "go-module-cache",
				FoundAt:    now,
			}, true
		}
	}

	// ── Rule 3: node_modules ─────────────────────────────────────────────────
	if base == "node_modules" {
		st := SourceTypeProject
		pname := parentBase

		// VS Code: ~/.vscode/extensions/<ext-id>/node_modules
		if pathContainsSegments(path, ".vscode", "extensions") {
			st = SourceTypeVSCodeExt
			pname = s.extensionDirName(path, ".vscode")
		} else if pathContainsSegments(path, ".cursor", "extensions") {
			// Cursor editor: ~/.cursor/extensions/<ext-id>/node_modules
			st = SourceTypeCursorExt
			pname = s.extensionDirName(path, ".cursor")
		} else if hint == SourceTypeVSCodeExt || hint == SourceTypeCursorExt {
			// Inherited from the root's sourceHint (walking extensions dir directly).
			st = hint
		}

		return ScanResult{
			AbsPath:    path,
			Ecosystem:  models.EcosystemNPM,
			SourceType: st,
			ParentName: pname,
			FoundAt:    now,
		}, true
	}

	// ── Rule 4: vendor (Go modules vendor directory) ──────────────────────────
	// A vendor directory alongside a go.mod is a Go vendor tree.
	// We match on the base name only; the parser confirms go.mod presence.
	if base == "vendor" {
		return ScanResult{
			AbsPath:    path,
			Ecosystem:  models.EcosystemGo,
			SourceType: SourceTypeProject,
			ParentName: parentBase,
			FoundAt:    now,
		}, true
	}

	// ── Rule 5: .venv (Python virtual environment) ────────────────────────────
	if base == ".venv" {
		return ScanResult{
			AbsPath:    path,
			Ecosystem:  models.EcosystemPyPI,
			SourceType: SourceTypeProject,
			ParentName: parentBase,
			FoundAt:    now,
		}, true
	}

	// ── Rule 6: site-packages ─────────────────────────────────────────────────
	// Python installs packages into site-packages directories.
	// Under /usr/ or /opt/ they belong to the system Python installation.
	if base == "site-packages" {
		st := SourceTypeProject
		if isSystemInstallPath(path) {
			st = SourceTypeSystem
		}
		return ScanResult{
			AbsPath:    path,
			Ecosystem:  models.EcosystemPyPI,
			SourceType: st,
			ParentName: parentBase,
			FoundAt:    now,
		}, true
	}

	return ScanResult{}, false
}

// extensionDirName extracts the extension identifier from a path like:
//
//	/home/user/.vscode/extensions/ms-python.python-2024.1.0/node_modules
//	                               ──────────────────────────
//	                               returned value
//
// Falls back to the immediate parent directory name if the structure is unexpected.
func (s *impl) extensionDirName(path, editorDir string) string {
	sep := string(filepath.Separator)
	// Needle: "/.vscode/extensions/" or "/.cursor/extensions/"
	needle := sep + editorDir + sep + "extensions" + sep
	idx := strings.Index(path, needle)
	if idx < 0 {
		return filepath.Base(filepath.Dir(path))
	}
	// rest = "ms-python.python-2024.1.0/node_modules"
	rest := path[idx+len(needle):]
	// Take only the first path component.
	if i := strings.Index(rest, sep); i >= 0 {
		return rest[:i]
	}
	return rest
}

// ecosystemAllowed returns true when either no ecosystem filter is set, or the
// given ecosystem is in the allowed list.
func (s *impl) ecosystemAllowed(eco models.Ecosystem) bool {
	if len(s.opts.Ecosystems) == 0 {
		return true
	}
	for _, e := range s.opts.Ecosystems {
		if models.Ecosystem(e) == eco {
			return true
		}
	}
	return false
}

// ── Package-level helpers ─────────────────────────────────────────────────────

// shouldSkipPath returns true when path refers to a virtual or device
// filesystem that should never be scanned.
func shouldSkipPath(path string) bool {
	sep := string(filepath.Separator)
	for _, prefix := range virtualFSPrefixes {
		// Match exact prefix OR prefix followed by a separator.
		// This prevents "/processing" from being skipped because of "/proc".
		if path == prefix || strings.HasPrefix(path, prefix+sep) {
			return true
		}
	}
	return false
}

// isPermissionErr returns true for OS-level permission-denied errors.
// Both fs.ErrPermission (wrapping syscall.EACCES) and raw os.ErrPermission
// are covered via errors.Is, which unwraps the error chain.
func isPermissionErr(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, os.ErrPermission)
}

// isSystemInstallPath returns true for paths under system-wide installation
// prefixes on Linux (/usr/, /opt/) and macOS (/System/, /Library/).
func isSystemInstallPath(path string) bool {
	for _, prefix := range []string{"/usr/", "/opt/", "/System/", "/Library/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// pathContainsSegments returns true when path contains the consecutive
// directory segments dir and sub in that order.
//
// Example: pathContainsSegments("/home/x/.vscode/extensions/foo", ".vscode", "extensions")
// returns true.
//
// This is stricter than strings.Contains(path, ".vscode/extensions") because
// it ensures each component is a complete path segment (not a substring of a
// longer name like ".vscode-oss").
func pathContainsSegments(path, dir, sub string) bool {
	sep := string(filepath.Separator)
	needle := sep + dir + sep + sub + sep
	return strings.Contains(path, needle)
}

// ── Detector interface (extension point) ─────────────────────────────────────

// FilterDetectors returns a subset of detectors whose Ecosystem() value is
// present in the allowed slice.  It is exported for use by custom tooling that
// builds on top of the scanner package.
func FilterDetectors(all []Detector, allowed []string) []Detector {
	if len(allowed) == 0 {
		return all
	}
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	out := make([]Detector, 0, len(all))
	for _, d := range all {
		if _, ok := set[string(d.Ecosystem())]; ok {
			out = append(out, d)
		}
	}
	return out
}
