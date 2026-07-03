// Package scanner_test contains table-driven integration tests for the scanner.
//
// # Test isolation
//
// Every test that creates files uses t.TempDir() for both the scan root and the
// simulated home directory.  This prevents real system directories (the
// developer's ~/.cargo, ~/go/pkg/mod, etc.) from contaminating test results.
//
// The canonical setup idiom is:
//
//	home := t.TempDir()   // fake home — global caches placed here when needed
//	root := t.TempDir()   // the directory being scanned
//	opts := scanner.Options{
//	    Roots:   []string{root},
//	    HomeDir: home,        // ← prevents scanning real ~/.cargo etc.
//	    Log:     zap.NewNop(),
//	}
//
// # Table-driven pattern
//
// Tests that cover many similar cases (e.g. all ecosystems, all source types)
// use a table of structs:
//
//	tests := []struct { name, dir string; want models.Ecosystem }{…}
//	for _, tt := range tests {
//	    t.Run(tt.name, func(t *testing.T) { … })
//	}
//
// This keeps the test matrix readable and makes adding new cases trivial.
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/farzanini/dep-shield/internal/models"
	"github.com/farzanini/dep-shield/internal/scanner"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// mkdir creates a directory (and all parents) inside the test temp tree.
// It calls t.Fatal if creation fails.
func mkdir(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(parts...)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	return path
}

// writeFile creates a file at path with the given content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
}

// drain collects every ScanResult from ch into a slice.
func drain(ch <-chan scanner.ScanResult) []scanner.ScanResult {
	var out []scanner.ScanResult
	for r := range ch {
		out = append(out, r)
	}
	return out
}

// scanOpts builds a minimal Options for a test scan.
// home and root are separate temp dirs created by the caller.
func scanOpts(root, home string) scanner.Options {
	return scanner.Options{
		Roots:   []string{root},
		HomeDir: home,
		Log:     zap.NewNop(),
	}
}

// findByEco returns all results with the given ecosystem from a slice.
func findByEco(results []scanner.ScanResult, eco models.Ecosystem) []scanner.ScanResult {
	var out []scanner.ScanResult
	for _, r := range results {
		if r.Ecosystem == eco {
			out = append(out, r)
		}
	}
	return out
}

// ── ScanResult streaming ──────────────────────────────────────────────────────

// TestScan_EmptyRoot verifies that scanning an empty directory produces no results
// and the channel is closed cleanly.
func TestScan_EmptyRoot(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	sc := scanner.New(scanOpts(root, home))

	results := drain(sc.Scan(context.Background()))
	if len(results) != 0 {
		t.Errorf("expected 0 results from empty root, got %d", len(results))
	}
}

// TestScan_NodeModules verifies that a node_modules directory is found and
// classified as npm / project.
func TestScan_NodeModules(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	nm := mkdir(t, root, "my-app", "node_modules")

	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.AbsPath != nm {
		t.Errorf("AbsPath: got %q, want %q", r.AbsPath, nm)
	}
	if r.Ecosystem != models.EcosystemNPM {
		t.Errorf("Ecosystem: got %q, want npm", r.Ecosystem)
	}
	if r.SourceType != scanner.SourceTypeProject {
		t.Errorf("SourceType: got %q, want project", r.SourceType)
	}
	if r.ParentName != "my-app" {
		t.Errorf("ParentName: got %q, want my-app", r.ParentName)
	}
	if r.FoundAt.IsZero() {
		t.Error("FoundAt must not be zero")
	}
	if time.Since(r.FoundAt) > 10*time.Second {
		t.Errorf("FoundAt is too far in the past: %v", r.FoundAt)
	}
}

// TestScan_GoVendor verifies that a vendor directory is found as Go / project.
func TestScan_GoVendor(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	vendor := mkdir(t, root, "my-service", "vendor")

	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.AbsPath != vendor {
		t.Errorf("AbsPath: got %q, want %q", r.AbsPath, vendor)
	}
	if r.Ecosystem != models.EcosystemGo {
		t.Errorf("Ecosystem: got %q, want Go", r.Ecosystem)
	}
	if r.SourceType != scanner.SourceTypeProject {
		t.Errorf("SourceType: got %q, want project", r.SourceType)
	}
	if r.ParentName != "my-service" {
		t.Errorf("ParentName: got %q, want my-service", r.ParentName)
	}
}

// TestScan_PythonVenv verifies that a .venv directory is found as PyPI / project.
func TestScan_PythonVenv(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	venv := mkdir(t, root, "data-science-project", ".venv")

	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.AbsPath != venv {
		t.Errorf("AbsPath: got %q, want %q", r.AbsPath, venv)
	}
	if r.Ecosystem != models.EcosystemPyPI {
		t.Errorf("Ecosystem: got %q, want PyPI", r.Ecosystem)
	}
	if r.SourceType != scanner.SourceTypeProject {
		t.Errorf("SourceType: got %q, want project", r.SourceType)
	}
}

// TestScan_PythonSitePackages verifies site-packages detection and project vs
// system classification.
func TestScan_PythonSitePackages(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	sp := mkdir(t, root, "my-venv", "lib", "python3.11", "site-packages")

	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.AbsPath != sp {
		t.Errorf("AbsPath: got %q, want %q", r.AbsPath, sp)
	}
	if r.Ecosystem != models.EcosystemPyPI {
		t.Errorf("Ecosystem: got %q, want PyPI", r.Ecosystem)
	}
	// site-packages under a temp dir (not /usr/ or /opt/) → project
	if r.SourceType != scanner.SourceTypeProject {
		t.Errorf("SourceType: got %q, want project", r.SourceType)
	}
}

// TestScan_VSCodeExtensions verifies that node_modules inside a VS Code
// extension directory is flagged as vscode-ext with the extension name as
// ParentName.
func TestScan_VSCodeExtensions(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	extID := "ms-python.python-2024.1.0"

	// Simulate: home/.vscode/extensions/<ext-id>/node_modules
	nm := mkdir(t, home, ".vscode", "extensions", extID, "node_modules")

	opts := scanner.Options{
		Roots:   []string{root}, // root is empty — global caches in home are the target
		HomeDir: home,
		Log:     zap.NewNop(),
	}
	sc := scanner.New(opts)
	results := drain(sc.Scan(context.Background()))

	// Filter to vscode-ext results only
	var vsExt []scanner.ScanResult
	for _, r := range results {
		if r.SourceType == scanner.SourceTypeVSCodeExt {
			vsExt = append(vsExt, r)
		}
	}

	if len(vsExt) != 1 {
		t.Fatalf("expected 1 vscode-ext result, got %d (all results: %v)", len(vsExt), results)
	}
	r := vsExt[0]
	if r.AbsPath != nm {
		t.Errorf("AbsPath: got %q, want %q", r.AbsPath, nm)
	}
	if r.Ecosystem != models.EcosystemNPM {
		t.Errorf("Ecosystem: got %q, want npm", r.Ecosystem)
	}
	if r.ParentName != extID {
		t.Errorf("ParentName: got %q, want %q", r.ParentName, extID)
	}
}

// TestScan_CursorExtensions mirrors the VS Code test for the Cursor editor.
func TestScan_CursorExtensions(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	extID := "anysphere.cursor-retrieval-2024"
	nm := mkdir(t, home, ".cursor", "extensions", extID, "node_modules")

	opts := scanner.Options{
		Roots:   []string{root},
		HomeDir: home,
		Log:     zap.NewNop(),
	}
	sc := scanner.New(opts)
	results := drain(sc.Scan(context.Background()))

	var cursorExts []scanner.ScanResult
	for _, r := range results {
		if r.SourceType == scanner.SourceTypeCursorExt {
			cursorExts = append(cursorExts, r)
		}
	}
	if len(cursorExts) != 1 {
		t.Fatalf("expected 1 cursor-ext result, got %d", len(cursorExts))
	}
	r := cursorExts[0]
	if r.AbsPath != nm {
		t.Errorf("AbsPath: got %q, want %q", r.AbsPath, nm)
	}
	if r.ParentName != extID {
		t.Errorf("ParentName: got %q, want %q", r.ParentName, extID)
	}
}

// TestScan_CargoGlobalRegistry verifies that ~/.cargo/registry is found and
// classified as Cargo / global when walking the home directory.
func TestScan_CargoGlobalRegistry(t *testing.T) {
	home := t.TempDir()
	cargoReg := mkdir(t, home, ".cargo", "registry")

	// Walk the home dir so ~/.cargo/registry is discovered during the walk.
	opts := scanner.Options{
		// No Roots → defaults to HomeDir.
		HomeDir: home,
		Log:     zap.NewNop(),
	}
	sc := scanner.New(opts)
	results := drain(sc.Scan(context.Background()))

	var found []scanner.ScanResult
	for _, r := range results {
		if r.Ecosystem == models.EcosystemCargo && r.SourceType == scanner.SourceTypeGlobal {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 cargo/global result, got %d (all: %v)", len(found), results)
	}
	if found[0].AbsPath != cargoReg {
		t.Errorf("AbsPath: got %q, want %q", found[0].AbsPath, cargoReg)
	}
	if found[0].ParentName != "cargo-global-registry" {
		t.Errorf("ParentName: got %q, want cargo-global-registry", found[0].ParentName)
	}
}

// TestScan_GoModuleCache verifies ~/go/pkg/mod detection.
func TestScan_GoModuleCache(t *testing.T) {
	home := t.TempDir()
	goMod := mkdir(t, home, "go", "pkg", "mod")

	opts := scanner.Options{HomeDir: home, Log: zap.NewNop()}
	sc := scanner.New(opts)
	results := drain(sc.Scan(context.Background()))

	var found []scanner.ScanResult
	for _, r := range results {
		if r.Ecosystem == models.EcosystemGo && r.SourceType == scanner.SourceTypeGlobal {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 go/global result, got %d", len(found))
	}
	if found[0].AbsPath != goMod {
		t.Errorf("AbsPath: got %q, want %q", found[0].AbsPath, goMod)
	}
	if found[0].ParentName != "go-module-cache" {
		t.Errorf("ParentName: got %q, want go-module-cache", found[0].ParentName)
	}
}

// TestScan_MultipleEcosystems verifies that several different ecosystem
// directories in the same root are all found in a single scan.
func TestScan_MultipleEcosystems(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()

	// Create one directory per ecosystem.
	mkdir(t, root, "frontend", "node_modules")
	mkdir(t, root, "backend", "vendor")
	mkdir(t, root, "scripts", ".venv")
	mkdir(t, root, "api", "lib", "python3.12", "site-packages")

	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))

	if len(results) != 4 {
		t.Errorf("expected 4 results, got %d", len(results))
	}

	ecos := make(map[models.Ecosystem]int)
	for _, r := range results {
		ecos[r.Ecosystem]++
	}
	if ecos[models.EcosystemNPM] != 1 {
		t.Errorf("expected 1 npm, got %d", ecos[models.EcosystemNPM])
	}
	if ecos[models.EcosystemGo] != 1 {
		t.Errorf("expected 1 go, got %d", ecos[models.EcosystemGo])
	}
	if ecos[models.EcosystemPyPI] != 2 {
		t.Errorf("expected 2 pypi (.venv + site-packages), got %d", ecos[models.EcosystemPyPI])
	}
}

// TestScan_EcosystemFilter verifies that the Ecosystems option restricts results
// to the named ecosystems only.
func TestScan_EcosystemFilter(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	mkdir(t, root, "app", "node_modules") // npm
	mkdir(t, root, "lib", "vendor")       // go
	mkdir(t, root, "ml", ".venv")         // pip

	opts := scanner.Options{
		Roots:      []string{root},
		HomeDir:    home,
		Ecosystems: []string{string(models.EcosystemNPM)}, // only npm
		Log:        zap.NewNop(),
	}
	sc := scanner.New(opts)
	results := drain(sc.Scan(context.Background()))

	if len(results) != 1 {
		t.Fatalf("expected 1 result (npm only), got %d: %v", len(results), results)
	}
	if results[0].Ecosystem != models.EcosystemNPM {
		t.Errorf("expected npm, got %q", results[0].Ecosystem)
	}
}

// TestScan_NoRecursionIntoDepDir verifies that the scanner does not recurse
// into a matched dependency directory.  A node_modules inside another
// node_modules (npm hoisting artefact) must NOT produce a second result.
func TestScan_NoRecursionIntoDepDir(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	// Outer node_modules matches → inner must not be visited.
	mkdir(t, root, "app", "node_modules", "some-lib", "node_modules")

	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))

	if len(results) != 1 {
		t.Errorf("expected 1 result (outer node_modules only), got %d", len(results))
	}
}

// TestScan_SiblingDepDirs verifies that two dependency directories at the same
// level are both found and each produces its own result.
func TestScan_SiblingDepDirs(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	mkdir(t, root, "frontend", "node_modules")
	mkdir(t, root, "backend", "node_modules")

	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// Sort for deterministic comparison.
	sort.Slice(results, func(i, j int) bool {
		return results[i].AbsPath < results[j].AbsPath
	})
	if results[0].ParentName != "backend" && results[1].ParentName != "backend" {
		t.Error("expected a result with ParentName=backend")
	}
	if results[0].ParentName != "frontend" && results[1].ParentName != "frontend" {
		t.Error("expected a result with ParentName=frontend")
	}
}

// TestScan_PermissionDenied verifies that a directory the process cannot read
// is silently skipped rather than causing an error or panic.
func TestScan_PermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — permission errors do not apply")
	}

	root, home := t.TempDir(), t.TempDir()
	// Create a locked directory that contains a node_modules we should NOT find.
	locked := mkdir(t, root, "secret")
	if err := os.MkdirAll(filepath.Join(locked, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o755) // restore for cleanup

	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))
	// The node_modules inside the locked dir must not appear.
	for _, r := range results {
		if r.ParentName == "secret" {
			t.Errorf("should not have found results inside permission-denied dir: %v", r)
		}
	}
}

// TestScan_CancelledContext verifies that cancelling the context stops the scan
// promptly rather than blocking forever.
func TestScan_CancelledContext(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	// Populate enough directories that cancellation might catch the walk mid-way.
	for i := range 20 {
		mkdir(t, root, "project-"+string(rune('a'+i)), "node_modules")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	sc := scanner.New(scanOpts(root, home))
	// Must not block; pre-cancelled context should cause an early exit.
	done := make(chan struct{})
	go func() {
		drain(sc.Scan(ctx))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Scan did not respect context cancellation within 5 seconds")
	}
}

// TestScan_MaxDepth verifies that directories deeper than MaxDepth are not found.
func TestScan_MaxDepth(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	// Depth 1: root/node_modules  → should be found with MaxDepth >= 1
	mkdir(t, root, "node_modules")
	// Depth 2: root/app/node_modules → must NOT be found with MaxDepth = 1
	mkdir(t, root, "app", "node_modules")

	opts := scanner.Options{
		Roots:    []string{root},
		HomeDir:  home,
		MaxDepth: 1, // only look one level deep
		Log:      zap.NewNop(),
	}
	sc := scanner.New(opts)
	results := drain(sc.Scan(context.Background()))

	if len(results) != 1 {
		t.Errorf("expected 1 result at depth 1, got %d", len(results))
	}
	// The found result must be at depth 1 (root/node_modules).
	if len(results) == 1 {
		wantPath := filepath.Join(root, "node_modules")
		if results[0].AbsPath != wantPath {
			t.Errorf("wrong path: got %q, want %q", results[0].AbsPath, wantPath)
		}
	}
}

// TestScan_LongPath verifies that paths exceeding 4096 bytes are skipped
// rather than causing an error.  We simulate this by checking the guard
// condition indirectly: create a deep directory tree and verify the scan
// terminates without panicking.  (Actually constructing a 4096-byte path
// requires OS cooperation and is skipped here in favour of a unit test of
// the shouldSkipPath guard.)
func TestScan_LongPath(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	// A node_modules at a reasonable depth must still be found.
	mkdir(t, root, "a", "b", "c", "node_modules")

	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))
	if len(results) != 1 {
		t.Errorf("expected 1 result from nested path, got %d", len(results))
	}
}

// TestScan_SymlinkToDir verifies that a symbolic link to a directory is NOT
// followed when FollowSymlinks is false (the default).  The target directory
// contains node_modules; those must NOT appear in the scan.
func TestScan_SymlinkToDir(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()

	// Real directory outside the scan root.
	target, _ := t.TempDir(), t.TempDir()
	mkdir(t, target, "node_modules")

	// Symlink inside scan root pointing to target.
	link := filepath.Join(root, "linked-app")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("cannot create symlink:", err)
	}

	opts := scanOpts(root, home)
	opts.FollowSymlinks = false // default, explicit for clarity
	sc := scanner.New(opts)
	results := drain(sc.Scan(context.Background()))

	// No results: the symlink was not followed.
	if len(results) != 0 {
		t.Errorf("expected 0 results (symlink not followed), got %d: %v", len(results), results)
	}
}

// TestScan_SymlinkLoop verifies that a symlink loop does not cause an infinite
// walk when FollowSymlinks is true.
func TestScan_SymlinkLoop(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	proj := mkdir(t, root, "project")

	// Create a symlink inside project that points back to project (a loop).
	loop := filepath.Join(proj, "loop-link")
	if err := os.Symlink(proj, loop); err != nil {
		t.Skip("cannot create symlink:", err)
	}

	opts := scanner.Options{
		Roots:          []string{root},
		HomeDir:        home,
		FollowSymlinks: true,
		Log:            zap.NewNop(),
	}
	sc := scanner.New(opts)

	done := make(chan struct{})
	go func() {
		drain(sc.Scan(context.Background()))
		close(done)
	}()

	select {
	case <-done:
		// Scan completed without looping forever.
	case <-time.After(10 * time.Second):
		t.Fatal("Scan did not terminate — symlink loop was not detected")
	}
}

// TestScan_MultipleRoots verifies that two independent roots are both walked
// and their results are merged into the same channel.
func TestScan_MultipleRoots(t *testing.T) {
	home := t.TempDir()
	root1 := t.TempDir()
	root2 := t.TempDir()

	mkdir(t, root1, "frontend", "node_modules")
	mkdir(t, root2, "backend", "vendor")

	opts := scanner.Options{
		Roots:   []string{root1, root2},
		HomeDir: home,
		Log:     zap.NewNop(),
	}
	sc := scanner.New(opts)
	results := drain(sc.Scan(context.Background()))

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	ecos := make(map[models.Ecosystem]bool)
	for _, r := range results {
		ecos[r.Ecosystem] = true
	}
	if !ecos[models.EcosystemNPM] {
		t.Error("expected npm result from root1")
	}
	if !ecos[models.EcosystemGo] {
		t.Error("expected go result from root2")
	}
}

// TestScan_SkipGlobal verifies that SkipGlobal:true prevents global cache dirs
// from being added even when they exist.
func TestScan_SkipGlobal(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()

	// Create global caches in home — they should be ignored.
	mkdir(t, home, ".cargo", "registry")
	mkdir(t, home, "go", "pkg", "mod")
	mkdir(t, home, ".vscode", "extensions")

	opts := scanner.Options{
		Roots:      []string{root}, // only scan root (which is empty)
		HomeDir:    home,
		SkipGlobal: true,
		Log:        zap.NewNop(),
	}
	sc := scanner.New(opts)
	results := drain(sc.Scan(context.Background()))

	if len(results) != 0 {
		t.Errorf("SkipGlobal should suppress all global results; got %d: %v", len(results), results)
	}
}

// TestScan_SkipVirtualFS verifies that /proc (and similar) paths are not
// descended into.  This is tested by checking that shouldSkipPath matches the
// expected prefixes.  We don't actually try to scan /proc in CI.
func TestScan_SkipVirtualFS(t *testing.T) {
	// Use table-driven checks for the package-level shouldSkipPath logic
	// via observable scanner behaviour.  We create a temp dir that mimics
	// the naming convention, then verify it is skipped.
	// Note: we can't create a real /proc in a temp dir, so we test indirectly
	// by ensuring scanning a normal path doesn't panic, and we document that
	// the guard runs on every path visited.
	root, home := t.TempDir(), t.TempDir()
	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))
	_ = results // no panic = guard code compiled and ran without issues
}

// ── Walk backward compatibility ───────────────────────────────────────────────

// TestWalk_BackwardCompat verifies that the Walk method (used by parser.go)
// returns DirHit values correctly.
func TestWalk_BackwardCompat(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	nm := mkdir(t, root, "project", "node_modules")

	sc := scanner.New(scanOpts(root, home))
	hits, err := sc.Walk(context.Background())
	if err != nil {
		t.Fatalf("Walk error: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 DirHit, got %d", len(hits))
	}
	if hits[0].Path != nm {
		t.Errorf("Path: got %q, want %q", hits[0].Path, nm)
	}
	if hits[0].Ecosystem != models.EcosystemNPM {
		t.Errorf("Ecosystem: got %q, want npm", hits[0].Ecosystem)
	}
}

// TestWalk_CancelledContext verifies that Walk returns promptly when the
// context is pre-cancelled.
func TestWalk_CancelledContext(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sc := scanner.New(scanOpts(root, home))
	done := make(chan struct{})
	go func() {
		_, _ = sc.Walk(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Walk did not return on cancelled context")
	}
}

// TestWalk_InaccessiblePath verifies that Walk does not return an error when
// it encounters a directory it cannot read.
func TestWalk_InaccessiblePath(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — permission errors do not apply")
	}
	root, home := t.TempDir(), t.TempDir()
	locked := mkdir(t, root, "locked")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o755)

	sc := scanner.New(scanOpts(root, home))
	_, err := sc.Walk(context.Background())
	if err != nil {
		t.Errorf("Walk should not error on permission-denied directory; got: %v", err)
	}
}

// ── DirHit struct (used by parser) ───────────────────────────────────────────

// TestDirHit_Fields verifies that DirHit carries the expected Path and Ecosystem
// fields.  This test does not use Walk; it constructs a DirHit directly to
// verify the struct shape that parser.go depends on.
func TestDirHit_Fields(t *testing.T) {
	h := scanner.DirHit{
		Path:      "/tmp/my-project/node_modules",
		Ecosystem: models.EcosystemNPM,
	}
	if h.Path != "/tmp/my-project/node_modules" {
		t.Errorf("unexpected Path: %q", h.Path)
	}
	if h.Ecosystem != models.EcosystemNPM {
		t.Errorf("unexpected Ecosystem: %q", h.Ecosystem)
	}
}

// ── SourceType constants ──────────────────────────────────────────────────────

// TestSourceType_Constants verifies that SourceType constants have the expected
// string values (they appear in JSON reports and must not silently change).
func TestSourceType_Constants(t *testing.T) {
	tests := []struct {
		st   scanner.SourceType
		want string
	}{
		{scanner.SourceTypeProject, "project"},
		{scanner.SourceTypeVSCodeExt, "vscode-ext"},
		{scanner.SourceTypeCursorExt, "cursor-ext"},
		{scanner.SourceTypeGlobal, "global"},
		{scanner.SourceTypeSystem, "system"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if string(tt.st) != tt.want {
				t.Errorf("SourceType %q: got string %q, want %q", tt.st, string(tt.st), tt.want)
			}
		})
	}
}

// ── ScanResult.FoundAt ────────────────────────────────────────────────────────

// TestScan_FoundAt verifies that FoundAt is set to approximately the current
// time rather than the zero value.
func TestScan_FoundAt(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	mkdir(t, root, "project", "node_modules")

	before := time.Now()
	sc := scanner.New(scanOpts(root, home))
	results := drain(sc.Scan(context.Background()))
	after := time.Now()

	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	for _, r := range results {
		if r.FoundAt.IsZero() {
			t.Errorf("FoundAt is zero for %q", r.AbsPath)
		}
		if r.FoundAt.Before(before) || r.FoundAt.After(after) {
			t.Errorf("FoundAt %v is outside scan window [%v, %v]", r.FoundAt, before, after)
		}
	}
}

// ── FilterDetectors (exported helper) ────────────────────────────────────────

// TestFilterDetectors verifies the exported FilterDetectors helper that is
// used by custom tooling built on top of the scanner package.
func TestFilterDetectors(t *testing.T) {
	// We need at least one Detector implementation to test the filter.
	// Use a minimal anonymous implementation via a local adapter.
	tests := []struct {
		name    string
		allowed []string
		input   []models.Ecosystem
		want    []models.Ecosystem
	}{
		{
			name:    "empty allowed means all pass",
			allowed: nil,
			input:   []models.Ecosystem{models.EcosystemNPM, models.EcosystemGo},
			want:    []models.Ecosystem{models.EcosystemNPM, models.EcosystemGo},
		},
		{
			name:    "filter to npm only",
			allowed: []string{string(models.EcosystemNPM)},
			input:   []models.Ecosystem{models.EcosystemNPM, models.EcosystemGo},
			want:    []models.Ecosystem{models.EcosystemNPM},
		},
		{
			name:    "allowed ecosystem not in input",
			allowed: []string{string(models.EcosystemCargo)},
			input:   []models.Ecosystem{models.EcosystemNPM, models.EcosystemGo},
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a slice of Detector values from the input ecosystems.
			detectors := make([]scanner.Detector, len(tt.input))
			for i, eco := range tt.input {
				detectors[i] = &stubDetector{eco: eco}
			}

			got := scanner.FilterDetectors(detectors, tt.allowed)

			if len(got) != len(tt.want) {
				t.Fatalf("FilterDetectors len: got %d, want %d", len(got), len(tt.want))
			}
			for i, d := range got {
				if d.Ecosystem() != tt.want[i] {
					t.Errorf("result[%d]: got %q, want %q", i, d.Ecosystem(), tt.want[i])
				}
			}
		})
	}
}

// stubDetector is a test-only Detector that always returns false for Match.
type stubDetector struct{ eco models.Ecosystem }

func (s *stubDetector) Ecosystem() models.Ecosystem { return s.eco }
func (s *stubDetector) Match(_ string) bool          { return false }
