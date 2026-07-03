package parser

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/farzanini/dep-shield/internal/models"
	"github.com/farzanini/dep-shield/internal/scanner"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func nopLog() *zap.Logger { return zap.NewNop() }

func mkdir(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	return p
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func findPkg(pkgs []Package, name string) (Package, bool) {
	for _, p := range pkgs {
		if p.Name == name {
			return p, true
		}
	}
	return Package{}, false
}

// ── Package.ToModel ───────────────────────────────────────────────────────────

func TestPackage_ToModel_UsesResolvedVersion(t *testing.T) {
	p := Package{Name: "express", Version: "^4.0.0", ResolvedVersion: "4.18.2", Ecosystem: "npm"}
	m := p.ToModel()
	if m.Version != "4.18.2" {
		t.Errorf("ToModel version: got %s, want 4.18.2", m.Version)
	}
}

func TestPackage_ToModel_FallsBackToVersion(t *testing.T) {
	p := Package{Name: "express", Version: "4.18.2", Ecosystem: "npm"}
	m := p.ToModel()
	if m.Version != "4.18.2" {
		t.Errorf("ToModel version: got %s, want 4.18.2", m.Version)
	}
}

func TestToModels_BulkConversion(t *testing.T) {
	pkgs := []Package{
		{Name: "a", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "b", Version: "2.0.0", Ecosystem: "Go"},
	}
	models := ToModels(pkgs)
	if len(models) != 2 {
		t.Fatalf("expected 2, got %d", len(models))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeParser
// ─────────────────────────────────────────────────────────────────────────────

func TestNodeParser_Ecosystem(t *testing.T) {
	p := &NodeParser{log: nopLog()}
	if p.Ecosystem() != "npm" {
		t.Fatalf("expected npm, got %s", p.Ecosystem())
	}
}

// ── package-lock.json v1 (nested dependencies) ────────────────────────────────

func TestNodeParser_PackageLockV1_DirectAndTransitive(t *testing.T) {
	root := t.TempDir()
	nm := mkdir(t, root, "node_modules")
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
		"lockfileVersion": 1,
		"dependencies": {
			"express": {
				"version": "4.18.2",
				"dependencies": {
					"accepts": {"version": "1.3.8"}
				}
			},
			"lodash": {"version": "4.17.21"}
		}
	}`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	express, ok := findPkg(pkgs, "express")
	if !ok {
		t.Fatal("express not found")
	}
	if express.IsTransitive {
		t.Error("express should be direct (depth=1)")
	}
	if express.Depth != 1 {
		t.Errorf("express depth: got %d, want 1", express.Depth)
	}

	accepts, ok := findPkg(pkgs, "accepts")
	if !ok {
		t.Fatal("accepts not found")
	}
	if !accepts.IsTransitive {
		t.Error("accepts should be transitive")
	}
	if accepts.Depth != 2 {
		t.Errorf("accepts depth: got %d, want 2", accepts.Depth)
	}
	if len(accepts.Parents) == 0 || accepts.Parents[0] != "express" {
		t.Errorf("accepts parents: got %v, want [express]", accepts.Parents)
	}
}

// ── package-lock.json v2 (flat packages map) ──────────────────────────────────

func TestNodeParser_PackageLockV2_FlatPackages(t *testing.T) {
	root := t.TempDir()
	nm := mkdir(t, root, "node_modules")
	writeFile(t, filepath.Join(root, "package.json"), `{
		"dependencies": {"express": "^4.18.2"}
	}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
		"lockfileVersion": 2,
		"packages": {
			"": {"dependencies": {"express": "^4.18.2"}},
			"node_modules/express": {
				"version": "4.18.2",
				"dependencies": {"accepts": "^1.3.8"}
			},
			"node_modules/accepts": {
				"version": "1.3.8"
			}
		}
	}`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	express, ok := findPkg(pkgs, "express")
	if !ok {
		t.Fatal("express not found")
	}
	if express.IsTransitive {
		t.Error("express should be direct")
	}
	if express.Depth != 1 {
		t.Errorf("express depth: got %d, want 1", express.Depth)
	}

	accepts, ok := findPkg(pkgs, "accepts")
	if !ok {
		t.Fatal("accepts not found")
	}
	if !accepts.IsTransitive {
		t.Error("accepts should be transitive")
	}
}

// ── package-lock.json v3 (flat only) ─────────────────────────────────────────

func TestNodeParser_PackageLockV3_FlatOnly(t *testing.T) {
	root := t.TempDir()
	nm := mkdir(t, root, "node_modules")
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/chalk": {"version": "5.3.0"},
			"node_modules/supports-color": {"version": "9.4.0"}
		}
	}`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
}

// ── package-lock.json skips root ("") entry ───────────────────────────────────

func TestNodeParser_PackageLockV2_SkipsRootEntry(t *testing.T) {
	root := t.TempDir()
	nm := mkdir(t, root, "node_modules")
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
		"lockfileVersion": 2,
		"packages": {
			"": {"name": "my-app", "version": "1.0.0"},
			"node_modules/react": {"version": "18.2.0"}
		}
	}`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Errorf("expected 1 (root skipped), got %d", len(pkgs))
	}
}

// ── package-lock.json scoped package ─────────────────────────────────────────

func TestNodeParser_PackageLockV2_ScopedPackage(t *testing.T) {
	root := t.TempDir()
	nm := mkdir(t, root, "node_modules")
	writeFile(t, filepath.Join(root, "package-lock.json"), `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/@types/node": {"version": "20.3.1"}
		}
	}`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := findPkg(pkgs, "@types/node")
	if !ok {
		t.Fatal("@types/node not found")
	}
	if pkg.Version != "20.3.1" {
		t.Errorf("version: got %s", pkg.Version)
	}
}

// ── yarn.lock classic ─────────────────────────────────────────────────────────

func TestNodeParser_YarnClassic_BasicPackages(t *testing.T) {
	root := t.TempDir()
	nm := mkdir(t, root, "node_modules")
	writeFile(t, filepath.Join(root, "package.json"), `{
		"dependencies": {"express": "^4.18.2"}
	}`)
	writeFile(t, filepath.Join(root, "yarn.lock"), `# yarn lockfile v1

express@^4.18.2:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
  dependencies:
    accepts "^1.3.8"

accepts@^1.3.8:
  version "1.3.8"
  resolved "https://registry.yarnpkg.com/accepts/-/accepts-1.3.8.tgz"

`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	express, ok := findPkg(pkgs, "express")
	if !ok {
		t.Fatal("express not found")
	}
	if express.Version != "4.18.2" {
		t.Errorf("version: got %s", express.Version)
	}
	if express.IsTransitive {
		t.Error("express should be direct")
	}

	accepts, ok := findPkg(pkgs, "accepts")
	if !ok {
		t.Fatal("accepts not found")
	}
	if !accepts.IsTransitive {
		t.Error("accepts should be transitive")
	}
}

func TestNodeParser_YarnClassic_MultipleSpecifiers(t *testing.T) {
	root := t.TempDir()
	nm := mkdir(t, root, "node_modules")
	writeFile(t, filepath.Join(root, "yarn.lock"), `# yarn lockfile v1

lodash@^4.17.21, lodash@^4.0.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 (deduped specifiers), got %d: %v", len(pkgs), pkgs)
	}
}

// ── yarn.lock berry ───────────────────────────────────────────────────────────

func TestNodeParser_YarnBerry_BasicPackages(t *testing.T) {
	root := t.TempDir()
	nm := mkdir(t, root, "node_modules")
	writeFile(t, filepath.Join(root, "package.json"), `{
		"dependencies": {"express": "^4.18.2"}
	}`)
	writeFile(t, filepath.Join(root, "yarn.lock"), `__metadata:
  version: 8
  cacheKey: 8c0

"express@npm:^4.18.2":
  version: 4.18.2
  resolution: "express@npm:4.18.2"
  dependencies:
    accepts: ^1.3.8

"accepts@npm:^1.3.8":
  version: 1.3.8
  resolution: "accepts@npm:1.3.8"

`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	express, ok := findPkg(pkgs, "express")
	if !ok {
		t.Fatal("express not found")
	}
	if express.Version != "4.18.2" {
		t.Errorf("version: got %s", express.Version)
	}
	if express.IsTransitive {
		t.Error("express should be direct (in package.json)")
	}

	accepts, ok := findPkg(pkgs, "accepts")
	if !ok {
		t.Fatal("accepts not found")
	}
	// accepts has express as parent
	if len(accepts.Parents) == 0 {
		t.Error("accepts should have a parent")
	}
}

func TestNodeParser_YarnBerry_ScopedPackage(t *testing.T) {
	root := t.TempDir()
	nm := mkdir(t, root, "node_modules")
	writeFile(t, filepath.Join(root, "yarn.lock"), `__metadata:
  version: 8

"@types/node@npm:^20.0.0":
  version: 20.3.1
  resolution: "@types/node@npm:20.3.1"

`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := findPkg(pkgs, "@types/node")
	if !ok {
		t.Fatal("@types/node not found")
	}
	if pkg.Version != "20.3.1" {
		t.Errorf("version: got %s", pkg.Version)
	}
}

// ── fallback: scan package.json files ────────────────────────────────────────

func TestNodeParser_Fallback_PackageJSON(t *testing.T) {
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules")
	mkdir(t, nm, "express")
	writeFile(t, filepath.Join(nm, "express", "package.json"),
		`{"name":"express","version":"4.18.2"}`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := findPkg(pkgs, "express")
	if !ok {
		t.Fatal("express not found")
	}
	if pkg.Version != "4.18.2" {
		t.Errorf("version: got %s", pkg.Version)
	}
}

func TestNodeParser_Fallback_ScopedPackage(t *testing.T) {
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules")
	mkdir(t, nm, "@types", "node")
	writeFile(t, filepath.Join(nm, "@types", "node", "package.json"),
		`{"name":"@types/node","version":"20.3.1"}`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := findPkg(pkgs, "@types/node")
	if !ok {
		t.Fatal("@types/node not found")
	}
	if pkg.Version != "20.3.1" {
		t.Errorf("version: got %s", pkg.Version)
	}
}

func TestNodeParser_Fallback_MissingOrMalformedJSON(t *testing.T) {
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules")
	mkdir(t, nm, "broken")
	writeFile(t, filepath.Join(nm, "broken", "package.json"), `{not valid}`)
	mkdir(t, nm, "noversion")
	writeFile(t, filepath.Join(nm, "noversion", "package.json"), `{"name":"noversion"}`)

	p := &NodeParser{log: nopLog()}
	pkgs, err := p.Parse(nm)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0, got %d", len(pkgs))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GoParser
// ─────────────────────────────────────────────────────────────────────────────

func TestGoParser_Ecosystem(t *testing.T) {
	p := &GoParser{log: nopLog()}
	if p.Ecosystem() != "Go" {
		t.Fatalf("expected Go, got %s", p.Ecosystem())
	}
}

func TestGoParser_Parse_DirectAndIndirect(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), `module github.com/example/app

go 1.22

require (
	github.com/pkg/errors v0.9.1
	golang.org/x/sync v0.7.0 // indirect
)
`)
	writeFile(t, filepath.Join(root, "go.sum"), `github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt38=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
golang.org/x/sync v0.7.0 h1:YsImfSBoP9QPYL0xyKJPq0gcaJdG3rInoqxTWbfQu9M=
golang.org/x/sync v0.7.0/go.mod h1:Czt+wKu1gCyEFDUtn0jG5QVvpJ6rzVqr5aXyt9drQfk=
`)

	p := &GoParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	errors, ok := findPkg(pkgs, "github.com/pkg/errors")
	if !ok {
		t.Fatal("pkg/errors not found")
	}
	if errors.IsTransitive {
		t.Error("pkg/errors should be direct")
	}
	if errors.Depth != 1 {
		t.Errorf("depth: got %d, want 1", errors.Depth)
	}

	sync, ok := findPkg(pkgs, "golang.org/x/sync")
	if !ok {
		t.Fatal("x/sync not found")
	}
	if !sync.IsTransitive {
		t.Error("x/sync should be indirect/transitive")
	}
	if sync.Depth != 2 {
		t.Errorf("x/sync depth: got %d, want 2", sync.Depth)
	}
}

func TestGoParser_Parse_SkipsGoModLines(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.sum"), `github.com/foo/bar v1.0.0 h1:abc=
github.com/foo/bar v1.0.0/go.mod h1:xyz=
`)

	p := &GoParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 (go.mod line skipped), got %d", len(pkgs))
	}
}

func TestGoParser_Parse_DeduplicatesVersions(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.sum"), `github.com/foo/bar v1.0.0 h1:abc=
github.com/foo/bar v1.0.0 h1:abc=
`)

	p := &GoParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Errorf("expected 1 (deduped), got %d", len(pkgs))
	}
}

func TestGoParser_Parse_MissingGoSum(t *testing.T) {
	root := t.TempDir()
	p := &GoParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatalf("missing go.sum should not error, got: %v", err)
	}
	if pkgs != nil {
		t.Errorf("expected nil, got %v", pkgs)
	}
}

func TestGoParser_Parse_SingleLineRequire(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), `module example.com/app
go 1.22
require github.com/spf13/cobra v1.8.1
`)
	writeFile(t, filepath.Join(root, "go.sum"), `github.com/spf13/cobra v1.8.1 h1:x=
`)

	p := &GoParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := findPkg(pkgs, "github.com/spf13/cobra")
	if !ok {
		t.Fatal("cobra not found")
	}
	if pkg.IsTransitive {
		t.Error("cobra should be direct")
	}
}

func TestGoParser_Parse_EcosystemField(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.sum"), "github.com/a/b v1.0.0 h1:x=\n")

	p := &GoParser{log: nopLog()}
	pkgs, _ := p.Parse(root)
	if len(pkgs) == 0 {
		t.Fatal("no packages")
	}
	if pkgs[0].Ecosystem != "Go" {
		t.Errorf("ecosystem: got %s", pkgs[0].Ecosystem)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CargoParser
// ─────────────────────────────────────────────────────────────────────────────

func TestCargoParser_Ecosystem(t *testing.T) {
	p := &CargoParser{log: nopLog()}
	if p.Ecosystem() != "crates.io" {
		t.Fatalf("expected crates.io, got %s", p.Ecosystem())
	}
}

func TestCargoParser_Parse_DirectAndTransitive(t *testing.T) {
	root := t.TempDir()
	// The root crate has no source; its deps are serde and tokio.
	// serde depends on serde_derive → transitive.
	writeFile(t, filepath.Join(root, "Cargo.lock"), `# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = [
 "serde",
 "tokio",
]

[[package]]
name = "serde"
version = "1.0.163"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "serde_derive",
]

[[package]]
name = "serde_derive"
version = "1.0.163"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.28.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)

	p := &CargoParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// my-app (root) is skipped; serde + tokio + serde_derive = 3
	if len(pkgs) != 3 {
		t.Fatalf("expected 3, got %d: %v", len(pkgs), pkgs)
	}

	serde, ok := findPkg(pkgs, "serde")
	if !ok {
		t.Fatal("serde not found")
	}
	if serde.IsTransitive {
		t.Error("serde should be direct")
	}
	if serde.Depth != 1 {
		t.Errorf("serde depth: got %d", serde.Depth)
	}

	derive, ok := findPkg(pkgs, "serde_derive")
	if !ok {
		t.Fatal("serde_derive not found")
	}
	if !derive.IsTransitive {
		t.Error("serde_derive should be transitive")
	}
	if len(derive.Parents) == 0 || derive.Parents[0] != "serde" {
		t.Errorf("serde_derive parents: got %v, want [serde]", derive.Parents)
	}
}

func TestCargoParser_Parse_SkipsRootCrate(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cargo.lock"), `[[package]]
name = "my-lib"
version = "0.1.0"

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)

	p := &CargoParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	// my-lib is root (no source), should be skipped
	if len(pkgs) != 1 {
		t.Fatalf("expected 1, got %d", len(pkgs))
	}
	if pkgs[0].Name != "rand" {
		t.Errorf("expected rand, got %s", pkgs[0].Name)
	}
}

func TestCargoParser_Parse_MissingFile(t *testing.T) {
	root := t.TempDir()
	p := &CargoParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatalf("missing Cargo.lock should not error: %v", err)
	}
	if pkgs != nil {
		t.Errorf("expected nil, got %v", pkgs)
	}
}

func TestCargoParser_Parse_EcosystemField(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cargo.lock"),
		"[[package]]\nname = \"foo\"\nversion = \"0.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n")

	p := &CargoParser{log: nopLog()}
	pkgs, _ := p.Parse(root)
	if len(pkgs) == 0 {
		t.Fatal("no packages")
	}
	if pkgs[0].Ecosystem != "crates.io" {
		t.Errorf("ecosystem: got %s", pkgs[0].Ecosystem)
	}
}

func TestCargoParser_Parse_MultilineDependencies(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cargo.lock"), `[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "dep-a",
 "dep-b",
]

[[package]]
name = "dep-a"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "dep-b"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)

	p := &CargoParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PythonParser
// ─────────────────────────────────────────────────────────────────────────────

func TestPythonParser_Ecosystem(t *testing.T) {
	p := &PythonParser{log: nopLog()}
	if p.Ecosystem() != "PyPI" {
		t.Fatalf("expected PyPI, got %s", p.Ecosystem())
	}
}

// ── Pipfile.lock ──────────────────────────────────────────────────────────────

func TestPythonParser_PipfileLock_Basic(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Pipfile.lock"), `{
		"_meta": {"requires": {"python_version": "3.11"}},
		"default": {
			"requests": {"version": "==2.31.0"},
			"certifi": {"version": "==2023.5.7"}
		},
		"develop": {
			"pytest": {"version": "==7.4.0"}
		}
	}`)

	p := &PythonParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3, got %d: %v", len(pkgs), pkgs)
	}
	req, ok := findPkg(pkgs, "requests")
	if !ok {
		t.Fatal("requests not found")
	}
	if req.Version != "2.31.0" {
		t.Errorf("version: got %s, want 2.31.0", req.Version)
	}
}

func TestPythonParser_PipfileLock_StripVersionPrefix(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Pipfile.lock"), `{
		"default": {"flask": {"version": "==2.3.2"}},
		"develop": {}
	}`)

	p := &PythonParser{log: nopLog()}
	pkgs, _ := p.Parse(root)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1, got %d", len(pkgs))
	}
	if pkgs[0].Version != "2.3.2" {
		t.Errorf("version should strip ==, got %s", pkgs[0].Version)
	}
}

func TestPythonParser_PipfileLock_DedupAcrossSections(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Pipfile.lock"), `{
		"default": {"requests": {"version": "==2.31.0"}},
		"develop": {"requests": {"version": "==2.31.0"}}
	}`)

	p := &PythonParser{log: nopLog()}
	pkgs, _ := p.Parse(root)
	if len(pkgs) != 1 {
		t.Errorf("expected 1 (deduped), got %d", len(pkgs))
	}
}

// ── poetry.lock ───────────────────────────────────────────────────────────────

func TestPythonParser_PoetryLock_Basic(t *testing.T) {
	root := t.TempDir()
	// No Pipfile.lock present → falls through to poetry.lock.
	writeFile(t, filepath.Join(root, "poetry.lock"), `[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"

[package.dependencies]
certifi = ">=2017.4.17"
urllib3 = ">=1.21.1,<3"

[[package]]
name = "certifi"
version = "2023.5.7"
description = "Python package for providing Mozilla's CA Bundle."
optional = false
python-versions = ">=3.6"

[[package]]
name = "urllib3"
version = "2.0.3"
description = "HTTP library with thread-safe connection pooling."
optional = false
`)

	p := &PythonParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3, got %d: %v", len(pkgs), pkgs)
	}

	req, ok := findPkg(pkgs, "requests")
	if !ok {
		t.Fatal("requests not found")
	}
	// requests has no parents → treated as direct
	if req.IsTransitive {
		t.Error("requests should be direct (no parents)")
	}

	cert, ok := findPkg(pkgs, "certifi")
	if !ok {
		t.Fatal("certifi not found")
	}
	if !cert.IsTransitive {
		t.Error("certifi should be transitive (listed in requests deps)")
	}
	if len(cert.Parents) == 0 || cert.Parents[0] != "requests" {
		t.Errorf("certifi parents: got %v, want [requests]", cert.Parents)
	}
}

func TestPythonParser_PoetryLock_MissingFile(t *testing.T) {
	root := t.TempDir()
	// Neither Pipfile.lock nor poetry.lock exists → falls to requirements.txt.
	p := &PythonParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatalf("missing files should not error: %v", err)
	}
	if pkgs != nil {
		t.Errorf("expected nil, got %v", pkgs)
	}
}

// ── requirements.txt ─────────────────────────────────────────────────────────

func TestPythonParser_Requirements_Basic(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "requirements.txt"), `# comment
requests==2.31.0
flask==2.3.2  # web framework
-r other-requirements.txt
git+https://github.com/foo/bar.git
Django>=3.0
numpy==1.24.0
`)

	p := &PythonParser{log: nopLog()}
	pkgs, err := p.Parse(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// requests, flask, numpy — 3 pinned packages
	if len(pkgs) != 3 {
		t.Fatalf("expected 3, got %d: %v", len(pkgs), pkgs)
	}
	req, ok := findPkg(pkgs, "requests")
	if !ok {
		t.Fatal("requests not found")
	}
	if req.Version != "2.31.0" {
		t.Errorf("version: got %s", req.Version)
	}
	if req.Depth != 1 {
		t.Errorf("depth: got %d, want 1", req.Depth)
	}
}

func TestPythonParser_Requirements_AllDirect(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "requirements.txt"), "boto3==1.28.0\nbotocore==1.31.0\n")

	p := &PythonParser{log: nopLog()}
	pkgs, _ := p.Parse(root)
	for _, pkg := range pkgs {
		if pkg.IsTransitive {
			t.Errorf("%s should be direct from requirements.txt", pkg.Name)
		}
	}
}

// ── site-packages fallback ────────────────────────────────────────────────────

func TestPythonParser_SitePackages_DistInfo(t *testing.T) {
	root := t.TempDir()
	siteDir := mkdir(t, root, "site-packages")
	distInfo := mkdir(t, siteDir, "requests-2.31.0.dist-info")
	writeFile(t, filepath.Join(distInfo, "METADATA"),
		"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\nlong desc\n")

	p := &PythonParser{log: nopLog()}
	pkgs, err := p.Parse(siteDir)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := findPkg(pkgs, "requests")
	if !ok {
		t.Fatal("requests not found")
	}
	if pkg.Version != "2.31.0" {
		t.Errorf("version: got %s", pkg.Version)
	}
}

func TestPythonParser_SitePackages_IgnoresNonDistInfo(t *testing.T) {
	root := t.TempDir()
	siteDir := mkdir(t, root, "site-packages")
	mkdir(t, siteDir, "requests") // not .dist-info

	p := &PythonParser{log: nopLog()}
	pkgs, _ := p.Parse(siteDir)
	if len(pkgs) != 0 {
		t.Errorf("expected 0, got %d", len(pkgs))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

func TestTomlStringValue(t *testing.T) {
	tests := []struct {
		line   string
		key    string
		want   string
		wantOK bool
	}{
		{`name = "serde"`, "name", "serde", true},
		{`version = "1.0.0"`, "version", "1.0.0", true},
		{`source = "registry+https://..."`, "name", "", false},
		{`name = no-quotes`, "name", "", false},
		{``, "name", "", false},
	}
	for _, tt := range tests {
		got, ok := tomlStringValue(tt.line, tt.key)
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("tomlStringValue(%q, %q) = (%q, %v), want (%q, %v)",
				tt.line, tt.key, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestYarnSpecName(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{"express@^4.18.2", "express"},
		{"@types/node@npm:^20.0.0", "@types/node"},
		{"lodash@^4.17.21", "lodash"},
		{"noscope", "noscope"},
	}
	for _, tt := range tests {
		got := yarnSpecName(tt.spec)
		if got != tt.want {
			t.Errorf("yarnSpecName(%q) = %q, want %q", tt.spec, got, tt.want)
		}
	}
}

func TestBerrySpecName(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{"express@npm:^4.18.2", "express"},
		{"@types/node@npm:^20.0.0", "@types/node"},
		{"lodash@npm:^4.17.21", "lodash"},
	}
	for _, tt := range tests {
		got := berrySpecName(tt.spec)
		if got != tt.want {
			t.Errorf("berrySpecName(%q) = %q, want %q", tt.spec, got, tt.want)
		}
	}
}

func TestUnquote(t *testing.T) {
	tests := []struct{ in, want string }{
		{`"hello"`, "hello"},
		{`'hello'`, "hello"},
		{`hello`, "hello"},
		{`""`, ""},
	}
	for _, tt := range tests {
		if got := unquote(tt.in); got != tt.want {
			t.Errorf("unquote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCoalesce(t *testing.T) {
	if coalesce("a", "b") != "a" {
		t.Error("should return first non-empty")
	}
	if coalesce("", "b") != "b" {
		t.Error("should skip empty first")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatcher
// ─────────────────────────────────────────────────────────────────────────────

func TestDispatcher_ParseAll_Empty(t *testing.T) {
	d := New(nopLog())
	pkgs, err := d.ParseAll(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0, got %d", len(pkgs))
	}
}

func TestDispatcher_ParseAll_UnknownEcosystem(t *testing.T) {
	d := New(nopLog())
	hits := []scanner.DirHit{{Path: "/nonexistent", Ecosystem: models.Ecosystem("unknown")}}
	pkgs, err := d.ParseAll(context.Background(), hits)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0, got %d", len(pkgs))
	}
}

func TestDispatcher_ParseAll_MultipleEcosystems(t *testing.T) {
	root := t.TempDir()

	// npm
	nm := filepath.Join(root, "node_modules")
	mkdir(t, nm, "express")
	writeFile(t, filepath.Join(nm, "express", "package.json"),
		`{"name":"express","version":"4.18.2"}`)

	// go
	goDir := mkdir(t, root, "go-project")
	writeFile(t, filepath.Join(goDir, "go.sum"),
		"github.com/pkg/errors v0.9.1 h1:x=\n")

	// cargo
	cargoDir := mkdir(t, root, "rust-project")
	writeFile(t, filepath.Join(cargoDir, "Cargo.lock"),
		"[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://crates.io\"\n")

	hits := []scanner.DirHit{
		{Path: nm, Ecosystem: models.EcosystemNPM},
		{Path: goDir, Ecosystem: models.EcosystemGo},
		{Path: cargoDir, Ecosystem: models.EcosystemCargo},
	}

	d := New(nopLog())
	pkgs, err := d.ParseAll(context.Background(), hits)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3, got %d: %v", len(pkgs), pkgs)
	}
}

func TestDispatcher_ParseAll_DeduplicatesAcrossHits(t *testing.T) {
	root := t.TempDir()
	for _, sub := range []string{"a", "b"} {
		nm := filepath.Join(root, sub, "node_modules")
		mkdir(t, nm, "lodash")
		writeFile(t, filepath.Join(nm, "lodash", "package.json"),
			`{"name":"lodash","version":"4.17.21"}`)
	}

	hits := []scanner.DirHit{
		{Path: filepath.Join(root, "a", "node_modules"), Ecosystem: models.EcosystemNPM},
		{Path: filepath.Join(root, "b", "node_modules"), Ecosystem: models.EcosystemNPM},
	}

	d := New(nopLog())
	pkgs, err := d.ParseAll(context.Background(), hits)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Errorf("expected 1 (deduped), got %d", len(pkgs))
	}
}

func TestDispatcher_NilLogger(t *testing.T) {
	d := New(nil) // should not panic
	pkgs, err := d.ParseAll(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = pkgs
}

// ── ParseError ────────────────────────────────────────────────────────────────

func TestParseError_ContainsPath(t *testing.T) {
	e := &ParseError{Path: "/foo/bar", Err: os.ErrNotExist}
	if !strings.Contains(e.Error(), "/foo/bar") {
		t.Errorf("error message should contain path: %s", e.Error())
	}
}

func TestParseError_Unwrap(t *testing.T) {
	e := &ParseError{Path: "/foo", Err: os.ErrNotExist}
	if e.Unwrap() != os.ErrNotExist {
		t.Errorf("Unwrap() = %v", e.Unwrap())
	}
}
