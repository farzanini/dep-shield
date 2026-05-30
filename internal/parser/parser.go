// Package parser reads dependency manifests and lockfiles, converting them into
// a uniform Package slice that the advisory-query layer can consume.
//
// Architecture
// ─────────────
// Each file format is handled by its own type that satisfies the Parser
// interface.  A Dispatcher maps a scanner.DirHit's Ecosystem value to the
// correct Parser and runs them concurrently via errgroup.
//
// The Parser interface uses a single string parameter (the directory the
// scanner matched) so that each implementation can decide which files to open;
// a node_modules/ dir needs very different logic than a directory containing
// Cargo.lock.
//
// Dependency graph metadata
// ─────────────────────────
// Where the lockfile format exposes it, each Package carries:
//   - IsTransitive  true when the package is not listed as a direct dependency
//   - Depth         1 = direct, 2 = first-level transitive, etc.
//                   (Go and pip set 2 for all known-transitive, ≥3 is unknown)
//   - Parents       names of the packages that require this one
//
// This metadata powers future scoring: a critical vuln in a deeply transitive
// package is lower-risk than the same vuln in a direct dependency.
package parser

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/dep-shield/dep-shield/internal/models"
	"github.com/dep-shield/dep-shield/internal/scanner"
)

// ── Public types ──────────────────────────────────────────────────────────────

// Package is one resolved dependency entry, enriched with graph metadata.
// It is richer than models.Package; call ToModel() when the advisory layer
// needs the leaner type.
type Package struct {
	Name            string
	Version         string
	Ecosystem       string
	ResolvedVersion string // exact version string from the lockfile
	IsTransitive    bool
	Depth           int      // 1 = direct, 2 = first transitive, etc.
	Parents         []string // package names that declare this as a dependency
}

// ToModel converts to the leaner models.Package used by the advisory layer.
func (p Package) ToModel() models.Package {
	return models.Package{
		Name:      p.Name,
		Version:   coalesce(p.ResolvedVersion, p.Version),
		Ecosystem: models.Ecosystem(p.Ecosystem),
	}
}

// ToModels bulk-converts a []Package slice.
func ToModels(pkgs []Package) []models.Package {
	out := make([]models.Package, len(pkgs))
	for i, p := range pkgs {
		out[i] = p.ToModel()
	}
	return out
}

// ── Parser interface ──────────────────────────────────────────────────────────

// Parser extracts Package records from one matched directory.
// The parameter is the directory path returned by the scanner — each
// implementation knows which files live inside it.
type Parser interface {
	// Parse reads the manifest/lockfile(s) inside dir and returns every
	// resolved package it can identify.
	// Implementations must honour ctx cancellation.
	Parse(dir string) ([]Package, error)

	// Ecosystem returns the ecosystem string (matches models.Ecosystem constants).
	Ecosystem() string
}

// ── ParseError ────────────────────────────────────────────────────────────────

// ParseError is returned when a specific file cannot be read or decoded.
// The Dispatcher logs these and continues; it never aborts the whole scan.
type ParseError struct {
	Path string
	Err  error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("parsing %s: %v", e.Path, e.Err)
}
func (e *ParseError) Unwrap() error { return e.Err }

// ── Dispatcher ────────────────────────────────────────────────────────────────

// Dispatcher fans out scanner.DirHit values to the correct Parser and merges
// results, deduplicating across directories.
type Dispatcher interface {
	ParseAll(ctx context.Context, hits []scanner.DirHit) ([]Package, error)
}

type dispatcher struct {
	parsers map[models.Ecosystem]Parser
	log     *zap.Logger
}

// New constructs a Dispatcher pre-loaded with all built-in parsers.
func New(log *zap.Logger) Dispatcher {
	if log == nil {
		log = zap.NewNop()
	}
	d := &dispatcher{
		parsers: make(map[models.Ecosystem]Parser),
		log:     log,
	}
	for _, p := range []Parser{
		&NodeParser{log: log},
		&GoParser{log: log},
		&CargoParser{log: log},
		&PythonParser{log: log},
	} {
		d.parsers[models.Ecosystem(p.Ecosystem())] = p
	}
	return d
}

func (d *dispatcher) ParseAll(ctx context.Context, hits []scanner.DirHit) ([]Package, error) {
	type result struct{ pkgs []Package }

	ch := make(chan result, len(hits))
	var wg sync.WaitGroup

	g, gctx := errgroup.WithContext(ctx)

	for _, hit := range hits {
		hit := hit
		p, ok := d.parsers[hit.Ecosystem]
		if !ok {
			d.log.Warn("no parser registered",
				zap.String("ecosystem", string(hit.Ecosystem)))
			continue
		}
		wg.Add(1)
		g.Go(func() error {
			defer wg.Done()
			if gctx.Err() != nil {
				return nil
			}
			pkgs, err := p.Parse(hit.Path)
			if err != nil {
				d.log.Warn("parse error",
					zap.String("path", hit.Path),
					zap.Error(err))
				ch <- result{nil}
				return nil
			}
			ch <- result{pkgs}
			return nil
		})
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	_ = g.Wait()

	seen := make(map[string]struct{})
	var all []Package
	for r := range ch {
		for _, pkg := range r.pkgs {
			key := pkg.Ecosystem + "|" + pkg.Name + "|" + coalesce(pkg.ResolvedVersion, pkg.Version)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			all = append(all, pkg)
		}
	}
	return all, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeParser
// ─────────────────────────────────────────────────────────────────────────────

// NodeParser handles node_modules/ directories.
// It looks in the parent directory for:
//  1. package-lock.json  (npm v1 / v2 / v3 formats)
//  2. yarn.lock          (Yarn classic v1 or Yarn berry v2+)
//
// If neither lockfile is found it falls back to reading each installed
// package's own package.json — this gives name+version but no graph metadata.
type NodeParser struct {
	log *zap.Logger
}

func (n *NodeParser) Ecosystem() string { return string(models.EcosystemNPM) }

func (n *NodeParser) Parse(dir string) ([]Package, error) {
	parent := filepath.Dir(dir)

	// --- try package-lock.json ---
	plPath := filepath.Join(parent, "package-lock.json")
	if _, err := os.Stat(plPath); err == nil {
		pkgs, err := n.parsePackageLock(plPath, dir)
		if err != nil {
			n.log.Warn("package-lock.json parse failed, falling back",
				zap.String("path", plPath), zap.Error(err))
		} else {
			return pkgs, nil
		}
	}

	// --- try yarn.lock ---
	yarnPath := filepath.Join(parent, "yarn.lock")
	if _, err := os.Stat(yarnPath); err == nil {
		pkgs, err := n.parseYarnLock(yarnPath, dir, parent)
		if err != nil {
			n.log.Warn("yarn.lock parse failed, falling back",
				zap.String("path", yarnPath), zap.Error(err))
		} else {
			return pkgs, nil
		}
	}

	// --- fallback: scan package.json files inside node_modules ---
	return n.fallbackScan(dir)
}

// ── package-lock.json ─────────────────────────────────────────────────────────

type pkgLockRoot struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]pkgLockFlat `json:"packages"`   // v2/v3
	Dependencies    map[string]pkgLockDep  `json:"dependencies"` // v1
}

// pkgLockFlat is one entry in the v2/v3 "packages" map.
type pkgLockFlat struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved"`
	Dev          bool              `json:"dev"`
	Dependencies map[string]string `json:"dependencies"`
}

// pkgLockDep is one entry in the v1 nested "dependencies" map.
type pkgLockDep struct {
	Version      string                `json:"version"`
	Resolved     string                `json:"resolved"`
	Dev          bool                  `json:"dev"`
	Dependencies map[string]pkgLockDep `json:"dependencies"` // nested
}

func (n *NodeParser) parsePackageLock(path, nodeModulesDir string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	var root pkgLockRoot
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	switch {
	case root.LockfileVersion >= 2 && root.Packages != nil:
		return n.fromPackageLockFlat(root.Packages, nodeModulesDir), nil
	case root.LockfileVersion == 1 || root.Dependencies != nil:
		return n.fromPackageLockNested(root.Dependencies, nodeModulesDir), nil
	default:
		// version field missing or zero, try flat first then nested
		if root.Packages != nil {
			return n.fromPackageLockFlat(root.Packages, nodeModulesDir), nil
		}
		return n.fromPackageLockNested(root.Dependencies, nodeModulesDir), nil
	}
}

// fromPackageLockFlat handles lockfileVersion 2 and 3.
// Keys are like "node_modules/express" or "node_modules/@types/node".
// The empty-string key "" represents the root package itself — skip it.
func (n *NodeParser) fromPackageLockFlat(pkgs map[string]pkgLockFlat, nmDir string) []Package {
	// Build a set of direct dep names from the root package (key == "").
	directNames := make(map[string]bool)
	if root, ok := pkgs[""]; ok {
		for name := range root.Dependencies {
			directNames[name] = true
		}
	}

	var out []Package
	for key, entry := range pkgs {
		if key == "" {
			continue
		}
		// key = "node_modules/express" or "node_modules/@scope/pkg"
		name := strings.TrimPrefix(key, "node_modules/")
		// Strip nested paths like "node_modules/foo/node_modules/bar"
		if idx := strings.Index(name, "/node_modules/"); idx >= 0 {
			name = name[idx+len("/node_modules/"):]
		}
		if name == "" {
			continue
		}

		isDirect := directNames[name]
		depth := 2
		if isDirect {
			depth = 1
		}

		out = append(out, Package{
			Name:            name,
			Version:         entry.Version,
			Ecosystem:       string(models.EcosystemNPM),
			ResolvedVersion: entry.Version,
			IsTransitive:    !isDirect,
			Depth:           depth,
		})
	}
	return out
}

// fromPackageLockNested handles lockfileVersion 1 (recursive dependencies tree).
func (n *NodeParser) fromPackageLockNested(deps map[string]pkgLockDep, nmDir string) []Package {
	var out []Package
	n.walkV1Deps(deps, 1, nil, &out)
	return out
}

func (n *NodeParser) walkV1Deps(deps map[string]pkgLockDep, depth int, parents []string, out *[]Package) {
	for name, dep := range deps {
		pkg := Package{
			Name:            name,
			Version:         dep.Version,
			Ecosystem:       string(models.EcosystemNPM),
			ResolvedVersion: dep.Version,
			IsTransitive:    depth > 1,
			Depth:           depth,
			Parents:         append([]string(nil), parents...),
		}
		*out = append(*out, pkg)
		if len(dep.Dependencies) > 0 {
			n.walkV1Deps(dep.Dependencies, depth+1, append(parents, name), out)
		}
	}
}

// ── yarn.lock ─────────────────────────────────────────────────────────────────

func (n *NodeParser) parseYarnLock(path, nmDir, projectDir string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	content := string(data)

	if strings.Contains(content, "__metadata:") {
		return n.parseYarnBerry(content, path, projectDir)
	}
	return n.parseYarnClassic(content, path, projectDir)
}

// parseYarnClassic handles Yarn v1 "classic" lockfiles.
//
// Format:
//
//	# yarn lockfile v1
//
//	express@^4.18.2:
//	  version "4.18.2"
//	  resolved "https://..."
//	  dependencies:
//	    accepts "^1.3.8"
// yarnEntry holds one parsed block from a Yarn classic lockfile.
// Declared at package scope so findYarnParents can reference it.
type yarnEntry struct {
	name    string
	version string
	deps    []string
}

func (n *NodeParser) parseYarnClassic(content, path, projectDir string) ([]Package, error) {
	directNames := n.readRootPackageJSON(projectDir)

	var entries []yarnEntry
	var cur *yarnEntry
	inDeps := false

	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)

		if line == "" || strings.HasPrefix(line, "#") {
			if cur != nil && line == "" {
				entries = append(entries, *cur)
				cur = nil
				inDeps = false
			}
			continue
		}

		// Header: `express@^4.18.2, express@^4.18.0:` (may have multiple specifiers)
		if !strings.HasPrefix(raw, " ") && strings.HasSuffix(line, ":") {
			if cur != nil {
				entries = append(entries, *cur)
			}
			// Extract bare name from first specifier.
			spec := strings.TrimSuffix(line, ":")
			spec = strings.SplitN(spec, ",", 2)[0]
			spec = strings.TrimSpace(spec)
			name := yarnSpecName(spec)
			cur = &yarnEntry{name: name}
			inDeps = false
			continue
		}

		if cur == nil {
			continue
		}

		if strings.HasPrefix(line, "version ") {
			cur.version = unquote(strings.TrimPrefix(line, "version "))
			continue
		}
		if line == "dependencies:" {
			inDeps = true
			continue
		}
		if inDeps && strings.HasPrefix(raw, "    ") {
			// `    accepts "^1.3.8"` or `    accepts: "^1.3.8"`
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				depName := strings.TrimSuffix(parts[0], ":")
				cur.deps = append(cur.deps, depName)
			}
			continue
		}
		if inDeps && !strings.HasPrefix(raw, " ") {
			inDeps = false
		}
	}
	if cur != nil {
		entries = append(entries, *cur)
	}

	var out []Package
	for _, e := range entries {
		if e.version == "" {
			continue
		}
		isDirect := directNames[e.name]
		parents := findYarnParents(e.name, entries)
		out = append(out, Package{
			Name:            e.name,
			Version:         e.version,
			Ecosystem:       string(models.EcosystemNPM),
			ResolvedVersion: e.version,
			IsTransitive:    !isDirect,
			Depth:           yarnDepth(e.name, directNames),
			Parents:         parents,
		})
	}
	return out, nil
}

// parseYarnBerry handles Yarn v2+ "berry" lockfiles.
//
// Format (YAML-ish):
//
//	__metadata:
//	  version: 8
//
//	"express@npm:^4.18.2":
//	  version: 4.18.2
//	  resolution: "express@npm:4.18.2"
//	  dependencies:
//	    accepts: ^1.3.8
func (n *NodeParser) parseYarnBerry(content, path, projectDir string) ([]Package, error) {
	directNames := n.readRootPackageJSON(projectDir)

	type berryEntry struct {
		name    string
		version string
		deps    []string
	}

	var entries []berryEntry
	var cur *berryEntry
	inDeps := false

	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)

		if line == "" {
			if cur != nil {
				entries = append(entries, *cur)
				cur = nil
				inDeps = false
			}
			continue
		}

		// Top-level key: `"express@npm:^4.18.2":`
		if !strings.HasPrefix(raw, " ") && strings.HasSuffix(line, ":") {
			if cur != nil {
				entries = append(entries, *cur)
			}
			spec := strings.Trim(strings.TrimSuffix(line, ":"), `"`)
			// spec = "express@npm:^4.18.2" — take part before first @
			// But scoped packages like "@types/node@npm:..." need care.
			name := berrySpecName(spec)
			if name == "__metadata" {
				cur = nil
				continue
			}
			cur = &berryEntry{name: name}
			inDeps = false
			continue
		}

		if cur == nil {
			continue
		}

		if strings.HasPrefix(line, "version: ") {
			cur.version = unquote(strings.TrimPrefix(line, "version: "))
			continue
		}
		if line == "dependencies:" {
			inDeps = true
			continue
		}
		if inDeps && strings.HasPrefix(raw, "    ") {
			// `    accepts: ^1.3.8`
			colonIdx := strings.Index(line, ":")
			if colonIdx > 0 {
				depName := strings.TrimSpace(line[:colonIdx])
				cur.deps = append(cur.deps, depName)
			}
			continue
		}
		if inDeps && strings.HasPrefix(raw, "  ") && !strings.HasPrefix(raw, "    ") {
			inDeps = false
		}
	}
	if cur != nil {
		entries = append(entries, *cur)
	}

	var out []Package
	for _, e := range entries {
		if e.version == "" {
			continue
		}
		isDirect := directNames[e.name]
		// Compute parents: which entries list this name in deps?
		var parents []string
		for _, other := range entries {
			for _, d := range other.deps {
				if d == e.name {
					parents = append(parents, other.name)
					break
				}
			}
		}
		out = append(out, Package{
			Name:            e.name,
			Version:         e.version,
			Ecosystem:       string(models.EcosystemNPM),
			ResolvedVersion: e.version,
			IsTransitive:    !isDirect,
			Depth:           ternary(isDirect, 1, 2),
			Parents:         parents,
		})
	}
	return out, nil
}

// ── node fallback: scan package.json files ────────────────────────────────────

type minPkgJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (n *NodeParser) fallbackScan(nmDir string) ([]Package, error) {
	entries, err := os.ReadDir(nmDir)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", nmDir, err)
	}
	var out []Package
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "@") {
			// scoped: one more level
			scopeDir := filepath.Join(nmDir, name)
			subs, _ := os.ReadDir(scopeDir)
			for _, sub := range subs {
				if !sub.IsDir() {
					continue
				}
				pkg, ok := n.readPkgJSON(filepath.Join(scopeDir, sub.Name(), "package.json"), nmDir)
				if ok {
					out = append(out, pkg)
				}
			}
			continue
		}
		pkg, ok := n.readPkgJSON(filepath.Join(nmDir, name, "package.json"), nmDir)
		if ok {
			out = append(out, pkg)
		}
	}
	return out, nil
}

func (n *NodeParser) readPkgJSON(path, nmDir string) (Package, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Package{}, false
	}
	var pj minPkgJSON
	if err := json.Unmarshal(data, &pj); err != nil || pj.Name == "" || pj.Version == "" {
		return Package{}, false
	}
	return Package{
		Name:            pj.Name,
		Version:         pj.Version,
		Ecosystem:       string(models.EcosystemNPM),
		ResolvedVersion: pj.Version,
		IsTransitive:    false, // unknown without lockfile
		Depth:           1,
	}, true
}

// readRootPackageJSON reads the project-level package.json to find direct deps.
func (n *NodeParser) readRootPackageJSON(dir string) map[string]bool {
	type rootPkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var rp rootPkg
	if err := json.Unmarshal(data, &rp); err != nil {
		return nil
	}
	direct := make(map[string]bool)
	for name := range rp.Dependencies {
		direct[name] = true
	}
	for name := range rp.DevDependencies {
		direct[name] = true
	}
	return direct
}

// ─────────────────────────────────────────────────────────────────────────────
// GoParser
// ─────────────────────────────────────────────────────────────────────────────

// GoParser reads go.sum (all resolved versions) and go.mod (direct vs indirect
// classification).
//
// dir is the module root directory — the one that contains go.sum and go.mod.
// The scanner hits a directory when it finds a go.sum or go.mod file, so dir
// is already the right place.
type GoParser struct {
	log *zap.Logger
}

func (g *GoParser) Ecosystem() string { return string(models.EcosystemGo) }

func (g *GoParser) Parse(dir string) ([]Package, error) {
	// Read go.mod first to learn which modules are direct dependencies.
	directMods, err := g.parseGoMod(filepath.Join(dir, "go.mod"))
	if err != nil && !os.IsNotExist(err) {
		g.log.Warn("go.mod read failed", zap.String("dir", dir), zap.Error(err))
	}

	// Parse go.sum for all resolved module@version pairs.
	pkgs, err := g.parseGoSum(filepath.Join(dir, "go.sum"), directMods)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // go.sum is optional (e.g. module with no dependencies)
		}
		return nil, fmt.Errorf("parsing %s: %w", filepath.Join(dir, "go.sum"), err)
	}
	return pkgs, nil
}

// directMod holds metadata from a single require line in go.mod.
type directMod struct {
	indirect bool
}

func (g *GoParser) parseGoMod(path string) (map[string]directMod, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	mods := make(map[string]directMod)
	inRequire := false
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Detect block require ( ... )
		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}

		// Single-line require: `require github.com/foo/bar v1.2.3`
		var requireLine string
		if strings.HasPrefix(line, "require ") {
			requireLine = strings.TrimPrefix(line, "require ")
			inRequire = false
		} else if inRequire {
			requireLine = line
		}

		if requireLine != "" {
			// Strip trailing comment.
			commentIdx := strings.Index(requireLine, "//")
			indirect := false
			if commentIdx >= 0 {
				comment := strings.TrimSpace(requireLine[commentIdx+2:])
				indirect = comment == "indirect"
				requireLine = strings.TrimSpace(requireLine[:commentIdx])
			}
			fields := strings.Fields(requireLine)
			if len(fields) >= 1 {
				mods[fields[0]] = directMod{indirect: indirect}
			}
		}
	}
	return mods, sc.Err()
}

func (g *GoParser) parseGoSum(path string, directMods map[string]directMod) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var pkgs []Package
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Fields: <module> <version>[/go.mod] <hash>
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		module := fields[0]
		version := fields[1]

		// Skip metadata-only entries.
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}

		key := module + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		mod, known := directMods[module]
		isDirect := known && !mod.indirect
		isTransitive := !isDirect
		depth := 2
		if isDirect {
			depth = 1
		}

		pkgs = append(pkgs, Package{
			Name:            module,
			Version:         version,
			Ecosystem:       string(models.EcosystemGo),
			ResolvedVersion: version,
			IsTransitive:    isTransitive,
			Depth:           depth,
		})
	}
	return pkgs, sc.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// CargoParser
// ─────────────────────────────────────────────────────────────────────────────

// CargoParser reads Cargo.lock using a line-by-line state machine, avoiding the
// need for an external TOML library.
//
// Cargo.lock structure (v3):
//
//	[[package]]
//	name = "serde"
//	version = "1.0.163"
//	source = "registry+..."
//	checksum = "..."
//	dependencies = [
//	 "serde_derive",
//	 "serde_derive >=1.0.0, <2.0.0",
//	]
//
// The first [[package]] entry is the root crate (no source).  Direct
// dependencies are those listed in the root crate's dependencies array.
type CargoParser struct {
	log *zap.Logger
}

func (c *CargoParser) Ecosystem() string { return string(models.EcosystemCargo) }

type cargoEntry struct {
	name    string
	version string
	source  string
	deps    []string // bare names extracted from the dependencies array
}

func (c *CargoParser) Parse(dir string) ([]Package, error) {
	path := filepath.Join(dir, "Cargo.lock")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	defer f.Close()

	entries, err := c.parseEntries(f, path)
	if err != nil {
		return nil, err
	}

	return c.buildPackages(entries), nil
}

func (c *CargoParser) parseEntries(f *os.File, path string) ([]cargoEntry, error) {
	var entries []cargoEntry
	var cur *cargoEntry
	inDeps := false // inside a `dependencies = [` block

	sc := bufio.NewScanner(f)
	flush := func() {
		if cur != nil && cur.name != "" && cur.version != "" {
			entries = append(entries, *cur)
		}
		cur = nil
		inDeps = false
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		if line == "[[package]]" {
			flush()
			cur = &cargoEntry{}
			continue
		}
		if cur == nil {
			continue
		}

		if v, ok := tomlStringValue(line, "name"); ok {
			cur.name = v
			continue
		}
		if v, ok := tomlStringValue(line, "version"); ok {
			cur.version = v
			continue
		}
		if v, ok := tomlStringValue(line, "source"); ok {
			cur.source = v
			continue
		}

		// dependencies = [ ... ] (may span multiple lines)
		if line == "dependencies = [" || strings.HasPrefix(line, "dependencies = [") {
			inDeps = true
			// Handle single-line: `dependencies = []`
			if strings.HasSuffix(line, "]") {
				inDeps = false
			}
			continue
		}
		if inDeps {
			if line == "]" {
				inDeps = false
				continue
			}
			// `"serde_derive"` or `"serde_derive >=1.0.0"`
			raw := strings.Trim(line, `",`)
			// Take only the name part (before any space/operator).
			depName := strings.Fields(raw)
			if len(depName) > 0 && depName[0] != "" {
				cur.deps = append(cur.deps, depName[0])
			}
		}
	}
	flush()

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return entries, nil
}

func (c *CargoParser) buildPackages(entries []cargoEntry) []Package {
	if len(entries) == 0 {
		return nil
	}

	// The root crate(s) have no source field.
	// Collect all names that are direct deps of any root crate.
	directNames := make(map[string]bool)
	for _, e := range entries {
		if e.source == "" {
			for _, dep := range e.deps {
				directNames[dep] = true
			}
		}
	}

	// Build name → entry for parent resolution.
	byName := make(map[string]*cargoEntry, len(entries))
	for i := range entries {
		byName[entries[i].name] = &entries[i]
	}

	var out []Package
	for _, e := range entries {
		if e.source == "" {
			// Skip root crate(s) themselves.
			continue
		}
		isDirect := directNames[e.name]

		// Parents: which packages declare this in their deps array.
		var parents []string
		for _, other := range entries {
			for _, dep := range other.deps {
				if dep == e.name {
					parents = append(parents, other.name)
					break
				}
			}
		}

		out = append(out, Package{
			Name:            e.name,
			Version:         e.version,
			Ecosystem:       string(models.EcosystemCargo),
			ResolvedVersion: e.version,
			IsTransitive:    !isDirect,
			Depth:           ternary(isDirect, 1, 2),
			Parents:         parents,
		})
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// PythonParser
// ─────────────────────────────────────────────────────────────────────────────

// PythonParser handles three formats in priority order:
//  1. Pipfile.lock   (JSON, emitted by pipenv)
//  2. poetry.lock    (TOML-subset, emitted by Poetry)
//  3. requirements.txt (plain text, pinned ==version lines)
//
// If none exists, Parse returns nil.
type PythonParser struct {
	log *zap.Logger
}

func (p *PythonParser) Ecosystem() string { return string(models.EcosystemPyPI) }

func (p *PythonParser) Parse(dir string) ([]Package, error) {
	// Pipfile.lock
	if pkgs, err := p.parsePipfileLock(filepath.Join(dir, "Pipfile.lock")); err == nil {
		return pkgs, nil
	}

	// poetry.lock
	if pkgs, err := p.parsePoetryLock(filepath.Join(dir, "poetry.lock")); err == nil {
		return pkgs, nil
	}

	// requirements.txt (also handles site-packages fallback from scanner)
	if filepath.Base(dir) == "site-packages" {
		return p.parseSitePackages(dir)
	}
	return p.parseRequirements(filepath.Join(dir, "requirements.txt"))
}

// ── Pipfile.lock ──────────────────────────────────────────────────────────────

type pipfileLock struct {
	Default map[string]pipfilePkg `json:"default"`
	Develop map[string]pipfilePkg `json:"develop"`
}

type pipfilePkg struct {
	Version string   `json:"version"` // "==2.31.0"
	Hashes  []string `json:"hashes"`
}

func (p *PythonParser) parsePipfileLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock pipfileLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	seen := make(map[string]struct{})
	var out []Package

	addSection := func(section map[string]pipfilePkg, isTransitive bool) {
		for name, pkg := range section {
			ver := strings.TrimPrefix(pkg.Version, "==")
			if ver == "" {
				continue
			}
			key := name + "@" + ver
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			depth := 1
			if isTransitive {
				depth = 2
			}
			out = append(out, Package{
				Name:            name,
				Version:         ver,
				Ecosystem:       string(models.EcosystemPyPI),
				ResolvedVersion: ver,
				IsTransitive:    isTransitive,
				Depth:           depth,
			})
		}
	}

	// Pipfile.lock lists both direct and transitive in the same section — all
	// are considered "default" deps so we mark them all as direct (depth=1).
	// There is no built-in way to separate direct from transitive without
	// reading Pipfile itself; that's a future enhancement.
	addSection(lock.Default, false)
	addSection(lock.Develop, false)
	return out, nil
}

// ── poetry.lock ───────────────────────────────────────────────────────────────

// parsePoetryLock reads poetry.lock using the same state-machine approach as
// CargoParser.  The format is:
//
//	[[package]]
//	name = "requests"
//	version = "2.31.0"
//	description = "..."
//	optional = false
//	...
//
//	[package.dependencies]
//	certifi = ">=2017.4.17"
//	...
func (p *PythonParser) parsePoetryLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type poetryEntry struct {
		name    string
		version string
		deps    []string
	}

	var entries []poetryEntry
	var cur *poetryEntry
	inDeps := false

	sc := bufio.NewScanner(f)
	flush := func() {
		if cur != nil && cur.name != "" && cur.version != "" {
			entries = append(entries, *cur)
		}
		cur = nil
		inDeps = false
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		if line == "[[package]]" {
			flush()
			cur = &poetryEntry{}
			inDeps = false
			continue
		}
		if cur == nil {
			continue
		}

		if line == "[package.dependencies]" || line == "[package.dev-dependencies]" {
			inDeps = true
			continue
		}
		// Any new section header ends the deps block.
		if strings.HasPrefix(line, "[") {
			inDeps = false
			continue
		}

		if v, ok := tomlStringValue(line, "name"); ok {
			cur.name = v
			continue
		}
		if v, ok := tomlStringValue(line, "version"); ok {
			cur.version = v
			continue
		}
		if inDeps {
			// `certifi = ">=2017.4.17"` or `certifi = {version = "..."}`
			eqIdx := strings.Index(line, "=")
			if eqIdx > 0 {
				depName := strings.TrimSpace(line[:eqIdx])
				if depName != "" {
					cur.deps = append(cur.deps, depName)
				}
			}
		}
	}
	flush()

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	// Packages that have no dependents are direct; all others are transitive.
	// (This is an approximation: poetry.lock doesn't directly mark direct deps.
	// The accurate source is pyproject.toml, which we don't read here.)
	depTargets := make(map[string][]string) // name → parents
	for _, e := range entries {
		for _, dep := range e.deps {
			depTargets[dep] = append(depTargets[dep], e.name)
		}
	}

	var out []Package
	for _, e := range entries {
		parents := depTargets[e.name]
		isDirect := len(parents) == 0
		out = append(out, Package{
			Name:            e.name,
			Version:         e.version,
			Ecosystem:       string(models.EcosystemPyPI),
			ResolvedVersion: e.version,
			IsTransitive:    !isDirect,
			Depth:           ternary(isDirect, 1, 2),
			Parents:         parents,
		})
	}
	return out, nil
}

// ── requirements.txt ─────────────────────────────────────────────────────────

func (p *PythonParser) parseRequirements(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	defer f.Close()

	var out []Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "-") || strings.Contains(line, "://") {
			continue
		}
		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		ver := strings.TrimSpace(parts[1])
		if name == "" || ver == "" {
			continue
		}
		out = append(out, Package{
			Name:            name,
			Version:         ver,
			Ecosystem:       string(models.EcosystemPyPI),
			ResolvedVersion: ver,
			IsTransitive:    false,
			Depth:           1,
		})
	}
	return out, sc.Err()
}

// ── site-packages fallback ────────────────────────────────────────────────────

func (p *PythonParser) parseSitePackages(dir string) ([]Package, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", dir, err)
	}
	var out []Package
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasSuffix(entry.Name(), ".dist-info") {
			continue
		}
		metaPath := filepath.Join(dir, entry.Name(), "METADATA")
		pkg, ok := p.readDistMetadata(metaPath, dir)
		if ok {
			out = append(out, pkg)
		}
	}
	return out, nil
}

func (p *PythonParser) readDistMetadata(path, siteDir string) (Package, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Package{}, false
	}
	defer f.Close()

	var name, ver string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Name: ") {
			name = strings.TrimPrefix(line, "Name: ")
		} else if strings.HasPrefix(line, "Version: ") {
			ver = strings.TrimPrefix(line, "Version: ")
		}
		if name != "" && ver != "" {
			break
		}
		if line == "" {
			break // end of headers
		}
	}
	if name == "" || ver == "" {
		return Package{}, false
	}
	return Package{
		Name:            name,
		Version:         ver,
		Ecosystem:       string(models.EcosystemPyPI),
		ResolvedVersion: ver,
		Depth:           1,
	}, true
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

// tomlStringValue parses a line like `key = "value"` and returns the value.
func tomlStringValue(line, key string) (string, bool) {
	prefix := key + ` = "`
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := line[len(prefix):]
	idx := strings.Index(rest, `"`)
	if idx < 0 {
		return "", false
	}
	return rest[:idx], true
}

// unquote removes surrounding double or single quotes from a string.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// coalesce returns the first non-empty string.
func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ternary returns a if cond, else b.
func ternary(cond bool, a, b int) int {
	if cond {
		return a
	}
	return b
}

// yarnSpecName extracts the bare package name from a Yarn specifier like
// "express@^4.18.2" or "@types/node@npm:^20.0.0".
func yarnSpecName(spec string) string {
	spec = strings.Trim(spec, `"`)
	// Scoped packages start with @: find the second @.
	if strings.HasPrefix(spec, "@") {
		idx := strings.Index(spec[1:], "@")
		if idx >= 0 {
			return spec[:idx+1]
		}
		return spec
	}
	// Regular: take everything before the first @.
	idx := strings.Index(spec, "@")
	if idx < 0 {
		return spec
	}
	return spec[:idx]
}

// berrySpecName extracts the package name from a Yarn Berry entry key like
// `"express@npm:^4.18.2"` or `"@types/node@npm:^20.0.0"`.
func berrySpecName(spec string) string {
	// Strip the npm: or patch: protocol suffix.
	// Format: name@registry:version
	// Scoped: @scope/name@registry:version
	if strings.HasPrefix(spec, "@") {
		// @types/node@npm:^20.0.0 → find the @npm: part
		idx := strings.Index(spec[1:], "@")
		if idx >= 0 {
			return spec[:idx+1]
		}
		return spec
	}
	idx := strings.Index(spec, "@")
	if idx < 0 {
		return spec
	}
	return spec[:idx]
}

// findYarnParents returns the names of all yarn classic entries that list
// `name` in their deps slice.
func findYarnParents(name string, entries []yarnEntry) []string {
	var parents []string
	for _, e := range entries {
		for _, dep := range e.deps {
			if dep == name {
				parents = append(parents, e.name)
				break
			}
		}
	}
	return parents
}

// yarnDepth returns 1 if the package is a direct dependency, 2 otherwise.
// Full BFS depth traversal is left as a future enhancement.
func yarnDepth(name string, directNames map[string]bool) int {
	if directNames[name] {
		return 1
	}
	return 2
}
