package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/models"
)

// npmScanner finds packages inside node_modules directories by reading the
// package.json file that lives at <node_modules>/<pkg>/package.json.
type npmScanner struct {
	log *zap.Logger
}

func (n *npmScanner) Name() string { return "npm" }

// Recognises returns true when dir is literally named "node_modules".
// We match on the base name so we don't need to stat any extra files.
func (n *npmScanner) Recognises(dir string) bool {
	return filepath.Base(dir) == "node_modules"
}

// packageJSON is the subset of package.json fields we care about.
// json struct tags map JSON keys → Go field names; omitempty is irrelevant
// for unmarshalling (it only affects marshalling) but is harmless.
type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Extract walks one level inside node_modules and reads each sub-package's
// package.json. Scoped packages (e.g. @scope/pkg) live one extra level deep.
func (n *npmScanner) Extract(ctx context.Context, dir string) ([]models.Package, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var pkgs []models.Package
	for _, e := range entries {
		if ctx.Err() != nil {
			return pkgs, ctx.Err()
		}
		if !e.IsDir() {
			continue
		}
		name := e.Name()

		// Scoped packages: "@scope" directories contain the real packages.
		if strings.HasPrefix(name, "@") {
			scopeDir := filepath.Join(dir, name)
			scoped, err := n.readScopedDir(ctx, scopeDir, name)
			if err != nil {
				n.log.Warn("skipping scoped dir", zap.String("dir", scopeDir), zap.Error(err))
				continue
			}
			pkgs = append(pkgs, scoped...)
			continue
		}

		pkg, ok := n.readPackageJSON(filepath.Join(dir, name, "package.json"), dir)
		if ok {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs, nil
}

// readScopedDir reads all packages inside an @scope directory.
func (n *npmScanner) readScopedDir(ctx context.Context, scopeDir, scope string) ([]models.Package, error) {
	entries, err := os.ReadDir(scopeDir)
	if err != nil {
		return nil, err
	}
	var pkgs []models.Package
	for _, e := range entries {
		if ctx.Err() != nil {
			return pkgs, ctx.Err()
		}
		if !e.IsDir() {
			continue
		}
		jsonPath := filepath.Join(scopeDir, e.Name(), "package.json")
		if pkg, ok := n.readPackageJSON(jsonPath, filepath.Dir(scopeDir)); ok {
			// Ensure the name includes the scope prefix when package.json omits it.
			if !strings.HasPrefix(pkg.Name, scope) {
				pkg.Name = scope + "/" + e.Name()
			}
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs, nil
}

// readPackageJSON parses a single package.json file and returns a Package.
// The second return value is false when the file is missing or unparseable.
func (n *npmScanner) readPackageJSON(jsonPath, nodeModulesDir string) (models.Package, bool) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return models.Package{}, false
	}
	var pj packageJSON
	if err := json.Unmarshal(data, &pj); err != nil || pj.Name == "" {
		return models.Package{}, false
	}
	return models.Package{
		Name:      pj.Name,
		Version:   pj.Version,
		Ecosystem: models.EcosystemNPM,
		Path:      nodeModulesDir,
	}, true
}
