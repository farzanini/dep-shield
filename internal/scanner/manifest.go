package scanner

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/farzanini/dep-shield/internal/models"
)

// ── Manifest-based hit discovery ──────────────────────────────────────────────
//
// The store-based walk in this package only matches installed dependency
// directories (node_modules, vendor, .venv, site-packages). ManifestHits
// complements it by finding committed manifest/lockfiles, so a checkout with no
// installed dependencies (e.g. a freshly cloned repo) still produces hits the
// parser layer can consume.

// manifestFiles maps a manifest/lockfile name to the ecosystem it identifies.
// These are the committed files present in a checked-out repo even when no
// packages are installed.
var manifestFiles = map[string]models.Ecosystem{
	"package-lock.json": models.EcosystemNPM,
	"yarn.lock":         models.EcosystemNPM,
	"pnpm-lock.yaml":    models.EcosystemNPM,
	"go.mod":            models.EcosystemGo,
	"Cargo.lock":        models.EcosystemCargo,
	"Pipfile.lock":      models.EcosystemPyPI,
	"poetry.lock":       models.EcosystemPyPI,
	"requirements.txt":  models.EcosystemPyPI,
}

// ManifestHits walks root (bounded by maxDepth) looking for directories that
// contain a committed manifest/lockfile, and returns DirHits using the Path
// convention each parser expects:
//
//   - npm: the parser reads the lockfile from the hit's PARENT directory, so
//     the hit points at <projectDir>/node_modules (which need not exist).
//   - Go/Cargo/PyPI: the parser reads the manifest from the hit directory
//     itself, so the hit points at <projectDir>.
//
// The walk aborts promptly when ctx is cancelled.
func ManifestHits(ctx context.Context, root string, maxDepth int) []DirHit {
	var hits []DirHit
	seen := map[string]bool{} // dedupe: one npm hit per project dir

	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			// Prune noise and installed-store subtrees — the store-based walk
			// already covers those, and they'd be slow to descend.
			if path != root && (name == ".git" || name == "node_modules" ||
				name == "vendor" || name == ".venv" || name == "site-packages" ||
				name == "__pycache__" || name == "dist" || name == "build") {
				return fs.SkipDir
			}
			if maxDepth > 0 {
				if rel, rErr := filepath.Rel(root, path); rErr == nil {
					depth := strings.Count(rel, string(filepath.Separator))
					if rel != "." && depth >= maxDepth {
						return fs.SkipDir
					}
				}
			}
			return nil
		}

		eco, ok := manifestFiles[d.Name()]
		if !ok {
			return nil
		}
		dir := filepath.Dir(path)
		if eco == models.EcosystemNPM {
			if seen[dir] {
				return nil
			}
			seen[dir] = true
			hits = append(hits, DirHit{
				Path:      filepath.Join(dir, "node_modules"),
				Ecosystem: eco,
			})
			return nil
		}
		hits = append(hits, DirHit{Path: dir, Ecosystem: eco})
		return nil
	})

	return hits
}

// MergeHits appends extra hits to base, dropping any that duplicate an existing
// (Ecosystem, Path) pair.
func MergeHits(base, extra []DirHit) []DirHit {
	seen := make(map[string]bool, len(base))
	key := func(h DirHit) string { return string(h.Ecosystem) + "\x00" + h.Path }
	for _, h := range base {
		seen[key(h)] = true
	}
	for _, h := range extra {
		if k := key(h); !seen[k] {
			seen[k] = true
			base = append(base, h)
		}
	}
	return base
}
