// Package pipeline runs the full dep-shield scan as a single reusable call:
// discover packages (from the filesystem and/or system package managers), query
// the CVE databases, and score the findings. It is the shared core behind the
// CLI, and the MCP server; the Wails GUI runs the same stages inline so it can
// stream progress events.
package pipeline

import (
	"context"
	"fmt"
	"runtime"

	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/cve"
	"github.com/dep-shield/dep-shield/internal/models"
	"github.com/dep-shield/dep-shield/internal/parser"
	"github.com/dep-shield/dep-shield/internal/scanner"
	"github.com/dep-shield/dep-shield/internal/scorer"
	"github.com/dep-shield/dep-shield/internal/syspkg"
)

// Options configures a scan run.
type Options struct {
	// Roots are the directories to scan. When empty and System is false, the
	// caller should default this to the home directory before calling Run.
	Roots []string

	// Ecosystems restricts the filesystem scan to these ecosystems. Empty = all.
	Ecosystems []string

	// System also enumerates the host's system package managers (dpkg/apt, apk,
	// Homebrew) and includes those packages in the scan.
	System bool

	// MinSeverity filters findings below this level out of the result.
	MinSeverity models.Severity

	// Offline skips all network requests (no CVE data is fetched).
	Offline bool

	// Workers bounds concurrent CVE requests. 0 defaults to runtime.NumCPU()*2.
	Workers int

	// ManifestDepth bounds how deep ManifestHits walks for committed lockfiles.
	// 0 defaults to 8.
	ManifestDepth int

	// Log is the structured logger. nil uses a no-op logger.
	Log *zap.Logger
}

// Run executes the scan and returns the scored result. The result's
// TotalPackages is the number of distinct packages discovered, and
// ScannedPaths echoes Roots.
func Run(ctx context.Context, opts Options) (models.ScanResult, error) {
	log := opts.Log
	if log == nil {
		log = zap.NewNop()
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	manifestDepth := opts.ManifestDepth
	if manifestDepth <= 0 {
		manifestDepth = 8
	}

	// ── Discover packages ─────────────────────────────────────────────────────
	var modelPkgs []models.Package

	if len(opts.Roots) > 0 {
		// Store-based walk (installed node_modules/vendor/.venv/site-packages)…
		w := scanner.New(scanner.Options{
			Roots:      opts.Roots,
			Ecosystems: opts.Ecosystems,
			SkipGlobal: true, // an explicit-path scan shouldn't pull in global caches
			Log:        log,
		})
		hits, err := w.Walk(ctx)
		if err != nil {
			return models.ScanResult{}, fmt.Errorf("filesystem walk: %w", err)
		}
		// …plus committed manifests, so checkouts without installed deps are found.
		for _, root := range opts.Roots {
			hits = scanner.MergeHits(hits, scanner.ManifestHits(ctx, root, manifestDepth))
		}

		pkgs, err := parser.New(log).ParseAll(ctx, hits)
		if err != nil {
			return models.ScanResult{}, fmt.Errorf("parsing packages: %w", err)
		}
		modelPkgs = parser.ToModels(pkgs)
	}

	if opts.System {
		for _, c := range syspkg.Detect(log) {
			got, err := c.Collect(ctx)
			if err != nil {
				log.Warn("system collector failed",
					zap.String("manager", c.Name()), zap.Error(err))
				continue
			}
			modelPkgs = append(modelPkgs, got...)
		}
	}

	if len(modelPkgs) == 0 {
		// Nothing to scan is not an error — return an empty, well-formed result.
		return models.ScanResult{ScannedPaths: opts.Roots}, nil
	}

	// ── Query CVE databases ───────────────────────────────────────────────────
	vulns, err := cve.NewClient(cve.Options{
		Offline: opts.Offline,
		Workers: workers,
		Log:     log,
	}).QueryAll(ctx, modelPkgs)
	if err != nil {
		return models.ScanResult{}, fmt.Errorf("CVE query: %w", err)
	}

	// ── Score, sort, filter ───────────────────────────────────────────────────
	result, err := scorer.New(log).Score(vulns, opts.MinSeverity)
	if err != nil {
		return models.ScanResult{}, fmt.Errorf("scoring: %w", err)
	}
	result.ScannedPaths = opts.Roots
	result.TotalPackages = len(modelPkgs)
	return result, nil
}
