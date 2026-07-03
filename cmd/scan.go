package cmd

// scanCmd wires up the "dep-shield scan" sub-command.
//
// Responsibility chain:
//
//	scan flags  →  scanner.Walker  →  parser.Parser  →  cve.Client
//	           →  scorer.Scorer   →  reporter.Reporter
//
// Each of those steps is a separate internal package so they can be tested and
// swapped independently.  This file only owns the CLI layer: flag parsing,
// progress feedback, and calling the pipeline in order.

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/farzanini/dep-shield/internal/models"
	"github.com/farzanini/dep-shield/internal/pipeline"
	"github.com/farzanini/dep-shield/internal/reporter"
)

// scanFlags holds all flags specific to the scan sub-command.
// Keeping them in a struct (rather than scattered package-level vars) makes
// table-driven tests straightforward: create a scanFlags{}, set fields, call
// runScan().
type scanFlags struct {
	// Paths is the list of root directories to scan.
	// Defaults to the user's home directory when empty.
	Paths []string

	// Ecosystems restricts the scan to the named ecosystems.
	// Empty means "all supported ecosystems".
	// Valid values: npm, go, cargo, pip
	Ecosystems []string

	// MinSeverity is the lowest severity that should appear in the report.
	// Findings below this threshold are silently dropped.
	// Valid values: LOW | MEDIUM | HIGH | CRITICAL
	MinSeverity string

	// Workers is the number of goroutines used for concurrent CVE queries.
	// Defaults to 2× the number of logical CPUs.
	Workers int

	// Timeout is the maximum wall-clock duration for the entire scan.
	// A scan that exceeds this duration is cancelled and the partial
	// results are reported.
	Timeout time.Duration

	// JSONOut, when non-empty, writes the raw ScanResult as indented JSON
	// to that file path in addition to the normal terminal output.
	JSONOut string

	// HTMLOut, when non-empty, writes an HTML report to that file path.
	HTMLOut string

	// OfflineMode skips all network requests and uses only locally cached
	// advisory data (if any).  Useful on air-gapped systems.
	OfflineMode bool

	// System also scans the host's system package managers (dpkg/apt, apk,
	// Homebrew). When set without any paths, only the system managers are
	// scanned (the filesystem walk is skipped).
	System bool
}

// scanCmd constructs and returns the cobra.Command for "dep-shield scan".
// It is called once from root.go's init() and must not be called again.
func scanCmd() *cobra.Command {
	sf := scanFlags{
		MinSeverity: "LOW",
		Workers:     runtime.NumCPU() * 2,
		Timeout:     30 * time.Minute,
	}

	cmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan directories for vulnerable dependencies",
		Long: `scan walks every supplied path (default: $HOME) looking for
dependency manifests (node_modules, go.sum, Cargo.lock, site-packages,
requirements.txt).  For every package it finds it queries OSV.dev and,
when GITHUB_TOKEN is set, the GitHub Advisory Database.

Examples:
  dep-shield scan                       # scan $HOME
  dep-shield scan /srv/app ~/projects   # scan specific directories
  dep-shield scan --min-severity HIGH   # only show HIGH and CRITICAL
  dep-shield scan --json out.json       # also write a JSON report
  dep-shield scan --ecosystem npm,go    # only npm and Go packages`,

		// Args validates positional arguments before RunE is called.
		Args: cobra.ArbitraryArgs,

		// RunE is preferred over Run because it can return an error; cobra
		// prints the error and sets exit code 1 automatically.
		RunE: func(cmd *cobra.Command, args []string) error {
			// Positional args are the paths to scan.
			if len(args) > 0 {
				sf.Paths = args
			}
			return runScan(cmd.Context(), sf)
		},
	}

	f := cmd.Flags()
	f.StringSliceVar(&sf.Ecosystems, "ecosystem", nil,
		"restrict scan to these ecosystems (comma-separated: npm,go,cargo,pip)")
	f.StringVar(&sf.MinSeverity, "min-severity", sf.MinSeverity,
		"minimum severity to include: LOW | MEDIUM | HIGH | CRITICAL")
	f.IntVar(&sf.Workers, "workers", sf.Workers,
		"number of concurrent CVE query goroutines")
	f.DurationVar(&sf.Timeout, "timeout", sf.Timeout,
		"maximum duration for the entire scan")
	f.StringVar(&sf.JSONOut, "json", "",
		"also write a JSON report to this file")
	f.StringVar(&sf.HTMLOut, "html", "",
		"also write an HTML report to this file")
	f.BoolVar(&sf.OfflineMode, "offline", false,
		"skip network requests; use only cached advisory data")
	f.BoolVar(&sf.System, "system", false,
		"also scan system package managers (dpkg/apt, apk, Homebrew); "+
			"with no paths, scans only those")

	return cmd
}

// runScan executes the full scan pipeline.
// Separating the business logic from the cobra wiring makes runScan unit-testable
// without constructing a cobra.Command.
func runScan(ctx context.Context, sf scanFlags) error {
	// Apply the timeout to the context so every downstream operation respects it.
	ctx, cancel := context.WithTimeout(ctx, sf.Timeout)
	defer cancel()

	log := Log
	if log == nil {
		log = zap.NewNop()
	}

	// ── 1. Resolve scan roots ─────────────────────────────────────────────────
	// A filesystem scan runs unless --system was given with no explicit paths,
	// in which case only the system package managers are scanned.
	paths := sf.Paths
	scanFS := len(paths) > 0 || !sf.System
	if scanFS && len(paths) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolving home directory: %w", err)
		}
		paths = []string{home}
	}
	log.Info("starting scan", zap.Strings("paths", paths), zap.Bool("system", sf.System))

	// ── 2. Run the scan pipeline ──────────────────────────────────────────────
	result, err := pipeline.Run(ctx, pipeline.Options{
		Roots:       paths,
		Ecosystems:  sf.Ecosystems,
		System:      sf.System,
		MinSeverity: models.Severity(sf.MinSeverity),
		Offline:     sf.OfflineMode,
		Workers:     sf.Workers,
		Log:         log,
	})
	if err != nil {
		return err
	}
	if result.TotalPackages == 0 {
		return fmt.Errorf("no packages found to scan")
	}

	// ── 3. Render output ──────────────────────────────────────────────────────
	rep := reporter.New(reporter.Options{
		NoColour: flags.NoColour,
		Format:   flags.Output,
		Log:      log,
	})

	// Always write to stdout.
	// TODO: replace stub call with real rep.WriteTable / rep.WriteJSON
	if err := rep.Write(os.Stdout, result); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	// Optional JSON file.
	if sf.JSONOut != "" {
		// TODO: replace stub call with real rep.WriteJSONFile(sf.JSONOut, result)
		if err := rep.WriteFile(sf.JSONOut, reporter.FormatJSON, result); err != nil {
			return fmt.Errorf("writing JSON file: %w", err)
		}
	}

	// Optional HTML file.
	if sf.HTMLOut != "" {
		// TODO: replace stub call with real rep.WriteHTMLFile(sf.HTMLOut, result)
		if err := rep.WriteFile(sf.HTMLOut, reporter.FormatHTML, result); err != nil {
			return fmt.Errorf("writing HTML file: %w", err)
		}
	}

	// Exit code 2 signals "scan succeeded but vulnerabilities were found".
	// This lets CI pipelines distinguish a tool error (exit 1) from a finding
	// (exit 2) so they can fail the build only on genuine CVEs.
	if len(result.Vulnerabilities) > 0 {
		os.Exit(2)
	}
	return nil
}
