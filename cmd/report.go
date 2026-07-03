package cmd

// reportCmd wires up the "dep-shield report" sub-command.
//
// Unlike "scan" (which discovers packages AND fetches CVEs in one pass),
// "report" works on an existing JSON scan result that was produced by a
// previous "scan --json" run.  This lets users:
//
//   - Run the expensive CVE queries once (e.g. nightly in CI).
//   - Re-render the report in different formats without re-querying.
//   - Filter a saved result by severity / ecosystem without re-scanning.

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/farzanini/dep-shield/internal/models"
	"github.com/farzanini/dep-shield/internal/reporter"
	"github.com/farzanini/dep-shield/internal/scorer"
)

// reportFlags holds all flags specific to the report sub-command.
type reportFlags struct {
	// InputFile is the path to a JSON scan result produced by "scan --json".
	InputFile string

	// MinSeverity filters out findings below this severity level.
	MinSeverity string

	// Ecosystem, when set, limits the output to one ecosystem.
	Ecosystem string

	// OutFile writes the rendered report to a file instead of stdout.
	OutFile string

	// Format overrides the global --output flag for this invocation.
	// Allows "dep-shield report --format html -o report.html" without
	// also changing the global default for subsequent commands.
	Format string
}

// reportCmd constructs and returns the cobra.Command for "dep-shield report".
func reportCmd() *cobra.Command {
	rf := reportFlags{
		MinSeverity: "LOW",
		Format:      "table",
	}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Re-render a saved scan result in a different format",
		Long: `report reads a JSON file produced by "dep-shield scan --json" and
renders it to stdout (or --out) in the chosen format.

This is useful when you want to:
  • Re-run filtering (e.g. only show CRITICAL) without hitting CVE APIs again.
  • Convert a JSON result to HTML for a stakeholder report.
  • Diff two scan results across releases.

Examples:
  dep-shield report --input scan.json
  dep-shield report --input scan.json --min-severity HIGH --format html -o report.html
  dep-shield report --input scan.json --ecosystem npm`,

		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(rf)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&rf.InputFile, "input", "i", "",
		"path to JSON scan result (required)")
	f.StringVar(&rf.MinSeverity, "min-severity", rf.MinSeverity,
		"minimum severity: LOW | MEDIUM | HIGH | CRITICAL")
	f.StringVar(&rf.Ecosystem, "ecosystem", "",
		"filter to a single ecosystem: npm | go | cargo | pip")
	f.StringVarP(&rf.OutFile, "out", "o", "",
		"write report to file instead of stdout")
	f.StringVar(&rf.Format, "format", rf.Format,
		`output format: "table" | "json" | "html"`)

	// Mark --input as required so cobra prints a clear error when it is missing.
	_ = cmd.MarkFlagRequired("input")

	return cmd
}

// runReport executes the report pipeline on a pre-existing scan result.
func runReport(rf reportFlags) error {
	log := Log
	if log == nil {
		log = zap.NewNop()
	}

	// ── 1. Load saved result ──────────────────────────────────────────────────
	// TODO: replace stub with real loader that opens rf.InputFile, unmarshals JSON
	result, err := loadScanResult(rf.InputFile)
	if err != nil {
		return fmt.Errorf("loading %s: %w", rf.InputFile, err)
	}
	log.Info("loaded scan result",
		zap.String("file", rf.InputFile),
		zap.Int("vulnerabilities", len(result.Vulnerabilities)),
	)

	// ── 2. Re-score / filter ──────────────────────────────────────────────────
	// TODO: replace stub with real scorer.Filter(result, rf.MinSeverity, rf.Ecosystem)
	sc := scorer.New(log)
	result, err = sc.Score(result.Vulnerabilities, models.Severity(rf.MinSeverity))
	if err != nil {
		return fmt.Errorf("scoring: %w", err)
	}

	// ── 3. Render ─────────────────────────────────────────────────────────────
	rep := reporter.New(reporter.Options{
		NoColour: flags.NoColour,
		Format:   rf.Format,
		Log:      log,
	})

	out := os.Stdout
	if rf.OutFile != "" {
		f, err := os.Create(rf.OutFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	// TODO: replace stub with real rep.Write(out, result)
	if err := rep.Write(out, result); err != nil {
		return fmt.Errorf("rendering report: %w", err)
	}
	return nil
}

// loadScanResult deserialises a JSON scan result from disk.
// TODO: implement — open file, json.NewDecoder(f).Decode(&result)
func loadScanResult(path string) (models.ScanResult, error) {
	_ = path
	// TODO: open path, decode JSON into models.ScanResult, return it
	return models.ScanResult{}, fmt.Errorf("TODO: loadScanResult not implemented")
}
