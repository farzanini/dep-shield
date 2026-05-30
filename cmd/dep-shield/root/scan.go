package root

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/advisory"
	"github.com/dep-shield/dep-shield/internal/models"
	"github.com/dep-shield/dep-shield/internal/parser"
	"github.com/dep-shield/dep-shield/internal/report"
	"github.com/dep-shield/dep-shield/internal/scanner"
)

// scanCmd builds and returns the `scan` sub-command.
// Returning a *cobra.Command (instead of using a package-level var) keeps all
// flag definitions co-located with the command they belong to.
func scanCmd() *cobra.Command {
	var (
		paths    []string
		jsonOut  string
		minSev   string
		workers  int
	)

	cmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Scan one or more directories for vulnerable dependencies",
		Example: `  dep-shield scan                    # scan your home directory
  dep-shield scan /srv/app ~/projects  # scan specific directories
  dep-shield scan --json report.json   # also write a JSON report`,
		// RunE lets us return an error; cobra prints it and sets exit code 1.
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no paths given, default to the user's home directory.
			if len(args) > 0 {
				paths = args
			}
			if len(paths) == 0 {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("cannot determine home directory: %w", err)
				}
				paths = []string{home}
			}

			noColour, _ := cmd.Flags().GetBool("no-colour")
			debug, _ := cmd.Flags().GetBool("debug")

			log := buildLogger(debug)
			defer log.Sync() //nolint:errcheck

			log.Info("starting scan", zap.Strings("paths", paths))

			// --- Phase 1: discover packages ---
			// Use the new Walker-based API: Walk returns DirHit values;
			// for now we have no parser yet so we log the hit count only.
			w := scanner.New(scanner.Options{Roots: paths, Log: log})
			hits, err := w.Walk(context.Background())
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
			log.Info("discovery complete", zap.Int("directories", len(hits)))

			// --- Phase 1b: parse lockfiles / manifests ---
			dispatcher := parser.New(log)
			parsed, err := dispatcher.ParseAll(context.Background(), hits)
			if err != nil {
				return fmt.Errorf("parsing failed: %w", err)
			}
			log.Info("parsing complete", zap.Int("packages", len(parsed)))
			pkgs := parser.ToModels(parsed)

			// --- Phase 2: query advisories ---
			client := advisory.New()
			_ = workers // workers flag reserved for future rate-limiting
			vulns, err := client.QueryAll(context.Background(), pkgs)
			if err != nil {
				return fmt.Errorf("advisory query failed: %w", err)
			}
			log.Info("advisory query complete", zap.Int("vulnerabilities", len(vulns)))

			// --- Phase 3: filter by minimum severity ---
			vulns = filterBySeverity(vulns, minSev)

			result := models.ScanResult{
				ScannedPaths:    paths,
				TotalPackages:   len(pkgs),
				Vulnerabilities: vulns,
			}

			// --- Phase 4: output ---
			report.PrintTable(os.Stdout, result, noColour)
			report.PrintSummary(os.Stdout, result)

			if jsonOut != "" {
				if err := report.WriteJSON(jsonOut, result); err != nil {
					return fmt.Errorf("writing JSON report: %w", err)
				}
				fmt.Fprintf(os.Stdout, "JSON report written to %s\n", jsonOut)
			}

			// Exit 2 when vulnerabilities are found so CI pipelines can detect it.
			if len(vulns) > 0 {
				os.Exit(2)
			}
			return nil
		},
	}

	defaultWorkers := runtime.NumCPU() * 2
	cmd.Flags().StringVar(&jsonOut, "json", "", "write JSON report to this file path")
	cmd.Flags().StringVar(&minSev, "min-severity", "LOW", "minimum severity to report (LOW|MEDIUM|HIGH|CRITICAL)")
	cmd.Flags().IntVar(&workers, "workers", defaultWorkers, "number of concurrent advisory queries")

	return cmd
}

// buildLogger returns a production zap logger in normal mode,
// or a development logger (with DEBUG level and coloured output) in debug mode.
func buildLogger(debug bool) *zap.Logger {
	if debug {
		log, _ := zap.NewDevelopment()
		return log
	}
	log, _ := zap.NewProduction()
	return log
}

// filterBySeverity returns only vulnerabilities at or above minSev.
func filterBySeverity(vulns []models.Vulnerability, minSev string) []models.Vulnerability {
	minRank := models.SeverityRank(models.Severity(minSev))
	out := vulns[:0]
	for _, v := range vulns {
		if models.SeverityRank(v.Severity) >= minRank {
			out = append(out, v)
		}
	}
	return out
}
