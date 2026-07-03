// Package cmd contains every cobra command for dep-shield.
//
// File layout:
//
//	root.go   — root command, global flags, shared helpers
//	scan.go   — "dep-shield scan"   sub-command
//	report.go — "dep-shield report" sub-command
//
// Why cobra?
// Cobra is the de-facto CLI framework in Go. It handles flag parsing,
// sub-command dispatch, --help generation, and shell-completion scripts
// automatically. The alternative (stdlib flag package) does not support
// sub-commands, so we would have to write that plumbing ourselves.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// ── Build-time version injection ────────────────────────────────────────────

// Version is set at build time via -ldflags:
//
//	-X github.com/dep-shield/dep-shield/cmd.Version=v0.1.0
//
// It defaults to "dev" so local builds always have an identifiable label.
var Version = "dev"

// ── Package-level logger ─────────────────────────────────────────────────────

// Log is the application-wide structured logger.  It is initialised inside
// PersistentPreRunE (after flags are parsed) and shared by all sub-commands.
// Using a package-level variable here is idiomatic for CLI tools; libraries
// should instead accept a *zap.Logger as a constructor argument.
var Log *zap.Logger

// ── Global flag bag ───────────────────────────────────────────────────────────

// flags holds values bound to the PersistentFlags defined on rootCmd.
// Grouping them in a struct instead of scattered var declarations makes it easy
// to see at a glance what state the root command owns.
var flags struct {
	// Debug switches the logger to development mode: DEBUG level, coloured
	// console output, stack traces on warnings and above.
	Debug bool

	// NoColour disables all ANSI escape codes in terminal output.
	// Useful in CI environments that do not support colour (e.g. some Jenkins
	// pipelines, Windows cmd.exe without VT mode).
	NoColour bool

	// Output selects the report format.
	// Accepted values: "table" | "json" | "html"
	Output string
}

// ── Root command ──────────────────────────────────────────────────────────────

var rootCmd = &cobra.Command{
	Use:   "dep-shield",
	Short: "Scan your system for vulnerable dependencies",
	Long: `dep-shield discovers every installed package across npm, Go modules,
Cargo (Rust), and Python (pip / site-packages), queries OSV.dev and the GitHub
Advisory Database for known CVEs, scores each finding by risk, and produces
a sorted vulnerability report in your choice of format.

Environment variables:
  GITHUB_TOKEN   Personal access token for GitHub Advisory queries.
                 Without this, only OSV.dev (no auth required) is queried.

Exit codes:
  0   No vulnerabilities found at or above --min-severity.
  1   Tool error (bad flags, I/O failure, API error).
  2   One or more vulnerabilities found.`,

	// PersistentPreRunE runs before every sub-command.
	// By the time it runs, cobra has already parsed all flags, so it is the
	// correct place to initialise the logger.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initLogger(flags.Debug)
	},
}

// Execute is the single public symbol in this package.
// main() calls it; it parses os.Args and dispatches to the right sub-command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	pf := rootCmd.PersistentFlags()

	pf.BoolVar(&flags.Debug, "debug", false,
		"enable debug logging (very verbose, shows every file visited)")

	pf.BoolVar(&flags.NoColour, "no-colour", false,
		"disable ANSI colour in terminal output")

	pf.StringVar(&flags.Output, "output", "table",
		`report format: "table" (default) | "json" | "html"`)

	// Sub-commands registered here are visible in --help and shell completion.
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(reportCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(mcpCmd())
}

// ── Version sub-command ───────────────────────────────────────────────────────

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print dep-shield version and exit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stdout, "dep-shield %s\n", Version)
		},
	}
}

// ── Logger initialisation ─────────────────────────────────────────────────────

// initLogger constructs a *zap.Logger and stores it in the package-level Log.
// zap has two pre-built configurations:
//
//   - NewDevelopment: human-readable, coloured, DEBUG level — for local work.
//   - NewProduction:  JSON lines, INFO level, no colour — for CI / servers.
func initLogger(debug bool) error {
	var (
		logger *zap.Logger
		err    error
	)
	if debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		return fmt.Errorf("building logger: %w", err)
	}
	Log = logger
	return nil
}

// ── Shared helpers ────────────────────────────────────────────────────────────

// die writes a formatted error to stderr and exits with code 1.
// Use only inside cobra Run functions, which cannot return errors.
// Prefer RunE (which can return an error) wherever possible.
func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "dep-shield: "+format+"\n", args...)
	os.Exit(1)
}
