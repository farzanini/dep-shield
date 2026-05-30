// Package root wires up the cobra command tree.
// Each sub-command lives in its own file in this package.
package root

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd is the top-level command: `dep-shield`.
// Sub-commands are added to it in their own init() functions.
var rootCmd = &cobra.Command{
	Use:   "dep-shield",
	Short: "Scan your system for vulnerable dependencies",
	Long: `dep-shield walks your filesystem, discovers installed packages across
npm, Go modules, Cargo (Rust), and Python (pip), queries OSV.dev and the
GitHub Advisory Database, then prints a sorted vulnerability report.

Set GITHUB_TOKEN to also query the GitHub Advisory Database for richer results.`,
}

// Execute is called by main. It runs the selected command.
func Execute() error {
	// cobra prints its own error message before returning, so we just need
	// to forward the error up to main for the exit-code decision.
	return rootCmd.Execute()
}

// init runs once when the package is loaded. We configure global flags here.
func init() {
	// PersistentFlags are inherited by all sub-commands.
	rootCmd.PersistentFlags().Bool("no-colour", false, "disable ANSI colour in output")
	rootCmd.PersistentFlags().Bool("debug", false, "enable verbose debug logging")

	// Add sub-commands.
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(versionCmd())
}

// fatalf prints a formatted error to stderr and exits. Used inside Run functions
// where we can't propagate an error back through cobra (Run has no error return).
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
