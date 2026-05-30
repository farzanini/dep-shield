//go:build !wails

// dep-shield: single-binary vulnerability scanner for system dependencies.
//
// Build a fully static binary (no C runtime, no shared libraries):
//
//	CGO_ENABLED=0 go build \
//	  -ldflags="-s -w -X github.com/dep-shield/dep-shield/cmd.Version=v0.1.0" \
//	  -o dep-shield .
//
// The -s -w flags strip the symbol table and DWARF debug info, shrinking the
// binary by ~30 %.  The -X flag injects the version string at link time so we
// never hard-code it in source.
package main

import (
	"os"

	"github.com/dep-shield/dep-shield/cmd"
)

func main() {
	// cmd.Execute() runs the selected cobra sub-command and returns any error.
	// Cobra already prints the error message before returning, so here we only
	// set the exit code.
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
