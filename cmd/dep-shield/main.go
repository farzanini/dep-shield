// dep-shield: scan your system for vulnerable dependencies.
//
// Build a single static binary with:
//
//	CGO_ENABLED=0 go build -ldflags="-s -w" -o dep-shield ./cmd/dep-shield
package main

import (
	"os"

	"github.com/dep-shield/dep-shield/cmd/dep-shield/root"
)

func main() {
	// Execute is the cobra entry point. It parses flags, selects the right
	// sub-command, and calls its Run function. If anything goes wrong it
	// prints the error and exits with code 1.
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
