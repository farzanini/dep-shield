package root

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags="-X .../root.version=v1.2.3".
// The default value is used during development builds.
var version = "dev"

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the dep-shield version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("dep-shield %s\n", version)
		},
	}
}
