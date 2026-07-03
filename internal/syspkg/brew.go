package syspkg

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/models"
)

// brewCollector enumerates Homebrew formulae. OSV has no Homebrew ecosystem, so
// these packages carry models.EcosystemHomebrew and are matched against NVD by
// the CVE layer rather than OSV. Casks (GUI apps) are excluded — they are not
// usefully keyed in NVD by formula name.
type brewCollector struct {
	run runner
	log *zap.Logger
}

func (c *brewCollector) Name() string { return "Homebrew" }

func (c *brewCollector) Available() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

func (c *brewCollector) Collect(ctx context.Context) ([]models.Package, error) {
	out, err := c.run(ctx, "brew", "list", "--formula", "--versions")
	if err != nil {
		return nil, fmt.Errorf("brew list: %w", err)
	}
	return parseBrewOutput(out), nil
}

// parseBrewOutput parses `brew list --formula --versions` lines of the form
// "name v1 [v2 …]". When multiple versions are installed we take the last one
// listed, which Homebrew orders oldest-to-newest, i.e. the current version.
func parseBrewOutput(out []byte) []models.Package {
	var pkgs []models.Package
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		version := fields[len(fields)-1]
		pkgs = append(pkgs, models.Package{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemHomebrew,
			Direct:    true,
			Depth:     1,
		})
	}
	return pkgs
}
