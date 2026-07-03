package syspkg

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/models"
)

// dpkgCollector enumerates installed packages on Debian/Ubuntu via dpkg-query.
// The OSV ecosystem string is derived from /etc/os-release so advisories are
// matched against the correct release (e.g. "Debian:12", "Ubuntu:22.04").
type dpkgCollector struct {
	run           runner
	osReleasePath string
	log           *zap.Logger
}

func (c *dpkgCollector) Name() string { return "dpkg" }

func (c *dpkgCollector) Available() bool {
	_, err := exec.LookPath("dpkg-query")
	return err == nil
}

func (c *dpkgCollector) Collect(ctx context.Context) ([]models.Package, error) {
	rel, err := readOSRelease(c.osReleasePath)
	if err != nil {
		return nil, fmt.Errorf("reading os-release: %w", err)
	}
	eco, ok := osvDebianEcosystem(rel)
	if !ok {
		return nil, fmt.Errorf("dpkg host %q is not an OSV-tracked distro", rel.ID)
	}

	// Tab-separated so names/versions with spaces (there are none, but be safe)
	// never split incorrectly. Status filters out removed-but-config packages.
	out, err := c.run(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n")
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	return parseDpkgOutput(out, models.Ecosystem(eco)), nil
}

// parseDpkgOutput turns dpkg-query's tab-separated lines into packages, keeping
// only entries whose status is exactly "install ok installed" (dpkg also lists
// packages that were removed but left config files behind).
func parseDpkgOutput(out []byte, eco models.Ecosystem) []models.Package {
	var pkgs []models.Package
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		version := strings.TrimSpace(fields[1])
		status := strings.TrimSpace(fields[2])
		if name == "" || version == "" || status != "install ok installed" {
			continue
		}
		pkgs = append(pkgs, models.Package{
			Name:      name,
			Version:   version,
			Ecosystem: eco,
			Direct:    true,
			Depth:     1,
		})
	}
	return pkgs
}
