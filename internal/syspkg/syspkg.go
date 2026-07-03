// Package syspkg enumerates packages installed by the host's system package
// manager (dpkg/apt, apk, Homebrew, …) and maps them onto models.Package with
// the ecosystem string the CVE layer expects.
//
// Unlike internal/scanner + internal/parser, which walk the filesystem and read
// lockfiles, a Collector shells out to the package manager (or reads its
// database) and produces resolved packages directly. The output flows into the
// same cve → scorer → reporter pipeline.
//
// # Ecosystem strings
//
// OSV.dev keys distro advisories by a release-specific ecosystem string, e.g.
// "Debian:12", "Ubuntu:22.04", "Alpine:v3.19". Collectors derive this from
// /etc/os-release (or /etc/alpine-release) at runtime, so the value is a plain
// models.Ecosystem string rather than a compile-time constant.
package syspkg

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"

	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/models"
)

// runner executes a command and returns its stdout. It is a field on each
// collector so tests can inject canned output without the real binary present.
type runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// execRunner is the production runner: it runs the command and returns stdout
// only (stderr is discarded; a non-zero exit surfaces as err).
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// Collector enumerates installed packages from one system package manager.
type Collector interface {
	// Name is a short human label, e.g. "dpkg" or "Homebrew".
	Name() string
	// Available reports whether this manager is usable on the current host.
	Available() bool
	// Collect returns every installed package with its ecosystem set.
	// Implementations must honour ctx cancellation.
	Collect(ctx context.Context) ([]models.Package, error)
}

// Detect returns the collectors usable on the current host. A collector is
// included only when Available() is true, so callers can Collect from each
// returned entry without further platform checks.
func Detect(log *zap.Logger) []Collector {
	if log == nil {
		log = zap.NewNop()
	}
	all := []Collector{
		&dpkgCollector{run: execRunner, osReleasePath: defaultOSReleasePath, log: log},
		&apkCollector{alpineReleasePath: defaultAlpineReleasePath, installedDBPath: defaultApkDBPath, log: log},
		&brewCollector{run: execRunner, log: log},
	}
	out := make([]Collector, 0, len(all))
	for _, c := range all {
		if c.Available() {
			out = append(out, c)
		}
	}
	return out
}

// ── os-release parsing ────────────────────────────────────────────────────────

const (
	defaultOSReleasePath     = "/etc/os-release"
	defaultAlpineReleasePath = "/etc/alpine-release"
	defaultApkDBPath         = "/lib/apk/db/installed"
)

// osRelease holds the subset of /etc/os-release fields we use.
type osRelease struct {
	ID        string // e.g. "debian", "ubuntu"
	VersionID string // e.g. "12", "22.04"
}

// readOSRelease parses the KEY=VALUE lines of an os-release file, stripping the
// optional surrounding quotes from values.
func readOSRelease(path string) (osRelease, error) {
	f, err := os.Open(path)
	if err != nil {
		return osRelease{}, err
	}
	defer f.Close()

	var r osRelease
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch strings.TrimSpace(key) {
		case "ID":
			r.ID = val
		case "VERSION_ID":
			r.VersionID = val
		}
	}
	return r, sc.Err()
}

// osvDebianEcosystem maps an os-release to the OSV ecosystem string for a
// dpkg-based distro. OSV tracks Debian by its major release number and Ubuntu
// by its VERSION_ID (the ":LTS" suffix is optional and omitted here). Returns
// ("", false) for any distro OSV does not track under a dpkg ecosystem.
func osvDebianEcosystem(r osRelease) (string, bool) {
	switch r.ID {
	case "debian":
		major, _, _ := strings.Cut(r.VersionID, ".")
		if major == "" {
			return "", false
		}
		return "Debian:" + major, true
	case "ubuntu":
		if r.VersionID == "" {
			return "", false
		}
		return "Ubuntu:" + r.VersionID, true
	default:
		return "", false
	}
}
