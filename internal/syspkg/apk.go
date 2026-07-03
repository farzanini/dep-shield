package syspkg

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/models"
)

// apkCollector enumerates installed packages on Alpine Linux. It reads the apk
// database directly (/lib/apk/db/installed) rather than shelling out, because
// `apk info -v` joins name-version-release with dashes that cannot be split
// unambiguously. The database's P:/V: records are exact.
type apkCollector struct {
	alpineReleasePath string
	installedDBPath   string
	log               *zap.Logger
}

func (c *apkCollector) Name() string { return "apk" }

func (c *apkCollector) Available() bool {
	if _, err := os.Stat(c.installedDBPath); err != nil {
		return false
	}
	_, err := os.Stat(c.alpineReleasePath)
	return err == nil
}

func (c *apkCollector) Collect(ctx context.Context) ([]models.Package, error) {
	eco, err := c.ecosystem()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(c.installedDBPath)
	if err != nil {
		return nil, fmt.Errorf("reading apk db: %w", err)
	}
	return parseApkDB(data, models.Ecosystem(eco)), nil
}

// ecosystem builds the OSV Alpine ecosystem string from /etc/alpine-release,
// which holds a full version like "3.19.1"; OSV keys advisories by the
// major.minor branch, e.g. "Alpine:v3.19".
func (c *apkCollector) ecosystem() (string, error) {
	data, err := os.ReadFile(c.alpineReleasePath)
	if err != nil {
		return "", fmt.Errorf("reading alpine-release: %w", err)
	}
	return alpineEcosystem(string(data))
}

// alpineEcosystem maps a raw alpine-release string ("3.19.1\n") to the OSV
// ecosystem branch string ("Alpine:v3.19").
func alpineEcosystem(raw string) (string, error) {
	ver := strings.TrimSpace(raw)
	parts := strings.Split(ver, ".")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("unrecognised alpine-release %q", ver)
	}
	return "Alpine:v" + parts[0] + "." + parts[1], nil
}

// parseApkDB parses the apk installed database. Each package is a block of
// KEY:VALUE lines separated by blank lines; we take P: (name) and V: (version).
func parseApkDB(data []byte, eco models.Ecosystem) []models.Package {
	var pkgs []models.Package
	var name, version string

	flush := func() {
		if name != "" && version != "" {
			pkgs = append(pkgs, models.Package{
				Name:      name,
				Version:   version,
				Ecosystem: eco,
				Direct:    true,
				Depth:     1,
			})
		}
		name, version = "", ""
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "P":
			name = val
		case "V":
			version = val
		}
	}
	flush() // final record may not end with a blank line
	return pkgs
}
