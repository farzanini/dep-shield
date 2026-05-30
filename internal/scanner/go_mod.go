package scanner

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/models"
)

// goScanner reads go.sum files (which list every resolved dependency and its
// exact checksum) rather than go.mod (which may use "latest" or ranges).
// go.sum is the ground truth for what is actually used.
type goScanner struct {
	log *zap.Logger
}

func (g *goScanner) Name() string { return "go" }

// Recognises returns true when a go.sum file exists inside dir.
func (g *goScanner) Recognises(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "go.sum"))
	return err == nil
}

// Extract parses go.sum line by line. Each line has the form:
//
//	module@version hash
//	module@version/go.mod hash
//
// We keep only the non-"/go.mod" lines to avoid duplicates.
func (g *goScanner) Extract(ctx context.Context, dir string) ([]models.Package, error) {
	f, err := os.Open(filepath.Join(dir, "go.sum"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var pkgs []models.Package

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return pkgs, ctx.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: "<module>@<version> <hash>"
		// Split on space → first field is "<module>@<version>"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		moduleVer := fields[0]

		// Skip the go.mod-only entries.
		if strings.HasSuffix(moduleVer, "/go.mod") {
			continue
		}

		at := strings.LastIndex(moduleVer, "@")
		if at < 0 {
			continue
		}
		name := moduleVer[:at]
		version := moduleVer[at+1:]

		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		pkgs = append(pkgs, models.Package{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemGo,
			Path:      dir,
		})
	}
	if err := scanner.Err(); err != nil {
		g.log.Warn("error reading go.sum", zap.String("dir", dir), zap.Error(err))
	}
	return pkgs, nil
}
