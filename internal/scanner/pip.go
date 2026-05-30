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

// pipScanner finds Python packages from two sources:
//  1. site-packages directories (installed packages have a <name>-<ver>.dist-info/METADATA file)
//  2. requirements.txt files (pinned dependencies declared by a project)
type pipScanner struct {
	log *zap.Logger
}

func (p *pipScanner) Name() string { return "pip" }

// Recognises returns true for:
//   - directories named "site-packages" (virtualenv / system Python installs)
//   - directories that contain a requirements.txt file
func (p *pipScanner) Recognises(dir string) bool {
	if filepath.Base(dir) == "site-packages" {
		return true
	}
	_, err := os.Stat(filepath.Join(dir, "requirements.txt"))
	return err == nil
}

// Extract dispatches to the right sub-parser based on directory type.
func (p *pipScanner) Extract(ctx context.Context, dir string) ([]models.Package, error) {
	if filepath.Base(dir) == "site-packages" {
		return p.extractSitePackages(ctx, dir)
	}
	return p.extractRequirements(ctx, dir)
}

// extractSitePackages reads *.dist-info/METADATA files.
// Each installed package leaves a directory like:  requests-2.31.0.dist-info/
// Inside, the METADATA file has lines:  Name: requests   Version: 2.31.0
func (p *pipScanner) extractSitePackages(ctx context.Context, dir string) ([]models.Package, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var pkgs []models.Package
	for _, e := range entries {
		if ctx.Err() != nil {
			return pkgs, ctx.Err()
		}
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".dist-info") {
			continue
		}
		metaPath := filepath.Join(dir, e.Name(), "METADATA")
		pkg, ok := p.readDistInfoMetadata(metaPath, dir)
		if ok {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs, nil
}

// readDistInfoMetadata extracts Name and Version from a METADATA file.
func (p *pipScanner) readDistInfoMetadata(path, siteDir string) (models.Package, bool) {
	f, err := os.Open(path)
	if err != nil {
		return models.Package{}, false
	}
	defer f.Close()

	var name, version string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// METADATA uses RFC 822 header style: "Key: Value"
		// Headers end at the first blank line.
		if line == "" {
			break
		}
		if v, ok := headerValue(line, "Name"); ok {
			name = v
		} else if v, ok := headerValue(line, "Version"); ok {
			version = v
		}
		if name != "" && version != "" {
			break
		}
	}
	if name == "" {
		return models.Package{}, false
	}
	return models.Package{
		Name:      name,
		Version:   version,
		Ecosystem: models.EcosystemPyPI,
		Path:      siteDir,
	}, true
}

// extractRequirements reads a requirements.txt file.
// Supported line formats:
//
//	requests==2.31.0
//	flask>=2.0,<3.0   (we record only the first version constraint)
//	# comment line    (skipped)
//	-r other.txt      (skipped — we don't follow includes)
func (p *pipScanner) extractRequirements(ctx context.Context, dir string) ([]models.Package, error) {
	f, err := os.Open(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []models.Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if ctx.Err() != nil {
			return pkgs, ctx.Err()
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		name, version := parseRequirementLine(line)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, models.Package{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemPyPI,
			Path:      dir,
		})
	}
	if err := sc.Err(); err != nil {
		p.log.Warn("error reading requirements.txt", zap.String("dir", dir), zap.Error(err))
	}
	return pkgs, nil
}

// parseRequirementLine extracts name and version from a requirements.txt entry.
// Returns ("", "") when the line can't be parsed as a package spec.
func parseRequirementLine(line string) (name, version string) {
	// Find the first operator: ==, >=, <=, !=, ~=, >
	operators := []string{"==", ">=", "<=", "!=", "~=", ">", "<"}
	for _, op := range operators {
		if idx := strings.Index(line, op); idx >= 0 {
			n := strings.TrimSpace(line[:idx])
			rest := strings.TrimSpace(line[idx+len(op):])
			// Take only up to the next comma (first constraint).
			if comma := strings.Index(rest, ","); comma >= 0 {
				rest = rest[:comma]
			}
			return n, strings.TrimSpace(rest)
		}
	}
	// No version constraint at all — just a bare package name.
	return strings.TrimSpace(line), ""
}

// headerValue parses a line like "Name: requests" returning ("requests", true).
func headerValue(line, key string) (string, bool) {
	prefix := key + ": "
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	return strings.TrimSpace(line[len(prefix):]), true
}
