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

// cargoScanner reads Cargo.lock files produced by Rust's Cargo build tool.
// Cargo.lock is TOML but we parse it with a lightweight line scanner to avoid
// pulling in a TOML dependency — the file format is stable and simple enough.
type cargoScanner struct {
	log *zap.Logger
}

func (c *cargoScanner) Name() string { return "cargo" }

// Recognises returns true when a Cargo.lock file is present in dir.
func (c *cargoScanner) Recognises(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "Cargo.lock"))
	return err == nil
}

// Extract parses Cargo.lock. Each package is a [[package]] block:
//
//	[[package]]
//	name = "tokio"
//	version = "1.37.0"
//	...
func (c *cargoScanner) Extract(ctx context.Context, dir string) ([]models.Package, error) {
	f, err := os.Open(filepath.Join(dir, "Cargo.lock"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []models.Package
	var currentName, currentVersion string

	flush := func() {
		if currentName != "" && currentVersion != "" {
			pkgs = append(pkgs, models.Package{
				Name:      currentName,
				Version:   currentVersion,
				Ecosystem: models.EcosystemCargo,
				Path:      dir,
			})
		}
		currentName, currentVersion = "", ""
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if ctx.Err() != nil {
			flush()
			return pkgs, ctx.Err()
		}
		line := strings.TrimSpace(sc.Text())

		if line == "[[package]]" {
			flush() // save previous block before starting new one
			continue
		}

		if val, ok := tomlStringValue(line, "name"); ok {
			currentName = val
		} else if val, ok := tomlStringValue(line, "version"); ok {
			currentVersion = val
		}
	}
	flush() // save the last block

	if err := sc.Err(); err != nil {
		c.log.Warn("error reading Cargo.lock", zap.String("dir", dir), zap.Error(err))
	}
	return pkgs, nil
}

// tomlStringValue extracts the value from a TOML line of the form:
//
//	key = "value"
//
// Returns the unquoted value and true, or ("", false) if the line doesn't match.
func tomlStringValue(line, key string) (string, bool) {
	prefix := key + ` = "`
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := line[len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}
