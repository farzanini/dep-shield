// Package advisory queries public vulnerability databases and maps their
// responses into the shared models.Vulnerability type.
package advisory

import (
	"context"

	"github.com/dep-shield/dep-shield/internal/models"
)

// Source is the interface every vulnerability database must implement.
// The design mirrors EcosystemScanner: adding a new database (e.g. NVD) only
// requires a new type that satisfies this interface.
type Source interface {
	// Name returns a label for logs and error messages.
	Name() string
	// Query returns all known vulnerabilities for the given package.
	// Implementations must respect ctx cancellation.
	Query(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error)
}

// Client fans out one Query call to all registered sources and merges results.
type Client struct {
	sources []Source
}

// New builds a Client that queries OSV.dev and GitHub Advisory Database.
func New() *Client {
	return &Client{
		sources: []Source{
			newOSVSource(),
			newGHAdvisorySource(),
		},
	}
}

// QueryAll queries every source for every package concurrently and returns
// the merged, deduplicated list of vulnerabilities.
//
// We use a simple fan-out pattern here: one goroutine per (package × source)
// pair, writing results into a buffered channel. This avoids holding a mutex
// while doing network I/O, which would serialize requests and defeat the
// purpose of concurrency.
func (c *Client) QueryAll(ctx context.Context, pkgs []models.Package) ([]models.Vulnerability, error) {
	type result struct {
		vulns []models.Vulnerability
		err   error
	}

	total := len(pkgs) * len(c.sources)
	ch := make(chan result, total)

	for _, pkg := range pkgs {
		for _, src := range c.sources {
			pkg, src := pkg, src // capture
			go func() {
				vulns, err := src.Query(ctx, pkg)
				ch <- result{vulns, err}
			}()
		}
	}

	seen := make(map[string]struct{})
	var all []models.Vulnerability

	for i := 0; i < total; i++ {
		r := <-ch
		if r.err != nil {
			// Non-fatal: one source failing shouldn't abort the whole scan.
			// The caller sees a partial result; errors are surfaced via logs
			// inside each source implementation.
			continue
		}
		for _, v := range r.vulns {
			if _, dup := seen[v.ID]; dup {
				continue
			}
			seen[v.ID] = struct{}{}
			all = append(all, v)
		}
	}
	return all, nil
}
