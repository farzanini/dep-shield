// Package cve queries public vulnerability databases and maps their responses
// into the shared models.Vulnerability type.
//
// Supported sources
// -----------------
//   - OSV.dev   (https://osv.dev)  — free, no auth, broad ecosystem coverage
//   - GitHub Advisory Database      — richer data, requires GITHUB_TOKEN
//
// Design
// ------
// Source is the interface every database must implement.  Client fans out
// queries to all registered sources concurrently using a fixed worker pool so
// we don't hammer the APIs with thousands of simultaneous connections.
//
// All HTTP communication is done through the standard net/http package.  We do
// not use a third-party HTTP client to keep the dependency graph small and the
// binary size down.
package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"

	"github.com/dep-shield/dep-shield/internal/models"
)

// ── Public interfaces ─────────────────────────────────────────────────────────

// Source is the interface every vulnerability database must implement.
type Source interface {
	// Name returns a human-readable label used in logs.
	Name() string

	// Query returns all known vulnerabilities for pkg.
	// Returning an empty slice (not an error) is valid when no vulns are found.
	// Implementations must honour ctx cancellation.
	Query(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error)
}

// ── Data types ────────────────────────────────────────────────────────────────

// Options configures a Client.
type Options struct {
	// Offline skips all network requests.
	// When true, only a locally cached advisory file (if any) is consulted.
	Offline bool

	// Workers is the size of the semaphore that limits concurrent HTTP requests.
	// Use runtime.NumCPU()*2 as a reasonable default.
	Workers int

	// HTTPTimeout is the per-request timeout.  Defaults to 15s.
	HTTPTimeout time.Duration

	// Log is the structured logger.  Pass zap.NewNop() in tests.
	Log *zap.Logger
}

// QueryResult pairs a vulnerability with the package it was found against.
// It is used internally to pass data through the worker pool channel.
type QueryResult struct {
	Vuln models.Vulnerability
	Err  error
}

// ── Client implementation ─────────────────────────────────────────────────────

// Client fans out CVE queries to all registered sources.
type Client struct {
	sources []Source
	sem     *semaphore.Weighted // bounds concurrent HTTP requests
	log     *zap.Logger
	offline bool
}

// NewClient constructs a Client with OSV.dev and GitHub Advisory registered.
func NewClient(opts Options) *Client {
	if opts.HTTPTimeout == 0 {
		opts.HTTPTimeout = 15 * time.Second
	}
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	log := opts.Log
	if log == nil {
		log = zap.NewNop()
	}

	httpClient := &http.Client{Timeout: opts.HTTPTimeout}

	return &Client{
		sources: []Source{
			newOSVSource(httpClient, log),
			newGHSource(httpClient, log),
		},
		sem:     semaphore.NewWeighted(int64(opts.Workers)),
		log:     log,
		offline: opts.Offline,
	}
}

// QueryAll queries every registered source for every package and returns the
// merged, deduplicated list of vulnerabilities.
//
// The concurrency model:
//   - One goroutine is spawned per (package, source) pair.
//   - A semaphore limits how many goroutines make HTTP calls simultaneously.
//   - Results flow through a buffered channel; the main goroutine collects them.
//   - Non-fatal per-package errors are logged and excluded from the result.
func (c *Client) QueryAll(ctx context.Context, pkgs []models.Package) ([]models.Vulnerability, error) {
	if c.offline {
		c.log.Info("offline mode: skipping CVE queries")
		return nil, nil
	}

	total := len(pkgs) * len(c.sources)
	ch := make(chan QueryResult, total)
	var wg sync.WaitGroup

	for _, pkg := range pkgs {
		for _, src := range c.sources {
			pkg, src := pkg, src
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Acquire semaphore slot before making the HTTP call.
				if err := c.sem.Acquire(ctx, 1); err != nil {
					// ctx cancelled — bail silently.
					return
				}
				defer c.sem.Release(1)

				vulns, err := src.Query(ctx, pkg)
				if err != nil {
					c.log.Warn("CVE query failed",
						zap.String("source", src.Name()),
						zap.String("package", pkg.Name),
						zap.Error(err),
					)
					ch <- QueryResult{Err: err}
					return
				}
				for _, v := range vulns {
					ch <- QueryResult{Vuln: v}
				}
			}()
		}
	}

	// Close channel once all goroutines finish.
	go func() {
		wg.Wait()
		close(ch)
	}()

	seen := make(map[string]struct{})
	var all []models.Vulnerability
	for r := range ch {
		if r.Err != nil {
			continue // already logged above
		}
		if _, dup := seen[r.Vuln.ID]; dup {
			continue
		}
		seen[r.Vuln.ID] = struct{}{}
		all = append(all, r.Vuln)
	}
	return all, nil
}

// ── OSV.dev source stub ───────────────────────────────────────────────────────

const osvURL = "https://api.osv.dev/v1/query"

// osvSource queries the OSV.dev REST API.
type osvSource struct {
	http *http.Client
	log  *zap.Logger
}

func newOSVSource(h *http.Client, log *zap.Logger) *osvSource {
	return &osvSource{http: h, log: log}
}

func (o *osvSource) Name() string { return "OSV.dev" }

// osvRequest / osvResponse are the JSON shapes for the OSV v1 query API.
// Only the fields we need are declared; unknown fields are ignored by
// encoding/json automatically.

type osvRequest struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
	Refs     []osvRef      `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"` // CVSS vector string
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed string `json:"fixed"`
}

type osvRef struct {
	URL string `json:"url"`
}

// Query implements Source for the OSV.dev REST API.
func (o *osvSource) Query(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error) {
	// TODO: implement
	//   1. marshal osvRequest{pkg.Version, osvPackage{pkg.Name, string(pkg.Ecosystem)}}
	//   2. POST to osvURL with Content-Type: application/json
	//   3. decode osvResponse
	//   4. convert each osvVuln → models.Vulnerability (see convertOSVVuln below)
	_ = bytes.NewReader   // import kept alive
	_ = json.Marshal      // import kept alive
	_ = os.Getenv         // import kept alive
	_, _ = ctx, pkg
	return nil, fmt.Errorf("TODO: osvSource.Query not implemented")
}

// convertOSVVuln maps an OSV API vuln into our internal type.
// TODO: implement severity parsing (CVSS vector → score → Severity enum),
//
//	fixed-version extraction, reference URL collection.
func convertOSVVuln(v osvVuln, pkg models.Package) models.Vulnerability {
	_ = v
	return models.Vulnerability{AffectedPkg: pkg}
}

// ── GitHub Advisory source stub ───────────────────────────────────────────────

const ghGraphQLURL = "https://api.github.com/graphql"

// ghSource queries the GitHub Advisory Database via GraphQL.
type ghSource struct {
	http  *http.Client
	token string
	log   *zap.Logger
}

func newGHSource(h *http.Client, log *zap.Logger) *ghSource {
	return &ghSource{
		http:  h,
		token: os.Getenv("GITHUB_TOKEN"),
		log:   log,
	}
}

func (g *ghSource) Name() string { return "GitHub Advisory" }

// ghQuery is the GraphQL query sent to the GitHub API.
// It asks for the first 10 security advisories affecting the named package.
const ghQuery = `
query($name: String!, $ecosystem: SecurityAdvisoryEcosystem!) {
  securityVulnerabilities(first: 10, package: $name, ecosystem: $ecosystem) {
    nodes {
      advisory {
        ghsaId
        summary
        severity
        cvss { score }
        references { url }
      }
      firstPatchedVersion { identifier }
    }
  }
}`

// ghGraphQLRequest is the JSON body sent to the GitHub GraphQL endpoint.
type ghGraphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// ghGraphQLResponse is the JSON body returned by the GitHub GraphQL endpoint.
type ghGraphQLResponse struct {
	Data struct {
		SecurityVulnerabilities struct {
			Nodes []ghNode `json:"nodes"`
		} `json:"securityVulnerabilities"`
	} `json:"data"`
	Errors []struct{ Message string } `json:"errors"`
}

// ghNode is one entry in the GraphQL response.
type ghNode struct {
	Advisory struct {
		GHSAId     string  `json:"ghsaId"`
		Summary    string  `json:"summary"`
		Severity   string  `json:"severity"`
		CVSS       struct{ Score float64 } `json:"cvss"`
		References []struct{ URL string } `json:"references"`
	} `json:"advisory"`
	FirstPatchedVersion *struct {
		Identifier string `json:"identifier"`
	} `json:"firstPatchedVersion"`
}

// Query implements Source for the GitHub Advisory Database.
func (g *ghSource) Query(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error) {
	// TODO: implement
	//   0. return nil, nil if g.token == "" (no auth → skip)
	//   1. map pkg.Ecosystem → GitHub's SecurityAdvisoryEcosystem enum string
	//   2. POST ghGraphQLRequest{ghQuery, vars} to ghGraphQLURL
	//      with Authorization: bearer <token>
	//   3. decode ghGraphQLResponse
	//   4. convert each ghNode → models.Vulnerability
	_, _ = ctx, pkg
	return nil, fmt.Errorf("TODO: ghSource.Query not implemented")
}

// ghEcosystem maps our Ecosystem constants to GitHub's GraphQL enum values.
// Returns ("", false) for unsupported ecosystems.
func ghEcosystem(e models.Ecosystem) (string, bool) {
	// TODO: fill in the complete mapping
	switch e {
	case models.EcosystemNPM:
		return "NPM", true
	case models.EcosystemGo:
		return "GO", true
	case models.EcosystemCargo:
		return "RUST", true
	case models.EcosystemPyPI:
		return "PIP", true
	default:
		return "", false
	}
}
