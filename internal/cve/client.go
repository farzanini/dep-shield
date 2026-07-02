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
	"strings"
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
	ID        string        `json:"id"`
	Aliases   []string      `json:"aliases"`
	Summary   string        `json:"summary"`
	Details   string        `json:"details"`
	Published string        `json:"published"` // RFC3339 timestamp
	Severity  []osvSeverity `json:"severity"`
	Affected  []osvAffected `json:"affected"`
	Refs      []osvRef      `json:"references"`

	DatabaseSpecific struct {
		Severity string  `json:"severity"`
		CVSS     float64 `json:"cvss"`
	} `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"` // CVSS vector string
}

type osvAffected struct {
	Package struct {
		Name string `json:"name"`
	} `json:"package"`
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
	body, err := json.Marshal(osvRequest{
		Version: pkg.Version,
		Package: osvPackage{
			Name:      pkg.Name,
			Ecosystem: string(pkg.Ecosystem),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("osv marshal: %w", err)
	}

	resp, err := doWithRetry(ctx, o.http, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("osv request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv http status %d for %s", resp.StatusCode, pkg.Name)
	}

	var out osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("osv decode: %w", err)
	}

	vulns := make([]models.Vulnerability, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		vulns = append(vulns, convertOSVVuln(v, pkg))
	}
	return vulns, nil
}

// convertOSVVuln maps an OSV API vuln into our internal type, resolving the best
// available CVSS score, deriving a Severity enum, and extracting the fixed
// version and reference URLs.
func convertOSVVuln(v osvVuln, pkg models.Package) models.Vulnerability {
	score := osvScore(v)
	refs := make([]string, 0, len(v.Refs))
	for _, r := range v.Refs {
		refs = append(refs, r.URL)
	}

	summary := v.Summary
	if summary == "" {
		summary = v.Details
	}

	return models.Vulnerability{
		ID:          osvID(v),
		Summary:     summary,
		Severity:    scoreToSeverity(score),
		CVSS:        score,
		FixedIn:     osvFixedIn(v, pkg.Name),
		References:  refs,
		AffectedPkg: pkg,
		Published:   parseAdvisoryTime(v.Published),
	}
}

// osvID prefers an assigned CVE alias over OSV's internal ID so findings are
// reported under their canonical CVE identifier when one exists.
func osvID(v osvVuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// osvScore returns the best numeric CVSS score for an OSV vuln, trying, in order:
// an explicit database_specific.cvss number, a CVSS_V3/V2 vector, then a
// database_specific.severity label.
func osvScore(v osvVuln) float64 {
	if v.DatabaseSpecific.CVSS > 0 {
		return v.DatabaseSpecific.CVSS
	}
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			if score := cvssVectorToScore(s.Score); score > 0 {
				return score
			}
		}
	}
	return severityToScore(v.DatabaseSpecific.Severity)
}

// osvFixedIn digs through OSV "affected" ranges to find the first "fixed" event
// version for the named package.
func osvFixedIn(v osvVuln, pkgName string) string {
	for _, a := range v.Affected {
		if a.Package.Name != "" && a.Package.Name != pkgName {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
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
        publishedAt
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
		GHSAId      string  `json:"ghsaId"`
		Summary     string  `json:"summary"`
		Severity    string  `json:"severity"`
		PublishedAt string  `json:"publishedAt"` // RFC3339 timestamp
		CVSS        struct{ Score float64 } `json:"cvss"`
		References  []struct{ URL string } `json:"references"`
	} `json:"advisory"`
	FirstPatchedVersion *struct {
		Identifier string `json:"identifier"`
	} `json:"firstPatchedVersion"`
}

// Query implements Source for the GitHub Advisory Database.
// It returns (nil, nil) — degrading gracefully to OSV-only results — when no
// token is configured or the ecosystem is unsupported by the GitHub API.
func (g *ghSource) Query(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error) {
	if g.token == "" {
		return nil, nil
	}

	ecosystem, ok := ghEcosystem(pkg.Ecosystem)
	if !ok {
		return nil, nil
	}

	body, err := json.Marshal(ghGraphQLRequest{
		Query: ghQuery,
		Variables: map[string]any{
			"name":      pkg.Name,
			"ecosystem": ecosystem,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gh marshal: %w", err)
	}

	resp, err := doWithRetry(ctx, g.http, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ghGraphQLURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "bearer "+g.token)
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("gh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gh http status %d for %s", resp.StatusCode, pkg.Name)
	}

	var ghr ghGraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&ghr); err != nil {
		return nil, fmt.Errorf("gh decode: %w", err)
	}
	if len(ghr.Errors) > 0 {
		return nil, fmt.Errorf("gh graphql error: %s", ghr.Errors[0].Message)
	}

	var vulns []models.Vulnerability
	for _, node := range ghr.Data.SecurityVulnerabilities.Nodes {
		vulns = append(vulns, convertGHNode(node, pkg))
	}
	return vulns, nil
}

// convertGHNode maps a GitHub GraphQL advisory node into our internal type.
// When the advisory carries no CVSS score we fall back to its severity label.
func convertGHNode(node ghNode, pkg models.Package) models.Vulnerability {
	score := node.Advisory.CVSS.Score
	if score == 0 {
		score = severityToScore(node.Advisory.Severity)
	}

	v := models.Vulnerability{
		ID:          node.Advisory.GHSAId,
		Summary:     node.Advisory.Summary,
		Severity:    ghSeverityToModel(node.Advisory.Severity),
		CVSS:        score,
		AffectedPkg: pkg,
		Published:   parseAdvisoryTime(node.Advisory.PublishedAt),
	}
	if node.FirstPatchedVersion != nil {
		v.FixedIn = node.FirstPatchedVersion.Identifier
	}
	for _, r := range node.Advisory.References {
		v.References = append(v.References, r.URL)
	}
	return v
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
