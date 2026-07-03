package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/farzanini/dep-shield/internal/models"
)

// ── NVD source (Homebrew / CPE matching) ──────────────────────────────────────
//
// OSV has no Homebrew ecosystem, so Homebrew formulae are matched against the
// NVD 2.0 CVE API by CPE instead. We build a virtual match string
// "cpe:2.3:a:*:<product>:<version>:*:*:*:*:*:*:*" and let NVD perform the
// version-range evaluation server-side, so no local CPE range logic is needed.
//
// Coverage is necessarily partial: a formula only matches when its name equals
// the CPE product (true for openssl, curl, git, ffmpeg, … but not for renamed
// or novel formulae), and a wildcard vendor can occasionally admit a
// same-named product from a different vendor. It complements, not replaces,
// the OSV ecosystems.

const nvdURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type nvdSource struct {
	http    *http.Client
	apiKey  string
	limiter *nvdLimiter
	log     *zap.Logger
}

// newNVDSource builds the NVD source. It reads NVD_API_KEY from the environment
// and sets the request interval accordingly: NVD allows ~5 requests / 30s
// unauthenticated and ~50 / 30s with a key.
func newNVDSource(h *http.Client, log *zap.Logger) *nvdSource {
	key := os.Getenv("NVD_API_KEY")
	interval := 6500 * time.Millisecond // ~5 req / 30s, with margin
	if key != "" {
		interval = 800 * time.Millisecond // ~37 req / 30s, safely under 50
	} else {
		log.Warn("NVD_API_KEY not set: Homebrew CVE lookups are throttled to " +
			"~5 requests/30s; set NVD_API_KEY for roughly 8x faster scans")
	}
	return &nvdSource{
		http:    h,
		apiKey:  key,
		limiter: newNVDLimiter(interval),
		log:     log,
	}
}

func (n *nvdSource) Name() string { return "NVD" }

// Query implements Source. It only handles Homebrew packages; for every other
// ecosystem it returns (nil, nil) so the fan-out leaves those to OSV/GitHub.
func (n *nvdSource) Query(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error) {
	if pkg.Ecosystem != models.EcosystemHomebrew {
		return nil, nil
	}
	product := nvdProduct(pkg.Name)
	if product == "" || pkg.Version == "" {
		return nil, nil
	}

	// Serialise and pace requests to stay within NVD's rate limit.
	if err := n.limiter.wait(ctx); err != nil {
		return nil, err
	}

	match := fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", product, pkg.Version)
	q := url.Values{}
	q.Set("virtualMatchString", match)
	q.Set("resultsPerPage", "100")
	reqURL := nvdURL + "?" + q.Encode()

	resp, err := doWithRetry(ctx, n.http, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		if n.apiKey != "" {
			req.Header.Set("apiKey", n.apiKey)
		}
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("nvd request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd http status %d for %s", resp.StatusCode, product)
	}

	var out nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("nvd decode: %w", err)
	}

	vulns := make([]models.Vulnerability, 0, len(out.Vulnerabilities))
	for _, entry := range out.Vulnerabilities {
		vulns = append(vulns, convertNVDCVE(entry.CVE, pkg))
	}
	return vulns, nil
}

// nvdProduct derives the CPE product from a Homebrew formula name: it drops any
// "@version" suffix (openssl@3 -> openssl, python@3.12 -> python) and lowercases.
func nvdProduct(name string) string {
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// ── NVD JSON shapes (only the fields we use) ──────────────────────────────────

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string          `json:"id"`
	Published    string          `json:"published"`
	Descriptions []nvdLangString `json:"descriptions"`
	Metrics      nvdMetrics      `json:"metrics"`
	References   []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
	V2  []nvdMetric `json:"cvssMetricV2"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// convertNVDCVE maps an NVD CVE record into our internal type.
func convertNVDCVE(c nvdCVE, pkg models.Package) models.Vulnerability {
	score, severity := nvdScore(c.Metrics)

	refs := make([]string, 0, len(c.References))
	for _, r := range c.References {
		refs = append(refs, r.URL)
	}

	return models.Vulnerability{
		ID:          c.ID,
		Summary:     nvdSummary(c.Descriptions),
		Severity:    severity,
		CVSS:        score,
		References:  refs,
		AffectedPkg: pkg,
		Published:   parseAdvisoryTime(c.Published),
	}
}

// nvdScore returns the best CVSS base score and derived severity, preferring
// CVSS v3.1, then v3.0, then v2.
func nvdScore(m nvdMetrics) (float64, models.Severity) {
	for _, group := range [][]nvdMetric{m.V31, m.V30, m.V2} {
		if len(group) > 0 {
			d := group[0].CVSSData
			sev := scoreToSeverity(d.BaseScore)
			if d.BaseSeverity != "" {
				sev = ghSeverityToModel(d.BaseSeverity)
			}
			return d.BaseScore, sev
		}
	}
	return 0, models.SeverityUnknown
}

// nvdSummary returns the English description, falling back to the first one.
func nvdSummary(ds []nvdLangString) string {
	for _, d := range ds {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(ds) > 0 {
		return ds[0].Value
	}
	return ""
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

// nvdLimiter enforces a minimum interval between NVD requests across all
// goroutines, since the cve worker pool may call Query concurrently but NVD's
// rate limit is global.
type nvdLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newNVDLimiter(interval time.Duration) *nvdLimiter {
	return &nvdLimiter{interval: interval}
}

// wait blocks until the next request slot is due, or until ctx is cancelled.
func (l *nvdLimiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	slot := l.next
	if slot.Before(now) {
		slot = now
	}
	l.next = slot.Add(l.interval)
	l.mu.Unlock()

	delay := time.Until(slot)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
