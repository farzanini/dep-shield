package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dep-shield/dep-shield/internal/models"
)

const osvQueryURL = "https://api.osv.dev/v1/query"

// osvSource queries the OSV.dev REST API.
// OSV is a free, open vulnerability database that covers npm, Go, PyPI,
// crates.io, and many more ecosystems under a unified schema.
type osvSource struct {
	http *http.Client
}

func newOSVSource() *osvSource {
	return &osvSource{
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

func (o *osvSource) Name() string { return "OSV.dev" }

// OSV API request / response types — only the fields we need.
// Using anonymous structs for the request keeps the types close to their use.

type osvQueryRequest struct {
	Version string         `json:"version"`
	Package osvQueryPackage `json:"package"`
}

type osvQueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
	References []osvRef    `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"` // CVSS vector string like "CVSS:3.1/AV:N/..."
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

// Query sends a POST to the OSV batch query endpoint for one package.
func (o *osvSource) Query(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error) {
	body, err := json.Marshal(osvQueryRequest{
		Version: pkg.Version,
		Package: osvQueryPackage{
			Name:      pkg.Name,
			Ecosystem: string(pkg.Ecosystem),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("osv marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv http status %d for %s", resp.StatusCode, pkg.Name)
	}

	var osv osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&osv); err != nil {
		return nil, fmt.Errorf("osv decode: %w", err)
	}

	vulns := make([]models.Vulnerability, 0, len(osv.Vulns))
	for _, v := range osv.Vulns {
		vulns = append(vulns, convertOSV(v, pkg))
	}
	return vulns, nil
}

// convertOSV maps an OSV API response item into our internal Vulnerability type.
func convertOSV(v osvVuln, pkg models.Package) models.Vulnerability {
	sev, cvss := parseSeverity(v.Severity)
	fixed := extractFixedVersion(v.Affected)
	refs := make([]string, 0, len(v.References))
	for _, r := range v.References {
		refs = append(refs, r.URL)
	}
	return models.Vulnerability{
		ID:          v.ID,
		Summary:     v.Summary,
		Severity:    sev,
		CVSS:        cvss,
		FixedIn:     fixed,
		References:  refs,
		AffectedPkg: pkg,
	}
}

// parseSeverity converts an OSV severity array into our Severity + CVSS score.
// OSV can return multiple severity entries (CVSS_V3, CVSS_V2, etc.).
// We prefer CVSS_V3 when available.
func parseSeverity(sevs []osvSeverity) (models.Severity, float64) {
	for _, s := range sevs {
		if s.Type == "CVSS_V3" {
			score := cvssVectorToScore(s.Score)
			return scoreToSeverity(score), score
		}
	}
	// Fall back to the first entry if no V3 present.
	if len(sevs) > 0 {
		score := cvssVectorToScore(sevs[0].Score)
		return scoreToSeverity(score), score
	}
	return models.SeverityUnknown, 0
}

// cvssVectorToScore extracts the numeric base score from a CVSS vector string.
// OSV embeds the score as the last segment: "CVSS:3.1/.../7.5"
// We look for a numeric suffix after the last slash.
func cvssVectorToScore(vector string) float64 {
	// Try to extract a plain score encoded at the end of the vector (non-standard
	// but used by some OSV entries). Otherwise return 0 and let callers treat it
	// as unknown — we don't want a full CVSS parser dependency.
	var score float64
	_, _ = fmt.Sscanf(extractLastSegment(vector), "%f", &score)
	return score
}

func extractLastSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}

func scoreToSeverity(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score > 0:
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}

// extractFixedVersion digs through OSV "affected" ranges to find the first
// "fixed" event version.
func extractFixedVersion(affected []osvAffected) string {
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}
