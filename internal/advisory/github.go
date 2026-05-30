package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dep-shield/dep-shield/internal/models"
)

const ghAdvisoryURL = "https://api.github.com/graphql"

// ghAdvisorySource queries the GitHub Advisory Database via its GraphQL API.
// It requires a GitHub personal access token in the GITHUB_TOKEN environment
// variable. Without a token, requests are unauthenticated and will quickly hit
// GitHub's rate limits (60 req/hour), so we skip querying when no token exists.
type ghAdvisorySource struct {
	http  *http.Client
	token string
}

func newGHAdvisorySource() *ghAdvisorySource {
	return &ghAdvisorySource{
		http:  &http.Client{Timeout: 15 * time.Second},
		token: os.Getenv("GITHUB_TOKEN"),
	}
}

func (g *ghAdvisorySource) Name() string { return "GitHub Advisory" }

// graphql query — we request the first 10 advisories for the package.
// Pagination is omitted for brevity; in practice most packages have < 10 CVEs.
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

type ghGraphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type ghGraphQLResponse struct {
	Data struct {
		SecurityVulnerabilities struct {
			Nodes []ghNode `json:"nodes"`
		} `json:"securityVulnerabilities"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type ghNode struct {
	Advisory struct {
		GHSAId     string `json:"ghsaId"`
		Summary    string `json:"summary"`
		Severity   string `json:"severity"`
		CVSS       struct {
			Score float64 `json:"score"`
		} `json:"cvss"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"advisory"`
	FirstPatchedVersion *struct {
		Identifier string `json:"identifier"`
	} `json:"firstPatchedVersion"`
}

// Query returns advisories from GitHub's database for the given package.
// Returns an empty slice (not an error) when no token is set, so the tool
// degrades gracefully to OSV-only results.
func (g *ghAdvisorySource) Query(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error) {
	if g.token == "" {
		return nil, nil
	}

	ecosystem, ok := toGHEcosystem(pkg.Ecosystem)
	if !ok {
		// GitHub Advisory doesn't support this ecosystem.
		return nil, nil
	}

	payload, err := json.Marshal(ghGraphQLRequest{
		Query: ghQuery,
		Variables: map[string]any{
			"name":      pkg.Name,
			"ecosystem": ecosystem,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gh marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ghAdvisoryURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("gh new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "bearer "+g.token)

	resp, err := g.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gh http: %w", err)
	}
	defer resp.Body.Close()

	var ghr ghGraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&ghr); err != nil {
		return nil, fmt.Errorf("gh decode: %w", err)
	}
	if len(ghr.Errors) > 0 {
		return nil, fmt.Errorf("gh graphql error: %s", ghr.Errors[0].Message)
	}

	var vulns []models.Vulnerability
	for _, node := range ghr.Data.SecurityVulnerabilities.Nodes {
		v := models.Vulnerability{
			ID:          node.Advisory.GHSAId,
			Summary:     node.Advisory.Summary,
			Severity:    ghSeverityToModel(node.Advisory.Severity),
			CVSS:        node.Advisory.CVSS.Score,
			AffectedPkg: pkg,
		}
		if node.FirstPatchedVersion != nil {
			v.FixedIn = node.FirstPatchedVersion.Identifier
		}
		for _, r := range node.Advisory.References {
			v.References = append(v.References, r.URL)
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// toGHEcosystem maps our Ecosystem constants to GitHub's SecurityAdvisoryEcosystem enum.
func toGHEcosystem(e models.Ecosystem) (string, bool) {
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

// ghSeverityToModel converts GitHub's severity string to our Severity type.
func ghSeverityToModel(s string) models.Severity {
	switch s {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MODERATE":
		return models.SeverityMedium
	case "LOW":
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}
