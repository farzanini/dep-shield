package cmd

// mcpCmd runs dep-shield as a Model Context Protocol server so AI agents can
// scan projects and the host for vulnerable packages. It speaks JSON-RPC over
// stdio; configure an MCP client to launch `dep-shield mcp`.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/mcp"
	"github.com/dep-shield/dep-shield/internal/models"
	"github.com/dep-shield/dep-shield/internal/pipeline"
)

func mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run dep-shield as an MCP server (stdio) for AI agents",
		Long: `mcp starts a Model Context Protocol server on stdin/stdout so AI agents can
call dep-shield to check projects and the host for vulnerable packages.

Configure your MCP client to launch this command, e.g.:

  {
    "mcpServers": {
      "dep-shield": { "command": "dep-shield", "args": ["mcp"] }
    }
  }

Tools exposed:
  scan_project          — scan a local project directory for vulnerable deps
  scan_system_packages  — scan installed OS packages (Homebrew, dpkg/apt, apk)

Set GITHUB_TOKEN for GitHub Advisory data and NVD_API_KEY for faster Homebrew
lookups.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMCP(cmd.Context())
		},
	}
}

func runMCP(ctx context.Context) error {
	// stdout carries the JSON-RPC protocol, so the logger MUST write to stderr.
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{"stderr"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	log, err := cfg.Build()
	if err != nil {
		log = zap.NewNop()
	}
	defer func() { _ = log.Sync() }()

	srv := &mcp.Server{
		Name:    "dep-shield",
		Version: Version,
		Log:     log,
		Tools:   depShieldTools(log),
	}
	return srv.Serve(ctx, os.Stdin, os.Stdout)
}

// depShieldTools returns the MCP tools backed by the scan pipeline.
func depShieldTools(log *zap.Logger) []mcp.Tool {
	return []mcp.Tool{
		{
			Name: "scan_project",
			Description: "Scan a local project directory for known-vulnerable dependencies " +
				"across npm, Go, Cargo, and PyPI. Reads installed dependency stores and " +
				"committed lockfiles/manifests, queries OSV (and the GitHub Advisory DB when " +
				"GITHUB_TOKEN is set), and returns findings with severity, CVSS, the fixed " +
				"version, and remediation advice. Returns a JSON object.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Absolute path to the project directory to scan.",
					},
					"min_severity": map[string]any{
						"type":        "string",
						"enum":        []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"},
						"description": "Lowest severity to include. Default LOW.",
					},
					"ecosystems": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": `Restrict to these ecosystems, e.g. ["npm","Go","crates.io","PyPI"]. Default: all.`,
					},
				},
				"required": []string{"path"},
			},
			Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
				var a struct {
					Path        string   `json:"path"`
					MinSeverity string   `json:"min_severity"`
					Ecosystems  []string `json:"ecosystems"`
				}
				if err := json.Unmarshal(raw, &a); err != nil {
					return "", fmt.Errorf("invalid arguments: %w", err)
				}
				if strings.TrimSpace(a.Path) == "" {
					return "", fmt.Errorf("path is required")
				}
				res, err := pipeline.Run(ctx, pipeline.Options{
					Roots:       []string{a.Path},
					Ecosystems:  a.Ecosystems,
					MinSeverity: parseMinSeverity(a.MinSeverity),
					Log:         log,
				})
				if err != nil {
					return "", err
				}
				return formatScanResult(res), nil
			},
		},
		{
			Name: "scan_system_packages",
			Description: "Scan packages installed by the host's system package managers " +
				"(Homebrew on macOS; dpkg/apt and apk on Linux) for known vulnerabilities. " +
				"Homebrew is matched against NVD by CPE (set NVD_API_KEY for speed); Linux " +
				"distros are matched against OSV. Returns a JSON object.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"min_severity": map[string]any{
						"type":        "string",
						"enum":        []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"},
						"description": "Lowest severity to include. Default LOW.",
					},
				},
			},
			Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
				var a struct {
					MinSeverity string `json:"min_severity"`
				}
				if len(raw) > 0 {
					if err := json.Unmarshal(raw, &a); err != nil {
						return "", fmt.Errorf("invalid arguments: %w", err)
					}
				}
				res, err := pipeline.Run(ctx, pipeline.Options{
					System:      true,
					MinSeverity: parseMinSeverity(a.MinSeverity),
					Log:         log,
				})
				if err != nil {
					return "", err
				}
				return formatScanResult(res), nil
			},
		},
	}
}

// parseMinSeverity maps an optional severity string to the enum, defaulting to LOW.
func parseMinSeverity(s string) models.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MEDIUM":
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

// mcpFinding is the flattened per-CVE shape returned to the agent.
type mcpFinding struct {
	ID        string  `json:"id"`
	CVE       string  `json:"cve,omitempty"`
	Package   string  `json:"package"`
	Version   string  `json:"version"`
	Ecosystem string  `json:"ecosystem"`
	Severity  string  `json:"severity"`
	CVSS      float64 `json:"cvss"`
	FixedIn   string  `json:"fixedIn,omitempty"`
	FixAdvice string  `json:"fixAdvice,omitempty"`
	Summary   string  `json:"summary,omitempty"`
}

// formatScanResult renders a ScanResult as an indented JSON string for the agent.
func formatScanResult(res models.ScanResult) string {
	counts := map[string]int{}
	findings := make([]mcpFinding, 0, len(res.Vulnerabilities))
	for _, v := range res.Vulnerabilities {
		counts[string(v.Severity)]++
		cve := ""
		if strings.HasPrefix(v.ID, "CVE-") {
			cve = v.ID
		}
		findings = append(findings, mcpFinding{
			ID:        v.ID,
			CVE:       cve,
			Package:   v.AffectedPkg.Name,
			Version:   v.AffectedPkg.Version,
			Ecosystem: string(v.AffectedPkg.Ecosystem),
			Severity:  string(v.Severity),
			CVSS:      v.CVSS,
			FixedIn:   v.FixedIn,
			FixAdvice: v.FixAdvice,
			Summary:   v.Summary,
		})
	}

	out := map[string]any{
		"scannedPaths":       res.ScannedPaths,
		"totalPackages":      res.TotalPackages,
		"vulnerabilityCount": len(res.Vulnerabilities),
		"severityCounts":     counts,
		"findings":           findings,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(b)
}
