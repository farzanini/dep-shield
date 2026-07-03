// Package reporter renders a models.ScanResult into human-readable output.
//
// Supported formats
// -----------------
//   - table   coloured, aligned terminal table (default)
//   - json    machine-readable JSON (for CI / downstream tools)
//   - html    self-contained HTML file (for stakeholder reports)
//
// Design
// ------
// Reporter is an interface so callers can supply a fake in tests.  Three
// concrete implementations live in this file:
//
//	tableReporter  — uses text/tabwriter for alignment, fatih/color for ANSI codes
//	jsonReporter   — uses encoding/json
//	htmlReporter   — uses html/template with an embedded template string
//
// All three satisfy the same Reporter interface.  The factory function New
// returns the right one based on Options.Format.
package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"go.uber.org/zap"

	"github.com/farzanini/dep-shield/internal/models"
)

// ── Constants ─────────────────────────────────────────────────────────────────

// Format selects the output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatHTML  Format = "html"
)

// ── Public interface ──────────────────────────────────────────────────────────

// Reporter renders a ScanResult.
type Reporter interface {
	// Write renders result to w in the configured format.
	Write(w io.Writer, result models.ScanResult) error

	// WriteFile renders result to the file at path in the given format.
	// It creates or truncates the file.
	WriteFile(path string, format Format, result models.ScanResult) error
}

// ── Options ───────────────────────────────────────────────────────────────────

// Options configures a Reporter.
type Options struct {
	// Format selects the output format.  Defaults to FormatTable.
	Format string

	// NoColour disables ANSI colour codes in terminal output.
	NoColour bool

	// Log is the structured logger.  Pass zap.NewNop() in tests.
	Log *zap.Logger
}

// ── Factory ───────────────────────────────────────────────────────────────────

// New constructs a Reporter for the format named in opts.Format.
// An unknown format falls back to FormatTable.
func New(opts Options) Reporter {
	log := opts.Log
	if log == nil {
		log = zap.NewNop()
	}
	if opts.NoColour {
		color.NoColor = true
	}

	switch Format(opts.Format) {
	case FormatJSON:
		return &jsonReporter{log: log}
	case FormatHTML:
		return &htmlReporter{log: log}
	default:
		return &tableReporter{log: log, noColour: opts.NoColour}
	}
}

// ── Shared helpers ────────────────────────────────────────────────────────────

// writeFileAs creates (or truncates) path and renders result into it using a
// reporter selected by format, regardless of which concrete reporter WriteFile
// was called on. File output never carries ANSI colour codes.
func writeFileAs(path string, format Format, result models.ScanResult, log *zap.Logger) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	rep := New(Options{Format: string(format), NoColour: true, Log: log})
	return rep.Write(f, result)
}

// severityColor maps severity levels to fatih/color attributes.
// fatih/color handles the NoColor global flag automatically.
var severityColor = map[models.Severity]*color.Color{
	models.SeverityCritical: color.New(color.FgRed, color.Bold),
	models.SeverityHigh:     color.New(color.FgRed),
	models.SeverityMedium:   color.New(color.FgYellow),
	models.SeverityLow:      color.New(color.FgCyan),
	models.SeverityUnknown:  color.New(color.FgWhite),
}

// severityLabel returns a right-padded severity string for aligned columns.
func severityLabel(s models.Severity) string {
	return fmt.Sprintf("%-8s", string(s))
}

// truncate shortens s to max runes, appending "…" when truncated.
func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-1]) + "…"
}

// ── Table reporter ────────────────────────────────────────────────────────────

type tableReporter struct {
	log      *zap.Logger
	noColour bool
}

// Write renders result as a coloured, tab-aligned table to w.
func (r *tableReporter) Write(w io.Writer, result models.ScanResult) error {
	if len(result.Vulnerabilities) == 0 {
		fmt.Fprintf(w, "No known vulnerabilities found across %d package(s) in %d path(s). ✓\n",
			result.TotalPackages, len(result.ScannedPaths))
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintln(tw, "SEVERITY\tCVSS\tID\tPACKAGE\tVERSION\tFIX\tSUMMARY")
	fmt.Fprintln(tw, strings.Join([]string{
		strings.Repeat("─", 8), strings.Repeat("─", 4), strings.Repeat("─", 18),
		strings.Repeat("─", 16), strings.Repeat("─", 10), strings.Repeat("─", 12),
		strings.Repeat("─", 40),
	}, "\t"))

	counts := make(map[models.Severity]int)
	for _, v := range result.Vulnerabilities {
		counts[v.Severity]++

		fix := v.FixedIn
		if fix == "" {
			fix = "none known"
		}

		sev := severityLabel(v.Severity)
		if c, ok := severityColor[v.Severity]; ok {
			sev = c.Sprint(sev)
		}

		fmt.Fprintf(tw, "%s\t%.1f\t%s\t%s\t%s\t%s\t%s\n",
			sev,
			v.CVSS,
			v.ID,
			v.AffectedPkg.Name,
			v.AffectedPkg.Version,
			fix,
			truncate(v.Summary, 60),
		)
	}
	tw.Flush()

	fmt.Fprintf(w, "\nScanned %d package(s) across %d path(s). Found %d vulnerabilit%s.\n",
		result.TotalPackages, len(result.ScannedPaths), len(result.Vulnerabilities),
		plural(len(result.Vulnerabilities)))
	fmt.Fprintln(w, severityBreakdown(counts))
	return nil
}

// plural returns "y" for a single item and "ies" otherwise, for "vulnerabilit_".
func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// severityBreakdown renders a coloured "CRITICAL:N HIGH:N …" summary line,
// ordered from most to least severe and omitting severities with no findings.
func severityBreakdown(counts map[models.Severity]int) string {
	order := []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityUnknown,
	}
	parts := make([]string, 0, len(order))
	for _, s := range order {
		n := counts[s]
		if n == 0 {
			continue
		}
		label := fmt.Sprintf("%s:%d", string(s), n)
		if c, ok := severityColor[s]; ok {
			label = c.Sprint(label)
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, "  ")
}

// WriteFile implements Reporter, dispatching on the requested format so callers
// can export a different format than the reporter was constructed with.
func (r *tableReporter) WriteFile(path string, format Format, result models.ScanResult) error {
	return writeFileAs(path, format, result, r.log)
}

// ── JSON reporter ─────────────────────────────────────────────────────────────

type jsonReporter struct {
	log *zap.Logger
}

// Write serialises result as indented JSON to w.
func (r *jsonReporter) Write(w io.Writer, result models.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encoding JSON report: %w", err)
	}
	return nil
}

// WriteFile implements Reporter.
func (r *jsonReporter) WriteFile(path string, format Format, result models.ScanResult) error {
	return writeFileAs(path, format, result, r.log)
}

// ── HTML reporter ─────────────────────────────────────────────────────────────

// htmlReportData is the data object passed into the HTML template.
type htmlReportData struct {
	GeneratedAt   string
	TotalPackages int
	ScannedPaths  []string
	Vulns         []models.Vulnerability
	// Counts holds per-severity totals for the summary banner.
	Counts map[models.Severity]int
}

// htmlTmplSrc is the embedded HTML template.
// Using a raw string literal keeps it in this file so the binary stays
// self-contained (no external template file to deploy).
//
// TODO: expand this template with proper CSS, severity badges, fix advice, etc.
const htmlTmplSrc = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>dep-shield vulnerability report</title>
  <style>
    body  { font-family: system-ui, sans-serif; margin: 2rem; }
    table { border-collapse: collapse; width: 100%; }
    th,td { border: 1px solid #ddd; padding: 0.4rem 0.8rem; text-align: left; }
    th    { background: #f4f4f4; }
    .CRITICAL { background: #ffd0d0; font-weight: bold; }
    .HIGH     { background: #ffe4cc; }
    .MEDIUM   { background: #fff9cc; }
    .LOW      { background: #d0f0ff; }
  </style>
</head>
<body>
  <h1>dep-shield — Vulnerability Report</h1>
  <p>Generated: {{.GeneratedAt}} | Packages scanned: {{.TotalPackages}}</p>
  <table>
    <thead>
      <tr><th>Severity</th><th>CVSS</th><th>ID</th><th>Package</th>
          <th>Version</th><th>Fix</th><th>Summary</th></tr>
    </thead>
    <tbody>
    {{range .Vulns}}
      <tr class="{{.Severity}}">
        <td>{{.Severity}}</td>
        <td>{{printf "%.1f" .CVSS}}</td>
        <td>{{.ID}}</td>
        <td>{{.AffectedPkg.Name}}</td>
        <td>{{.AffectedPkg.Version}}</td>
        <td>{{if .FixedIn}}{{.FixedIn}}{{else}}none known{{end}}</td>
        <td>{{.Summary}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
</body>
</html>`

type htmlReporter struct {
	log *zap.Logger
}

// Write renders result as a self-contained HTML document to w.
func (r *htmlReporter) Write(w io.Writer, result models.ScanResult) error {
	// TODO: implement
	//   1. parse htmlTmplSrc with html/template
	//   2. build htmlReportData
	//   3. tmpl.Execute(w, data)

	tmpl, err := template.New("report").Parse(htmlTmplSrc)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	counts := make(map[models.Severity]int)
	for _, v := range result.Vulnerabilities {
		counts[v.Severity]++
	}

	data := htmlReportData{
		GeneratedAt:   time.Now().UTC().Format(time.RFC1123),
		TotalPackages: result.TotalPackages,
		ScannedPaths:  result.ScannedPaths,
		Vulns:         result.Vulnerabilities,
		Counts:        counts,
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("executing HTML template: %w", err)
	}
	return nil
}

// WriteFile implements Reporter.
func (r *htmlReporter) WriteFile(path string, format Format, result models.ScanResult) error {
	return writeFileAs(path, format, result, r.log)
}
