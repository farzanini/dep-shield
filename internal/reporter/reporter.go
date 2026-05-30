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

	"github.com/dep-shield/dep-shield/internal/models"
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
	// TODO: implement full table rendering
	//   1. Write header row via tabwriter
	//   2. For each vuln (already sorted by scorer):
	//        col1 = severity with ANSI colour
	//        col2 = CVSS score ("%.1f")
	//        col3 = ID (CVE- or GHSA-)
	//        col4 = package name
	//        col5 = current version
	//        col6 = fixed-in version (or "none known")
	//        col7 = truncated summary (60 chars)
	//   3. Write totals line
	//   4. Write per-severity counts (CRITICAL:N HIGH:N …)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer tw.Flush()

	// Keep imports alive until implementation.
	_ = strings.Repeat
	_ = severityColor
	_ = severityLabel
	_ = truncate
	_ = color.NoColor

	// Placeholder header.
	fmt.Fprintln(tw, "SEVERITY\tCVSS\tID\tPACKAGE\tVERSION\tFIX\tSUMMARY")
	fmt.Fprintln(tw, strings.Repeat("-", 90))

	for _, v := range result.Vulnerabilities {
		// TODO: apply severityColor[v.Severity].Sprintf(...)
		fix := v.FixedIn
		if fix == "" {
			fix = "none known"
		}
		fmt.Fprintf(tw, "%s\t%.1f\t%s\t%s\t%s\t%s\t%s\n",
			severityLabel(v.Severity),
			v.CVSS,
			v.ID,
			v.AffectedPkg.Name,
			v.AffectedPkg.Version,
			fix,
			truncate(v.Summary, 60),
		)
	}

	fmt.Fprintf(w, "\nScanned %d packages across %d path(s). Found %d vulnerabilities.\n",
		result.TotalPackages, len(result.ScannedPaths), len(result.Vulnerabilities))
	return nil
}

// WriteFile implements Reporter.
func (r *tableReporter) WriteFile(path string, format Format, result models.ScanResult) error {
	// TODO: open path, call the right Write* method based on format
	_ = format
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	return r.Write(f, result)
}

// ── JSON reporter ─────────────────────────────────────────────────────────────

type jsonReporter struct {
	log *zap.Logger
}

// Write serialises result as indented JSON to w.
func (r *jsonReporter) Write(w io.Writer, result models.ScanResult) error {
	// TODO: implement
	//   enc := json.NewEncoder(w)
	//   enc.SetIndent("", "  ")
	//   return enc.Encode(result)
	_ = json.NewEncoder // import kept alive
	return fmt.Errorf("TODO: jsonReporter.Write not implemented")
}

// WriteFile implements Reporter.
func (r *jsonReporter) WriteFile(path string, format Format, result models.ScanResult) error {
	// TODO: implement — open file, call Write
	_ = format
	return fmt.Errorf("TODO: jsonReporter.WriteFile not implemented")
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
	// TODO: open path, call Write
	_ = format
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	return r.Write(f, result)
}
