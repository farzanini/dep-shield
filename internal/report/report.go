// Package report formats scan results into human-readable output.
// Two formats are supported: a coloured terminal table and a JSON file.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/dep-shield/dep-shield/internal/models"
)

// severityColour maps severity levels to ANSI escape codes.
// These codes work on every modern terminal including macOS Terminal,
// iTerm2, Windows Terminal, and most Linux terminal emulators.
var severityColour = map[models.Severity]string{
	models.SeverityCritical: "\033[1;31m", // bold red
	models.SeverityHigh:     "\033[0;31m", // red
	models.SeverityMedium:   "\033[0;33m", // yellow
	models.SeverityLow:      "\033[0;36m", // cyan
	models.SeverityUnknown:  "\033[0;37m", // grey
}

const colourReset = "\033[0m"

// PrintTable writes a sorted vulnerability table to w.
// Vulnerabilities are sorted by severity (most critical first),
// then alphabetically by package name for stable output.
func PrintTable(w io.Writer, result models.ScanResult, noColour bool) {
	vulns := sortedVulns(result.Vulnerabilities)

	// tabwriter aligns columns by padding with spaces.
	// The arguments are: minwidth, tabwidth, padding, padchar, flags.
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer tw.Flush()

	header := "SEVERITY\tCVSS\tID\tPACKAGE\tVERSION\tFIX\tSUMMARY\n"
	fmt.Fprint(tw, header)
	fmt.Fprint(tw, strings.Repeat("-", 100)+"\n")

	for _, v := range vulns {
		colour := ""
		reset := ""
		if !noColour {
			colour = severityColour[v.Severity]
			reset = colourReset
		}

		summary := v.Summary
		if len(summary) > 60 {
			summary = summary[:57] + "..."
		}
		fix := v.FixedIn
		if fix == "" {
			fix = "none known"
		}

		fmt.Fprintf(tw, "%s%s%s\t%.1f\t%s\t%s\t%s\t%s\t%s\n",
			colour, v.Severity, reset,
			v.CVSS,
			v.ID,
			v.AffectedPkg.Name,
			v.AffectedPkg.Version,
			fix,
			summary,
		)
	}

	fmt.Fprintf(w, "\nScanned %d packages across %d path(s). Found %d vulnerabilities.\n",
		result.TotalPackages,
		len(result.ScannedPaths),
		len(result.Vulnerabilities),
	)
}

// PrintSummary writes a one-line count broken down by severity.
func PrintSummary(w io.Writer, result models.ScanResult) {
	counts := make(map[models.Severity]int)
	for _, v := range result.Vulnerabilities {
		counts[v.Severity]++
	}
	fmt.Fprintf(w, "CRITICAL:%d  HIGH:%d  MEDIUM:%d  LOW:%d  UNKNOWN:%d\n",
		counts[models.SeverityCritical],
		counts[models.SeverityHigh],
		counts[models.SeverityMedium],
		counts[models.SeverityLow],
		counts[models.SeverityUnknown],
	)
}

// WriteJSON serialises the ScanResult as indented JSON to the file at path.
// This is useful for CI pipelines that parse the output programmatically.
func WriteJSON(path string, result models.ScanResult) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

// sortedVulns returns a new slice sorted: highest severity first,
// then by CVSS score descending, then by package name ascending.
// Sorting by multiple criteria is done with a single sort.Slice call
// using a comparison function that checks each criterion in order.
func sortedVulns(vulns []models.Vulnerability) []models.Vulnerability {
	out := make([]models.Vulnerability, len(vulns))
	copy(out, vulns)

	sort.Slice(out, func(i, j int) bool {
		ri := models.SeverityRank(out[i].Severity)
		rj := models.SeverityRank(out[j].Severity)
		if ri != rj {
			return ri > rj // higher rank first
		}
		if out[i].CVSS != out[j].CVSS {
			return out[i].CVSS > out[j].CVSS
		}
		return out[i].AffectedPkg.Name < out[j].AffectedPkg.Name
	})
	return out
}
