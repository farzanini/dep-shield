// Package models holds every shared data type used across dep-shield.
// Nothing in here does work — it only describes shape.
package models

import "time"

// Ecosystem identifies which package manager a dependency belongs to.
// Using a named string type (not plain string) lets the compiler catch
// accidental mix-ups like passing "npm" where an Ecosystem is expected.
type Ecosystem string

const (
	EcosystemNPM   Ecosystem = "npm"
	EcosystemGo    Ecosystem = "Go"
	EcosystemCargo Ecosystem = "crates.io"
	EcosystemPyPI  Ecosystem = "PyPI"
)

// Package is one discovered dependency — name, version, where it lives on disk.
type Package struct {
	Name      string
	Version   string
	Ecosystem Ecosystem
	// Path is the folder where this package was found, useful for reports.
	Path string

	// Direct is true when the package is declared directly in the project's
	// manifest (vs. being pulled in transitively). The scorer weights direct
	// dependencies slightly higher because they sit in the critical path.
	Direct bool
	// Depth is the dependency-graph distance: 1 = direct, 2 = first-level
	// transitive, etc. 0 means the parser could not determine it.
	Depth int
}

// Severity maps to the OSV / CVSS severity strings.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

// SeverityRank returns a numeric rank so we can sort vulnerabilities
// from most to least severe. Higher number = more severe.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Vulnerability is one CVE / advisory entry returned by a database.
//
// The first block of fields is populated by the CVE client from the upstream
// advisory. The second block is filled in later by the scorer — they are zero
// until Score() runs.
type Vulnerability struct {
	ID          string   // e.g. "CVE-2021-44228" or "GHSA-xxxx-xxxx-xxxx"
	Summary     string   // short human-readable description
	Severity    Severity
	CVSS        float64   // 0.0–10.0; 0 means not scored
	FixedIn     string    // version that resolves this, "" if unknown
	References  []string  // URLs to advisories / patches
	AffectedPkg Package   // the specific package this vuln belongs to
	Published   time.Time // when the advisory was first published; zero if unknown

	// ── Scorer-computed fields (zero until Score() runs) ──────────────────────

	// NormScore is the 0–10 risk score: CVSS plus contextual bonuses (missing
	// fix, direct dependency, advisory age). Used for ranking; higher is worse.
	NormScore float64
	// DaysSincePublished is the advisory age in days, derived from Published.
	DaysSincePublished int
	// FixAdvice is a human-readable remediation line, e.g.
	// "Upgrade lodash from 4.17.20 to 4.17.21".
	FixAdvice string
}

// ScanResult is the complete output of one scan run.
type ScanResult struct {
	ScannedPaths   []string
	TotalPackages  int
	Vulnerabilities []Vulnerability
}
