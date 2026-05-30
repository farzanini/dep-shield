// Package scorer assigns a final RiskScore to each vulnerability and filters
// the list down to the caller-supplied minimum severity.
//
// Why a separate scorer package?
// The CVE databases (OSV, GitHub) return raw data.  Scoring adds business
// logic on top: combining CVSS with contextual signals (is the package
// reachable? is a fix available? how old is the finding?) to produce an
// actionable priority rank.  Keeping this logic separate means the scan
// pipeline can swap scoring algorithms without touching the CVE client.
package scorer

import (
	"context"
	"fmt"
	"sort"
	"time"

	"go.uber.org/zap"

	"github.com/dep-shield/dep-shield/internal/models"
)

// ── Public interfaces ─────────────────────────────────────────────────────────

// Scorer processes a slice of raw vulnerabilities and returns a ScanResult
// with the findings scored, sorted, and filtered.
type Scorer interface {
	// Score filters vulns to those at or above minSeverity, assigns a
	// RiskScore to each, sorts them by descending risk, and wraps them in
	// a ScanResult.
	Score(vulns []models.Vulnerability, minSeverity models.Severity) (models.ScanResult, error)
}

// ── Data types ────────────────────────────────────────────────────────────────

// RiskScore is an enriched view of a single vulnerability.
// It extends models.Vulnerability with fields that are computed during scoring
// rather than fetched from the CVE database.
type RiskScore struct {
	models.Vulnerability

	// NormalisedScore is a 0–10 float that combines CVSS with contextual
	// signals.  Higher is worse.
	NormalisedScore float64

	// HasFix is true when FixedIn is non-empty.
	// Pre-computed here so templates and table renderers don't need to repeat
	// the string-empty check.
	HasFix bool

	// DaysSincePublished is the age of the advisory in days.
	// Older unfixed vulnerabilities are considered higher risk because they
	// have had more time to be exploited.
	DaysSincePublished int

	// FixAdvice is a human-readable upgrade suggestion, e.g.
	// "Upgrade lodash from 4.17.20 to 4.17.21"
	FixAdvice string
}

// ScoringContext carries signals that influence scoring beyond raw CVSS.
// Fields are optional; zero values cause that signal to be ignored.
type ScoringContext struct {
	// PublishedAt is when the advisory was first published.
	// Used to compute DaysSincePublished.
	PublishedAt time.Time

	// IsDirectDependency is true when the package appears directly in the
	// user's lockfile (vs. being a transitive dependency).
	// Direct deps are scored slightly higher because they are more likely to
	// be in the critical path.
	IsDirectDependency bool
}

// ── Scorer implementation ─────────────────────────────────────────────────────

type scorer struct {
	log *zap.Logger
}

// New constructs a Scorer.
func New(log *zap.Logger) Scorer {
	if log == nil {
		log = zap.NewNop()
	}
	return &scorer{log: log}
}

// Score implements Scorer.
func (s *scorer) Score(
	vulns []models.Vulnerability,
	minSeverity models.Severity,
) (models.ScanResult, error) {
	// TODO: implement
	//   1. filter vulns where SeverityRank(v.Severity) >= SeverityRank(minSeverity)
	//   2. call scoreOne(v) for each remaining vuln
	//   3. sort by NormalisedScore descending
	//   4. wrap in models.ScanResult

	filtered := filterBySeverity(vulns, minSeverity)
	scored := make([]RiskScore, 0, len(filtered))
	for _, v := range filtered {
		rs, err := s.scoreOne(v, ScoringContext{})
		if err != nil {
			s.log.Warn("scoring failed for vuln",
				zap.String("id", v.ID), zap.Error(err))
			continue
		}
		scored = append(scored, rs)
	}

	// Sort highest risk first.
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].NormalisedScore > scored[j].NormalisedScore
	})

	// Flatten back to []models.Vulnerability for the ScanResult.
	out := make([]models.Vulnerability, len(scored))
	for i, rs := range scored {
		out[i] = rs.Vulnerability
	}

	return models.ScanResult{Vulnerabilities: out}, nil
}

// scoreOne computes a RiskScore for a single vulnerability.
// TODO: implement the scoring formula described below.
func (s *scorer) scoreOne(v models.Vulnerability, sctx ScoringContext) (RiskScore, error) {
	// TODO: implement scoring formula:
	//
	//   base   = v.CVSS  (0–10)
	//   bonus  += 0.5 if no fix is available (unfixed = more dangerous)
	//   bonus  += 0.3 if sctx.IsDirectDependency
	//   bonus  += min(0.2, daysSince/365*0.2) for age
	//   capped at 10.0
	//
	//   NormalisedScore = min(base + bonus, 10.0)
	//   FixAdvice = "Upgrade <name> from <current> to <fixed>" if HasFix
	//             = "No fix available; consider removing or replacing <name>"

	_ = sctx
	_ = fmt.Sprintf // import kept alive
	_ = context.Background // import kept alive
	_ = time.Since // import kept alive

	rs := RiskScore{
		Vulnerability:   v,
		NormalisedScore: v.CVSS, // placeholder until TODO is implemented
		HasFix:          v.FixedIn != "",
		FixAdvice:       buildFixAdvice(v),
	}
	return rs, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// filterBySeverity returns only vulnerabilities at or above minSeverity.
func filterBySeverity(vulns []models.Vulnerability, min models.Severity) []models.Vulnerability {
	minRank := models.SeverityRank(min)
	out := make([]models.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if models.SeverityRank(v.Severity) >= minRank {
			out = append(out, v)
		}
	}
	return out
}

// buildFixAdvice produces a one-line fix suggestion string.
// TODO: enrich with registry links once the parser provides package metadata.
func buildFixAdvice(v models.Vulnerability) string {
	if v.FixedIn == "" {
		return fmt.Sprintf(
			"No fix available — consider replacing %s", v.AffectedPkg.Name)
	}
	return fmt.Sprintf(
		"Upgrade %s from %s to %s",
		v.AffectedPkg.Name,
		v.AffectedPkg.Version,
		v.FixedIn,
	)
}
