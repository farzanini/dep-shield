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
	"fmt"
	"math"
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
	filtered := filterBySeverity(vulns, minSeverity)

	out := make([]models.Vulnerability, 0, len(filtered))
	for _, v := range filtered {
		// Derive the scoring context from data the CVE client and parser
		// already attached to the vulnerability, rather than an empty context.
		out = append(out, s.scoreOne(v, ScoringContext{
			PublishedAt:        v.Published,
			IsDirectDependency: v.AffectedPkg.Direct,
		}))
	}

	// Sort highest risk first.
	sort.Slice(out, func(i, j int) bool {
		return out[i].NormScore > out[j].NormScore
	})

	return models.ScanResult{Vulnerabilities: out}, nil
}

// scoreOne returns v with its scorer-computed fields (NormScore,
// DaysSincePublished, FixAdvice) populated. The input is copied by value, so
// the caller's vulnerability is left untouched.
func (s *scorer) scoreOne(v models.Vulnerability, sctx ScoringContext) models.Vulnerability {
	hasFix := v.FixedIn != ""

	// Contextual bonuses layered on top of the raw CVSS base score.
	base := v.CVSS
	bonus := 0.0
	if !hasFix {
		// Unfixed vulnerabilities are more dangerous — no upgrade path exists.
		bonus += 0.5
	}
	if sctx.IsDirectDependency {
		// Direct deps are more likely to sit in the critical path.
		bonus += 0.3
	}

	// Age bonus: older findings have had more time to be exploited.
	// Scales linearly up to a +0.2 cap at one year and beyond.
	daysSince := 0
	if !sctx.PublishedAt.IsZero() {
		daysSince = int(time.Since(sctx.PublishedAt).Hours() / 24)
		if daysSince < 0 {
			daysSince = 0
		}
		bonus += math.Min(0.2, float64(daysSince)/365.0*0.2)
	}

	v.NormScore = math.Min(base+bonus, 10.0)
	v.DaysSincePublished = daysSince
	v.FixAdvice = buildFixAdvice(v)
	return v
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
