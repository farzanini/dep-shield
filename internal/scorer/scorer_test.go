package scorer

import (
	"testing"
	"time"

	"github.com/farzanini/dep-shield/internal/models"
)

func newScorer() *scorer { return &scorer{} }

func TestScoreOneBonuses(t *testing.T) {
	s := newScorer()

	t.Run("unfixed adds 0.5", func(t *testing.T) {
		v := s.scoreOne(models.Vulnerability{CVSS: 7.0}, ScoringContext{})
		if v.NormScore != 7.5 {
			t.Errorf("NormScore = %v, want 7.5", v.NormScore)
		}
		if v.FixedIn != "" {
			t.Error("FixedIn non-empty, want empty (unfixed)")
		}
	})

	t.Run("fixed direct dep adds 0.3 only", func(t *testing.T) {
		v := s.scoreOne(
			models.Vulnerability{CVSS: 7.0, FixedIn: "1.2.3"},
			ScoringContext{IsDirectDependency: true},
		)
		if v.NormScore != 7.3 {
			t.Errorf("NormScore = %v, want 7.3", v.NormScore)
		}
		if v.FixedIn == "" {
			t.Error("FixedIn empty, want set")
		}
	})

	t.Run("age bonus capped at 0.2", func(t *testing.T) {
		v := s.scoreOne(
			models.Vulnerability{CVSS: 5.0, FixedIn: "1.0.0"},
			ScoringContext{PublishedAt: time.Now().AddDate(-3, 0, 0)},
		)
		// 5.0 base + 0.2 age cap, no other bonuses.
		if v.NormScore != 5.2 {
			t.Errorf("NormScore = %v, want 5.2", v.NormScore)
		}
		if v.DaysSincePublished < 365 {
			t.Errorf("DaysSincePublished = %d, want >= 365", v.DaysSincePublished)
		}
	})

	t.Run("capped at 10", func(t *testing.T) {
		v := s.scoreOne(models.Vulnerability{CVSS: 9.9}, ScoringContext{IsDirectDependency: true})
		if v.NormScore != 10.0 {
			t.Errorf("NormScore = %v, want 10.0 cap", v.NormScore)
		}
	})
}

func TestScoreFiltersAndSorts(t *testing.T) {
	s := New(nil)

	vulns := []models.Vulnerability{
		{ID: "low", Severity: models.SeverityLow, CVSS: 2.0},
		{ID: "crit", Severity: models.SeverityCritical, CVSS: 9.5},
		{ID: "med", Severity: models.SeverityMedium, CVSS: 5.0},
	}

	result, err := s.Score(vulns, models.SeverityMedium)
	if err != nil {
		t.Fatalf("Score returned error: %v", err)
	}

	// "low" is filtered out; remaining sorted by descending normalised score.
	if len(result.Vulnerabilities) != 2 {
		t.Fatalf("got %d vulns, want 2", len(result.Vulnerabilities))
	}
	if result.Vulnerabilities[0].ID != "crit" {
		t.Errorf("first = %q, want crit (highest risk first)", result.Vulnerabilities[0].ID)
	}
	if result.Vulnerabilities[1].ID != "med" {
		t.Errorf("second = %q, want med", result.Vulnerabilities[1].ID)
	}
}
