package models_test

import (
	"testing"

	"github.com/farzanini/dep-shield/internal/models"
)

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  models.Severity
		want int
	}{
		{models.SeverityCritical, 4},
		{models.SeverityHigh, 3},
		{models.SeverityMedium, 2},
		{models.SeverityLow, 1},
		{models.SeverityUnknown, 0},
		{"GARBAGE", 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			if got := models.SeverityRank(tt.sev); got != tt.want {
				t.Errorf("SeverityRank(%q) = %d, want %d", tt.sev, got, tt.want)
			}
		})
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	// CRITICAL must always rank higher than HIGH, HIGH > MEDIUM, etc.
	order := []models.Severity{
		models.SeverityUnknown,
		models.SeverityLow,
		models.SeverityMedium,
		models.SeverityHigh,
		models.SeverityCritical,
	}
	for i := 1; i < len(order); i++ {
		if models.SeverityRank(order[i]) <= models.SeverityRank(order[i-1]) {
			t.Errorf("expected %q rank > %q rank", order[i], order[i-1])
		}
	}
}
