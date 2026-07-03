package cve

import (
	"testing"

	"github.com/farzanini/dep-shield/internal/models"
)

func TestCVSSVectorToScore(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   float64
	}{
		{"critical network RCE", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"scope changed maxes out", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"no prefix still parses", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"no impact is zero", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
		{"empty", "", 0},
		{"garbage", "not-a-vector", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cvssVectorToScore(tc.vector); got != tc.want {
				t.Errorf("cvssVectorToScore(%q) = %v, want %v", tc.vector, got, tc.want)
			}
		})
	}
}

func TestScoreToSeverity(t *testing.T) {
	cases := []struct {
		score float64
		want  models.Severity
	}{
		{9.8, models.SeverityCritical},
		{9.0, models.SeverityCritical},
		{7.5, models.SeverityHigh},
		{4.0, models.SeverityMedium},
		{2.0, models.SeverityLow},
		{0, models.SeverityUnknown},
	}
	for _, tc := range cases {
		if got := scoreToSeverity(tc.score); got != tc.want {
			t.Errorf("scoreToSeverity(%v) = %v, want %v", tc.score, got, tc.want)
		}
	}
}

func TestConvertOSVVuln(t *testing.T) {
	pkg := models.Package{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNPM}

	v := osvVuln{
		ID:      "GHSA-xxxx",
		Aliases: []string{"CVE-2021-23337"},
		Summary: "Command injection in lodash",
		Severity: []osvSeverity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		Affected: []osvAffected{{
			Ranges: []osvRange{{
				Type:   "SEMVER",
				Events: []osvEvent{{Fixed: "4.17.21"}},
			}},
		}},
		Refs: []osvRef{{URL: "https://example.com/advisory"}},
	}

	got := convertOSVVuln(v, pkg)

	if got.ID != "CVE-2021-23337" {
		t.Errorf("ID = %q, want CVE alias to be preferred", got.ID)
	}
	if got.CVSS != 9.8 {
		t.Errorf("CVSS = %v, want 9.8", got.CVSS)
	}
	if got.Severity != models.SeverityCritical {
		t.Errorf("Severity = %v, want CRITICAL", got.Severity)
	}
	if got.FixedIn != "4.17.21" {
		t.Errorf("FixedIn = %q, want 4.17.21", got.FixedIn)
	}
	if len(got.References) != 1 || got.References[0] != "https://example.com/advisory" {
		t.Errorf("References = %v, want one advisory URL", got.References)
	}
	if got.AffectedPkg != pkg {
		t.Errorf("AffectedPkg = %+v, want %+v", got.AffectedPkg, pkg)
	}
}

func TestOSVScoreFallbacks(t *testing.T) {
	// Explicit database_specific.cvss wins over everything.
	v := osvVuln{}
	v.DatabaseSpecific.CVSS = 7.1
	if got := osvScore(v); got != 7.1 {
		t.Errorf("osvScore explicit = %v, want 7.1", got)
	}

	// Severity label fallback when no vector or numeric score is present.
	v = osvVuln{}
	v.DatabaseSpecific.Severity = "HIGH"
	if got := osvScore(v); got != 7.5 {
		t.Errorf("osvScore label fallback = %v, want 7.5", got)
	}
}
