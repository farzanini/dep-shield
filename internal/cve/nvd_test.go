package cve

import (
	"testing"

	"github.com/farzanini/dep-shield/internal/models"
)

func TestNVDProduct(t *testing.T) {
	cases := map[string]string{
		"openssl":      "openssl",
		"openssl@3":    "openssl",
		"python@3.12":  "python",
		"FFmpeg":       "ffmpeg",
		"  curl  ":     "curl",
	}
	for in, want := range cases {
		if got := nvdProduct(in); got != want {
			t.Errorf("nvdProduct(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConvertNVDCVE(t *testing.T) {
	raw := nvdCVE{
		ID:        "CVE-2021-4044",
		Published: "2022-01-14T21:15:00.000",
		Descriptions: []nvdLangString{
			{Lang: "es", Value: "descripción"},
			{Lang: "en", Value: "OpenSSL internally calls X509_verify_cert()..."},
		},
		References: []struct {
			URL string `json:"url"`
		}{{URL: "https://example.com/advisory"}},
	}
	raw.Metrics.V31 = []nvdMetric{{}}
	raw.Metrics.V31[0].CVSSData.BaseScore = 7.5
	raw.Metrics.V31[0].CVSSData.BaseSeverity = "HIGH"

	pkg := models.Package{Name: "openssl@3", Version: "3.0.0", Ecosystem: models.EcosystemHomebrew}
	v := convertNVDCVE(raw, pkg)

	if v.ID != "CVE-2021-4044" {
		t.Errorf("ID = %q", v.ID)
	}
	if v.CVSS != 7.5 || v.Severity != models.SeverityHigh {
		t.Errorf("score/severity = %v/%v, want 7.5/HIGH", v.CVSS, v.Severity)
	}
	if v.Summary[:7] != "OpenSSL" {
		t.Errorf("summary picked wrong language: %q", v.Summary)
	}
	if v.Published.IsZero() {
		t.Error("published time not parsed")
	}
	if v.AffectedPkg.Name != "openssl@3" {
		t.Errorf("affected pkg not preserved: %+v", v.AffectedPkg)
	}
}

// TestNVDScorePrefersV31 checks the v3.1 > v3.0 > v2 preference.
func TestNVDScorePrefersV31(t *testing.T) {
	var m nvdMetrics
	m.V2 = []nvdMetric{{}}
	m.V2[0].CVSSData.BaseScore = 4.0
	m.V30 = []nvdMetric{{}}
	m.V30[0].CVSSData.BaseScore = 6.0
	m.V31 = []nvdMetric{{}}
	m.V31[0].CVSSData.BaseScore = 9.1
	m.V31[0].CVSSData.BaseSeverity = "CRITICAL"

	score, sev := nvdScore(m)
	if score != 9.1 || sev != models.SeverityCritical {
		t.Errorf("got %v/%v, want 9.1/CRITICAL", score, sev)
	}
}
