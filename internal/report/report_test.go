package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dep-shield/dep-shield/internal/models"
	"github.com/dep-shield/dep-shield/internal/report"
)

func sampleResult() models.ScanResult {
	pkg := func(name string) models.Package {
		return models.Package{Name: name, Version: "1.0.0", Ecosystem: models.EcosystemNPM}
	}
	return models.ScanResult{
		ScannedPaths:  []string{"/tmp"},
		TotalPackages: 10,
		Vulnerabilities: []models.Vulnerability{
			{ID: "CVE-001", Severity: models.SeverityCritical, CVSS: 9.8, AffectedPkg: pkg("bad-pkg"), Summary: "Very bad"},
			{ID: "CVE-002", Severity: models.SeverityLow, CVSS: 2.0, AffectedPkg: pkg("meh-pkg"), Summary: "Meh"},
			{ID: "CVE-003", Severity: models.SeverityHigh, CVSS: 7.5, AffectedPkg: pkg("risky-pkg"), Summary: "Risky"},
		},
	}
}

func TestPrintTable_OrderedBySeverity(t *testing.T) {
	var buf bytes.Buffer
	report.PrintTable(&buf, sampleResult(), true /*noColour*/)
	out := buf.String()

	critPos := strings.Index(out, "CRITICAL")
	highPos := strings.Index(out, "HIGH")
	lowPos := strings.Index(out, "LOW")

	if critPos < 0 || highPos < 0 || lowPos < 0 {
		t.Fatalf("missing severity label in output:\n%s", out)
	}
	if !(critPos < highPos && highPos < lowPos) {
		t.Errorf("expected CRITICAL before HIGH before LOW, got positions %d %d %d", critPos, highPos, lowPos)
	}
}

func TestPrintTable_ContainsPackageNames(t *testing.T) {
	var buf bytes.Buffer
	report.PrintTable(&buf, sampleResult(), true)
	out := buf.String()

	for _, name := range []string{"bad-pkg", "risky-pkg", "meh-pkg"} {
		if !strings.Contains(out, name) {
			t.Errorf("output missing package %q", name)
		}
	}
}

func TestWriteJSON_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "report.json")

	original := sampleResult()
	if err := report.WriteJSON(path, original); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var got models.ScanResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TotalPackages != original.TotalPackages {
		t.Errorf("TotalPackages: got %d want %d", got.TotalPackages, original.TotalPackages)
	}
	if len(got.Vulnerabilities) != len(original.Vulnerabilities) {
		t.Errorf("Vulnerabilities length: got %d want %d", len(got.Vulnerabilities), len(original.Vulnerabilities))
	}
}

func TestPrintSummary_Counts(t *testing.T) {
	var buf bytes.Buffer
	report.PrintSummary(&buf, sampleResult())
	out := buf.String()

	// Expect "CRITICAL:1  HIGH:1  MEDIUM:0  LOW:1"
	for _, fragment := range []string{"CRITICAL:1", "HIGH:1", "LOW:1", "MEDIUM:0"} {
		if !strings.Contains(out, fragment) {
			t.Errorf("PrintSummary output missing %q\ngot: %s", fragment, out)
		}
	}
}
