package reporter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dep-shield/dep-shield/internal/models"
)

func sampleResult() models.ScanResult {
	return models.ScanResult{
		ScannedPaths:  []string{"."},
		TotalPackages: 3,
		Vulnerabilities: []models.Vulnerability{{
			ID:          "CVE-2021-23337",
			Summary:     "Command injection in lodash",
			Severity:    models.SeverityCritical,
			CVSS:        9.8,
			FixedIn:     "4.17.21",
			AffectedPkg: models.Package{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNPM},
		}},
	}
}

func TestJSONReporterRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	rep := New(Options{Format: string(FormatJSON)})
	if err := rep.Write(&buf, sampleResult()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var decoded models.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(decoded.Vulnerabilities) != 1 || decoded.Vulnerabilities[0].ID != "CVE-2021-23337" {
		t.Errorf("round-tripped result mismatch: %+v", decoded)
	}
}

func TestTableReporterContainsData(t *testing.T) {
	var buf bytes.Buffer
	rep := New(Options{Format: string(FormatTable), NoColour: true})
	if err := rep.Write(&buf, sampleResult()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"CVE-2021-23337", "lodash", "4.17.21", "CRITICAL:1", "Found 1 vulnerability"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q\n---\n%s", want, out)
		}
	}
}

func TestTableReporterEmpty(t *testing.T) {
	var buf bytes.Buffer
	rep := New(Options{Format: string(FormatTable), NoColour: true})
	if err := rep.Write(&buf, models.ScanResult{TotalPackages: 5}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(buf.String(), "No known vulnerabilities") {
		t.Errorf("empty result should report clean scan, got: %s", buf.String())
	}
}

// WriteFile must honour its format argument even when the reporter was built for
// a different format (e.g. a table reporter exporting a JSON file).
func TestWriteFileDispatchesByFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")

	rep := New(Options{Format: string(FormatTable)}) // table reporter...
	if err := rep.WriteFile(path, FormatJSON, sampleResult()); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var decoded models.ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Errorf("WriteFile(FormatJSON) did not produce JSON: %v\n%s", err, data)
	}
}
