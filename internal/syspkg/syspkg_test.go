package syspkg

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/farzanini/dep-shield/internal/models"
)

func TestReadOSReleaseAndEcosystem(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantEco string
		wantOK  bool
	}{
		{
			name:    "debian 12",
			content: "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
			wantEco: "Debian:12",
			wantOK:  true,
		},
		{
			name:    "ubuntu 22.04",
			content: "ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n",
			wantEco: "Ubuntu:22.04",
			wantOK:  true,
		},
		{
			name:    "fedora unsupported by dpkg mapping",
			content: "ID=fedora\nVERSION_ID=39\n",
			wantOK:  false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "os-release")
			if err := os.WriteFile(path, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			rel, err := readOSRelease(path)
			if err != nil {
				t.Fatalf("readOSRelease: %v", err)
			}
			eco, ok := osvDebianEcosystem(rel)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (rel=%+v)", ok, c.wantOK, rel)
			}
			if ok && eco != c.wantEco {
				t.Errorf("eco = %q, want %q", eco, c.wantEco)
			}
		})
	}
}

func TestParseDpkgOutput(t *testing.T) {
	out := "" +
		"bash\t5.2.15-2+b7\tinstall ok installed\n" +
		"libssl3\t3.0.11-1~deb12u2\tinstall ok installed\n" +
		"removed-pkg\t1.0\tdeinstall ok config-files\n" + // must be dropped
		"malformed-line-without-tabs\n" + // must be skipped
		"\n"
	pkgs := parseDpkgOutput([]byte(out), models.Ecosystem("Debian:12"))

	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "bash" || pkgs[0].Version != "5.2.15-2+b7" {
		t.Errorf("pkg[0] = %+v", pkgs[0])
	}
	if pkgs[1].Ecosystem != "Debian:12" || !pkgs[1].Direct {
		t.Errorf("pkg[1] ecosystem/direct wrong: %+v", pkgs[1])
	}
}

func TestParseApkDB(t *testing.T) {
	db := "" +
		"C:Q1abc\nP:musl\nV:1.2.4-r2\nA:x86_64\n\n" +
		"C:Q1def\nP:busybox\nV:1.36.1-r5\nA:x86_64\n\n" +
		"C:Q1ghi\nP:curl\nV:8.5.0-r0\n" // final record, no trailing blank line
	pkgs := parseApkDB([]byte(db), models.Ecosystem("Alpine:v3.19"))

	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3: %+v", len(pkgs), pkgs)
	}
	want := map[string]string{"musl": "1.2.4-r2", "busybox": "1.36.1-r5", "curl": "8.5.0-r0"}
	for _, p := range pkgs {
		if want[p.Name] != p.Version {
			t.Errorf("%s = %q, want %q", p.Name, p.Version, want[p.Name])
		}
		if p.Ecosystem != "Alpine:v3.19" {
			t.Errorf("%s ecosystem = %q", p.Name, p.Ecosystem)
		}
	}
}

func TestAlpineEcosystem(t *testing.T) {
	got, err := alpineEcosystem("3.19.1\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Alpine:v3.19" {
		t.Errorf("got %q, want Alpine:v3.19", got)
	}
	if _, err := alpineEcosystem("garbage"); err == nil {
		t.Error("expected error for unparseable alpine-release")
	}
}

func TestParseBrewOutput(t *testing.T) {
	out := "curl 8.20.0\nopenssl@3 3.2.1 3.3.0\nbat 0.26.1\n\n"
	pkgs := parseBrewOutput([]byte(out))

	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3: %+v", len(pkgs), pkgs)
	}
	// Multi-version line keeps the last (current) version.
	var openssl models.Package
	for _, p := range pkgs {
		if p.Name == "openssl@3" {
			openssl = p
		}
		if p.Ecosystem != models.EcosystemHomebrew {
			t.Errorf("%s ecosystem = %q, want Homebrew", p.Name, p.Ecosystem)
		}
	}
	if openssl.Version != "3.3.0" {
		t.Errorf("openssl@3 version = %q, want 3.3.0", openssl.Version)
	}
}

// TestDpkgCollectorWithFakeRunner exercises Collect end-to-end with injected
// os-release + command output, so the parsing path is covered without dpkg.
func TestDpkgCollectorWithFakeRunner(t *testing.T) {
	osRel := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(osRel, []byte("ID=debian\nVERSION_ID=12\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &dpkgCollector{
		osReleasePath: osRel,
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte("bash\t5.2.15\tinstall ok installed\n"), nil
		},
	}
	pkgs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Ecosystem != "Debian:12" {
		t.Fatalf("unexpected packages: %+v", pkgs)
	}
}
