package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dep-shield/dep-shield/internal/models"
)

func TestBuildCloneURL(t *testing.T) {
	cases := []struct {
		name, url, token, want string
		wantErr                bool
	}{
		{"https no token", "https://github.com/o/r.git", "", "https://github.com/o/r.git", false},
		{"https with token", "https://github.com/o/r.git", "tok123", "https://tok123:x-oauth-basic@github.com/o/r.git", false},
		{"scp ssh untouched", "git@github.com:o/r.git", "tok", "git@github.com:o/r.git", false},
		{"ssh scheme untouched", "ssh://git@host/o/r.git", "tok", "ssh://git@host/o/r.git", false},
		{"file scheme rejected", "file:///etc/passwd", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := buildCloneURL(c.url, c.token)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestRedactToken(t *testing.T) {
	in := "fatal: could not read from https://ghp_secret:x@github.com/o/r"
	if out := redactToken(in, "ghp_secret"); out == in || filepath.Base(out) == "" {
		t.Errorf("token not redacted: %q", out)
	}
}

func TestManifestHits(t *testing.T) {
	root := t.TempDir()
	// npm project (lockfile, no node_modules)
	npmDir := filepath.Join(root, "web")
	mustWrite(t, filepath.Join(npmDir, "package-lock.json"), `{"lockfileVersion":3,"packages":{}}`)
	// go project
	goDir := filepath.Join(root, "svc")
	mustWrite(t, filepath.Join(goDir, "go.mod"), "module x\n")
	// node_modules subtree should be pruned, not double-counted
	mustWrite(t, filepath.Join(npmDir, "node_modules", "left-pad", "package.json"), `{"name":"left-pad"}`)

	hits := manifestHits(root, 8)

	got := map[string]models.Ecosystem{}
	for _, h := range hits {
		got[h.Path] = h.Ecosystem
	}
	// npm hit must point at <project>/node_modules so the parser finds the lockfile in the parent.
	wantNpm := filepath.Join(npmDir, "node_modules")
	if got[wantNpm] != models.EcosystemNPM {
		t.Errorf("expected npm hit at %q, got hits: %+v", wantNpm, hits)
	}
	if got[goDir] != models.EcosystemGo {
		t.Errorf("expected Go hit at %q, got hits: %+v", goDir, hits)
	}
	// Exactly one npm hit (deduped, not one per lockfile-in-node_modules).
	npmCount := 0
	for _, e := range got {
		if e == models.EcosystemNPM {
			npmCount++
		}
	}
	if npmCount != 1 {
		t.Errorf("expected 1 npm hit, got %d: %+v", npmCount, hits)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
