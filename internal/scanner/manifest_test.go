package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dep-shield/dep-shield/internal/models"
)

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestManifestHits(t *testing.T) {
	root := t.TempDir()
	// npm project (lockfile, no node_modules)
	npmDir := filepath.Join(root, "web")
	mustWriteFile(t, filepath.Join(npmDir, "package-lock.json"), `{"lockfileVersion":3,"packages":{}}`)
	// go project
	goDir := filepath.Join(root, "svc")
	mustWriteFile(t, filepath.Join(goDir, "go.mod"), "module x\n")
	// node_modules subtree should be pruned, not double-counted
	mustWriteFile(t, filepath.Join(npmDir, "node_modules", "left-pad", "package.json"), `{"name":"left-pad"}`)

	hits := ManifestHits(context.Background(), root, 8)

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

func TestMergeHits(t *testing.T) {
	base := []DirHit{{Path: "/a/node_modules", Ecosystem: models.EcosystemNPM}}
	extra := []DirHit{
		{Path: "/a/node_modules", Ecosystem: models.EcosystemNPM}, // dup — dropped
		{Path: "/b", Ecosystem: models.EcosystemGo},               // new — kept
	}
	out := MergeHits(base, extra)
	if len(out) != 2 {
		t.Fatalf("got %d hits, want 2: %+v", len(out), out)
	}
}
