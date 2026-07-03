package main

import (
	"path/filepath"
	"testing"
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

