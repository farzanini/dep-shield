package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

// ── Remote git repositories ───────────────────────────────────────────────────

// cloneRepo shallow-clones rawURL into a fresh temp directory and returns that
// directory plus a cleanup func the caller must always defer. token, when
// non-empty, is injected for HTTPS clones of private repositories; SSH URLs
// (git@…) authenticate via the user's existing SSH keys and ignore token.
//
// The clone is --depth 1 --single-branch so we fetch only what we need. The
// token is never logged: any error output has it redacted first.
func cloneRepo(ctx context.Context, rawURL, token string, log *zap.Logger) (dir string, cleanup func(), err error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", func() {}, fmt.Errorf("no repository URL provided")
	}
	if _, err := exec.LookPath("git"); err != nil {
		return "", func() {}, fmt.Errorf("git is not installed or not on PATH")
	}

	cloneURL, err := buildCloneURL(rawURL, token)
	if err != nil {
		return "", func() {}, err
	}

	tmp, err := os.MkdirTemp("", "dep-shield-clone-")
	if err != nil {
		return "", func() {}, fmt.Errorf("cannot create temp directory: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tmp) }

	// Fast path: a blobless, sparse checkout that fetches only dependency
	// manifests. On a large repo this transfers a handful of small files plus
	// tree metadata instead of every blob at HEAD.
	if err := sparseCloneManifests(ctx, cloneURL, tmp, token); err == nil {
		log.Info("cloned repository (sparse manifests)", zap.String("dir", tmp))
		return tmp, cleanup, nil
	} else {
		// Partial clone isn't supported by every server or older git; fall back
		// to a full shallow clone so scanning still works (just less cheaply).
		log.Warn("sparse clone unavailable; falling back to full shallow clone",
			zap.String("reason", err.Error()))
		if rmErr := os.RemoveAll(tmp); rmErr != nil {
			cleanup()
			return "", func() {}, fmt.Errorf("cannot reset temp directory: %w", rmErr)
		}
		if mkErr := os.MkdirAll(tmp, 0o755); mkErr != nil {
			return "", func() {}, fmt.Errorf("cannot recreate temp directory: %w", mkErr)
		}
	}

	cmd := exec.CommandContext(ctx, "git", "clone",
		"--depth", "1", "--single-branch", "--no-tags",
		cloneURL, tmp)
	// GIT_TERMINAL_PROMPT=0 makes git fail fast instead of hanging on an
	// interactive username/password prompt for a private or missing repo.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=echo")

	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		cleanup()
		msg := redactToken(string(out), token)
		if msg == "" {
			msg = runErr.Error()
		}
		return "", func() {}, fmt.Errorf("git clone failed: %s", strings.TrimSpace(msg))
	}

	log.Info("cloned repository", zap.String("dir", tmp))
	return tmp, cleanup, nil
}

// sparseManifestFiles are the files the parsers actually read. It is a superset
// of manifestFiles: a sparse checkout must also pull each manifest's companion
// files (go.sum beside go.mod, package.json beside a lockfile) or the parser
// would find the directory but no packages inside it.
var sparseManifestFiles = []string{
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "package.json",
	"go.mod", "go.sum",
	"Cargo.lock",
	"Pipfile.lock", "poetry.lock", "requirements.txt",
}

// sparseCloneManifests performs a blobless, no-checkout clone and then checks
// out only sparseManifestFiles. It returns an error (with the token redacted)
// when any git step fails — the caller then falls back to a full clone.
//
// The three steps:
//  1. clone --filter=blob:none --no-checkout  → fetch commit + tree objects only
//  2. sparse-checkout set --no-cone <files>   → restrict the working tree
//  3. checkout                                → fetch just the matching blobs
func sparseCloneManifests(ctx context.Context, cloneURL, dir, token string) error {
	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=echo")
		out, err := cmd.CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(redactToken(string(out), token))
			if msg == "" {
				msg = err.Error()
			}
			return fmt.Errorf("git %s: %s", args[0], msg)
		}
		return nil
	}

	if err := run("clone", "--depth", "1", "--single-branch", "--no-tags",
		"--filter=blob:none", "--no-checkout", cloneURL, dir); err != nil {
		return err
	}
	setArgs := append([]string{"-C", dir, "sparse-checkout", "set", "--no-cone"}, sparseManifestFiles...)
	if err := run(setArgs...); err != nil {
		return err
	}
	return run("-C", dir, "checkout")
}

// buildCloneURL validates the URL scheme and, for HTTPS, injects the token as
// basic-auth userinfo. Only http(s) and SSH (ssh:// or scp-style git@host:…)
// are accepted; anything else (file://, etc.) is rejected.
func buildCloneURL(rawURL, token string) (string, error) {
	// scp-style SSH: git@github.com:owner/repo.git — not a parseable URL.
	if strings.HasPrefix(rawURL, "git@") || strings.HasPrefix(rawURL, "ssh://") {
		return rawURL, nil // SSH auth uses the user's keys; token is ignored.
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid repository URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		if token != "" {
			// GitHub/GitLab accept a token as the username with basic auth.
			u.User = url.UserPassword(token, "x-oauth-basic")
		}
		return u.String(), nil
	default:
		return "", fmt.Errorf("unsupported URL scheme %q — use https:// or git@…", u.Scheme)
	}
}

// redactToken removes the token from text so it never reaches logs or the UI.
func redactToken(text, token string) string {
	if token == "" {
		return text
	}
	return strings.ReplaceAll(text, token, "***")
}

// looksLikeGitURL reports whether s should be treated as a remote repo URL
// rather than a local filesystem path.
func looksLikeGitURL(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "ssh://") ||
		strings.HasPrefix(s, "git@")
}
