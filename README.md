# dep-shield

**dep-shield** scans your project's dependencies for known CVEs across every ecosystem at once — npm, Go, PyPI, and Cargo — in a single command.

```
$ dep-shield scan .

Scanning /home/user/my-project
  ✓ npm        142 packages
  ✓ Go          38 packages
  ✓ PyPI        61 packages

┌─────────────────────────────────┬─────────┬──────────┬───────────┐
│ Package                         │ Version │ Severity │ CVE       │
├─────────────────────────────────┼─────────┼──────────┼───────────┤
│ lodash (npm)                    │ 4.17.19 │ CRITICAL │ CVE-2021… │
│ golang.org/x/net (Go)           │ 0.0.1   │ HIGH     │ CVE-2022… │
│ pillow (PyPI)                   │ 9.0.0   │ MEDIUM   │ CVE-2023… │
└─────────────────────────────────┴─────────┴──────────┴───────────┘

3 vulnerabilities found across 241 packages.
```

---

## Install

### Linux and macOS — one command

```bash
curl -fsSL https://raw.githubusercontent.com/dep-shield/dep-shield/main/install.sh | sh
```

The script auto-detects your OS and CPU architecture (amd64 or arm64), downloads the right binary from the [latest GitHub Release](https://github.com/dep-shield/dep-shield/releases/latest), verifies its sha256 checksum, and places the binary in `/usr/local/bin`.

**Pin to a specific version:**

```bash
curl -fsSL https://raw.githubusercontent.com/dep-shield/dep-shield/main/install.sh | sh -s -- --version v1.2.3
```

**Install to a custom directory:**

```bash
curl -fsSL https://raw.githubusercontent.com/dep-shield/dep-shield/main/install.sh | sh -s -- --install-dir ~/.local/bin
```

### Windows — PowerShell

```powershell
irm https://raw.githubusercontent.com/dep-shield/dep-shield/main/install.ps1 | iex
```

*(PowerShell 5.1+ or PowerShell 7+ required.)*

### Manual download

Download a pre-built binary for your platform from the [Releases page](https://github.com/dep-shield/dep-shield/releases):

| Platform | Architecture | File |
|---|---|---|
| Linux | amd64 (x86-64) | `dep-shield_*_linux_amd64.tar.gz` |
| Linux | arm64 (Graviton, Ampere) | `dep-shield_*_linux_arm64.tar.gz` |
| macOS | amd64 (Intel) | `dep-shield_*_darwin_amd64.tar.gz` |
| macOS | arm64 (Apple Silicon) | `dep-shield_*_darwin_arm64.tar.gz` |
| Windows | amd64 | `dep-shield_*_windows_amd64.zip` |

Each release includes `checksums.txt` (sha256). Verify before running:

```bash
sha256sum --check checksums.txt
```

### Build from source

```bash
git clone https://github.com/dep-shield/dep-shield.git
cd dep-shield
CGO_ENABLED=0 go build \
  -ldflags="-s -w -X github.com/dep-shield/dep-shield/cmd.Version=$(git describe --tags --always)" \
  -o dep-shield .
```

Requires **Go 1.22+**. No C compiler. No external system libraries.

---

## Usage

### Scan a project directory

```bash
dep-shield scan /path/to/project

# Scan the current directory:
dep-shield scan .

# Exit with code 1 if any HIGH or CRITICAL vulnerabilities are found (useful in CI):
dep-shield scan . --fail-on high
```

dep-shield auto-detects which ecosystems are present by looking for lockfiles:

| Ecosystem | Files detected |
|---|---|
| npm | `package-lock.json`, `yarn.lock` |
| Go | `go.mod`, `go.sum` |
| PyPI | `Pipfile.lock`, `poetry.lock`, `requirements.txt` |
| Cargo | `Cargo.lock` |

### Scan system packages

Beyond project dependencies, dep-shield can scan packages installed by your OS package manager:

```bash
# Scan Homebrew (macOS) / dpkg/apt / apk (Linux):
dep-shield scan --system

# Combine with a project scan:
dep-shield scan /path/to/project --system
```

Linux distro packages are matched against OSV; Homebrew formulae are matched against NVD by CPE (set `NVD_API_KEY` for faster lookups).

### Generate a report

```bash
# JSON — machine-readable, for CI pipelines:
dep-shield report --format json > vulns.json

# Table — human-readable (default):
dep-shield report --format table
```

### Global flags

```
--timeout duration   abort scan after this duration (default 2m)
--offline            skip all network requests (no CVE data)
--log-level string   debug, info, warn, error (default "info")
```

---

## MCP server — scan from AI agents

dep-shield ships a [Model Context Protocol](https://modelcontextprotocol.io) server, so AI agents (Claude, and any MCP-compatible client) can scan projects and hosts for vulnerable packages as part of their work — e.g. auditing a repo they're editing and proposing the fixes.

Start it over stdio:

```bash
dep-shield mcp
```

### Configure a client

Most clients (Claude Desktop, etc.) use this config shape:

```json
{
  "mcpServers": {
    "dep-shield": {
      "command": "dep-shield",
      "args": ["mcp"],
      "env": { "GITHUB_TOKEN": "ghp_…", "NVD_API_KEY": "…" }
    }
  }
}
```

Use an absolute path to the binary if `dep-shield` isn't on the client's `PATH`. Both env vars are optional — `GITHUB_TOKEN` enriches results from the GitHub Advisory DB, `NVD_API_KEY` speeds up Homebrew lookups.

For **Claude Code**:

```bash
claude mcp add dep-shield -- dep-shield mcp
```

### Tools

| Tool | Arguments | Description |
|---|---|---|
| `scan_project` | `path` (required), `min_severity`, `ecosystems` | Scan a local project directory for vulnerable dependencies (npm, Go, Cargo, PyPI). |
| `scan_system_packages` | `min_severity` | Scan installed OS packages (Homebrew, dpkg/apt, apk). |

Both return a JSON object:

```json
{
  "scannedPaths": ["/path/to/project"],
  "totalPackages": 241,
  "vulnerabilityCount": 3,
  "severityCounts": { "CRITICAL": 1, "HIGH": 2 },
  "findings": [
    {
      "id": "CVE-2019-10744", "cve": "CVE-2019-10744",
      "package": "lodash", "version": "4.17.11", "ecosystem": "npm",
      "severity": "CRITICAL", "cvss": 9.1,
      "fixedIn": "4.17.12", "fixAdvice": "Upgrade lodash from 4.17.11 to 4.17.12",
      "summary": "Prototype pollution in lodash…"
    }
  ]
}
```

---

## CI Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security scan

on: [push, pull_request]

jobs:
  dep-shield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dep-shield
        run: |
          curl -fsSL https://raw.githubusercontent.com/dep-shield/dep-shield/main/install.sh | sh

      - name: Scan dependencies
        run: dep-shield scan . --fail-on high
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}   # optional: enriches results from GitHub Advisory DB
```

### GitLab CI

```yaml
security-scan:
  image: alpine:3.20
  before_script:
    - apk add --no-cache curl
    - curl -fsSL https://raw.githubusercontent.com/dep-shield/dep-shield/main/install.sh | sh
  script:
    - dep-shield scan . --fail-on high
```

---

## Data sources

dep-shield queries two vulnerability databases and merges the results:

| Source | Coverage | Authentication |
|---|---|---|
| [OSV.dev](https://osv.dev) | npm, Go, PyPI, Cargo, and 20+ more | None required |
| [GitHub Advisory Database](https://github.com/advisories) | npm, Go, PyPI, Cargo, Ruby, Java | `GITHUB_TOKEN` env var (optional; enriches data) |
| [NVD](https://nvd.nist.gov) | Homebrew formulae (CPE matching) | `NVD_API_KEY` env var (optional; raises the rate limit) |

Deduplication: when the same CVE appears in both sources, dep-shield keeps the entry with the higher CVSS score so the risk picture is never understated.

---

## Verifying a release

Every release publishes `checksums.txt` signed with the project's GPG key.

```bash
# 1. Download the binary and checksums
curl -fsSL -O https://github.com/dep-shield/dep-shield/releases/download/v1.2.3/dep-shield_v1.2.3_linux_amd64.tar.gz
curl -fsSL -O https://github.com/dep-shield/dep-shield/releases/download/v1.2.3/checksums.txt

# 2. Verify the sha256 checksum
sha256sum --check --ignore-missing checksums.txt

# 3. Extract and run
tar -xzf dep-shield_v1.2.3_linux_amd64.tar.gz
./dep-shield version
```

---

## Contributing

```bash
# Clone
git clone https://github.com/dep-shield/dep-shield.git
cd dep-shield

# Run all Go tests
go test ./...

# Run TypeScript tests (CVE module)
npm test

# Build a local snapshot (requires goreleaser)
goreleaser build --snapshot --clean
```

See [`docs/learning/`](docs/learning/) for a guided tour of the codebase.

---

## License

MIT © dep-shield contributors
