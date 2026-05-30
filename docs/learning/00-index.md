# dep-shield — Learning Roadmap

> **Who this is for:** someone who knows at least one other language and wants
> to understand the dep-shield codebase from scratch.  No prior Go experience
> required.

---

## 1. Read this first

Go has a handful of ideas that appear everywhere in this codebase.  Trying to
read the code without them is like reading Spanish without knowing what "ser"
means.  Spend 20–30 minutes here before touching any `.go` file.

### The short list

| Concept | What it is | Where you'll see it in dep-shield |
|---|---|---|
| **Packages** | A folder = a package. `package scanner` at the top of every file. | Every `.go` file |
| **Exported vs unexported** | Capitalised name → public. `Scanner` is exported; `impl` is not. | `internal/scanner/scanner.go` |
| **Interfaces** | A set of method signatures. Any type that has those methods satisfies the interface — no `implements` keyword. | `Source`, `Scanner`, `Detector`, `Reporter`, `Scorer` |
| **Pointer receivers** | `func (c *Client) QueryAll(…)` — the method belongs to `*Client`. Read `*` as "pointer to". | Every method in the codebase |
| **`error` as a value** | Functions return `(result, error)`. The caller checks `if err != nil`. There are no exceptions. | Every function that does I/O |
| **`fmt.Errorf("…: %w", err)`** | Wraps an error with context. `%w` is Go's equivalent of `cause`. | `internal/parser/parser.go`, `internal/advisory/osv.go` |
| **`defer`** | Schedules a call to run when the surrounding function returns. Used for cleanup: `defer resp.Body.Close()`. | `internal/advisory/osv.go` |
| **Goroutines** | Lightweight threads. `go func() { … }()` starts one. | `internal/scanner/scanner.go`, `internal/advisory/client.go` |
| **Channels** | Typed pipes between goroutines. `make(chan T, N)` creates a buffered channel. | `internal/scanner/scanner.go` |
| **`context.Context`** | A cancellation signal threaded through every call chain. Always the first parameter when doing I/O. | Every public function that calls the network or filesystem |

### Recommended pre-reading (free, online)

These are the official Go resources, in the order most useful for this
codebase:

1. **[A Tour of Go](https://go.dev/tour/)** — basics, structs, interfaces,
   goroutines.  Takes ~2 hours.  Do sections 1–3 (Basics, Methods/Interfaces,
   Concurrency).
2. **[Effective Go — Error handling](https://go.dev/doc/effective_go#errors)**
   — one page.  Explains why Go uses return values for errors instead of
   exceptions.
3. **[Go by Example — Goroutines](https://gobyexample.com/goroutines)** and
   **[Channels](https://gobyexample.com/channels)** — runnable examples,
   2 minutes each.

### Our own guides

These guides are built around the actual dep-shield source files.  Read them
in order:

| Guide | Concepts covered | Source files |
|---|---|---|
| [01 — Project structure](01-project-structure.md) | `go.mod`, packages, modules, `main.go`, cobra CLI basics, struct methods, named types, `errors.Is`/`errors.As` | `go.mod`, `main.go`, `cmd/root.go`, `cmd/scan.go` |
| [02 — Scanner & concurrency](02-scanner-and-concurrency.md) | Interfaces, goroutine pools, `sync.WaitGroup`, buffered channels, `filepath.WalkDir`, `context.Context`, symlink deduplication with `sync.Map` | `internal/scanner/scanner.go` and siblings |
| [03 — Interfaces & parsers](03-interfaces-and-parsers.md) | Interfaces in depth, JSON struct tags, `bufio.Scanner`, `%w` error wrapping, table-driven tests, TOML state machine | `internal/parser/parser.go`, `internal/parser/parser_test.go` |
| [04 — HTTP & APIs](04-http-and-apis.md) | `http.Client` with timeouts, `context.WithTimeout`, pointer receivers, retry with exponential back-off and full jitter | `internal/advisory/osv.go`, `internal/cve/client.go`, `src/cve.ts` |

---

## 2. Follow this order

Reading the files in dependency order means you never encounter a concept
before it's been introduced.

```
go.mod                          ← 1. Start here: the module declaration
main.go                         ← 2. Entry point — only 8 lines
cmd/root.go                     ← 3. Cobra root command, flags, Version variable
cmd/scan.go                     ← 4. The scan sub-command: ties everything together
  │
  ├── internal/models/models.go ← 5. Pure data types — no logic, easy read
  │
  ├── internal/scanner/         ← 6. Filesystem walk and ecosystem detection
  │     scanner.go              │      (goroutines, channels, interfaces)
  │     npm.go                  │
  │     go_mod.go               │
  │     cargo.go                │
  │     pip.go                  │
  │
  ├── internal/parser/          ← 7. Lockfile parsing (JSON, TOML, plain text)
  │     parser.go               │
  │     parser_test.go          ← 7a. Read tests alongside the source
  │
  ├── internal/advisory/        ← 8. CVE lookups over HTTP
  │     client.go               │      (fan-out, deduplication)
  │     osv.go                  │      (JSON REST API)
  │     github.go               │      (GraphQL API)
  │
  ├── internal/cve/client.go    ← 9. Full CVE client with semaphore, worker pool
  │
  ├── internal/scorer/          ← 10. Risk scoring and sorting
  │     scorer.go
  │
  └── internal/reporter/        ← 11. Output formatting (table, JSON, HTML)
        reporter.go
```

### Why this order?

- `models.go` (step 5) defines `Package`, `Vulnerability`, and `ScanResult`.
  Every other package uses these types.  Read it first so later types make
  sense.
- The scanner (step 6) produces `[]models.Package` from the filesystem.  Read
  it before the parser because the parser sits downstream.
- The advisory clients (steps 8–9) are the most complex: they combine
  goroutines, HTTP, JSON, and error handling.  Reading them last means each
  individual piece is familiar.
- Tests (step 7a) should be read in parallel with the source file they test.
  `parser_test.go` contains the most instructive examples of table-driven
  tests in the project.

---

## 3. Concepts by file

Each row is one `.go` file.  The concepts column lists the Go ideas you'll
encounter *specifically in that file* — not things borrowed from imports.

| File | What it does | Go concepts demonstrated |
|---|---|---|
| `go.mod` | Module declaration and dependency list | Modules, `require` blocks, semantic versioning, `// indirect` annotations |
| `main.go` | Binary entry point | `package main`, `func main()`, `os.Exit`, importing internal packages |
| `cmd/root.go` | Cobra root command; global flags; `Version` variable | Cobra `*cobra.Command`, `init()` pattern, package-level `var`, `ldflags` injection, `fmt.Fprintf` to `os.Stderr` |
| `cmd/scan.go` | `scan` sub-command; wires scanner → parser → advisory → scorer → reporter | Struct for flags (`scanFlags`), method receivers, `context.WithTimeout`, `os.Exit(2)` for vuln-found exit code |
| `internal/models/models.go` | Shared data types; no behaviour | Named string types (`type Ecosystem string`), typed constants (`const EcosystemNPM Ecosystem = "npm"`), struct embedding concept, `SeverityRank` as a pure function |
| `internal/scanner/scanner.go` | Directory walker; goroutine pool; ecosystem detection dispatch | `interface` definition, goroutine pools with `sync.WaitGroup`, buffered channels (`make(chan T, N)`), `filepath.WalkDir`, `sync.Map` for concurrent deduplication, `context` cancellation with `select` |
| `internal/scanner/npm.go` | Detects and extracts npm packages | Struct implementing `Detector` interface, `os.Stat` for file existence, JSON decoding with `encoding/json` |
| `internal/scanner/go_mod.go` | Parses `go.sum` line by line | `bufio.Scanner`, string splitting with `strings.Fields`, guard clauses (`if len(fields) < 2`) |
| `internal/scanner/cargo.go` | Parses Cargo.lock | Manual TOML state machine, string prefix matching, building a map to detect transitive deps |
| `internal/scanner/pip.go` | Detects pip/PyPI packages | Multiple fallback strategies in one function, `filepath.Glob`, reading `*.dist-info/METADATA` |
| `internal/parser/parser.go` | Lockfile parsing for all four ecosystems; `Dispatcher` fan-out | Interface satisfaction without declaration, JSON struct tags (`json:"lockfileVersion"`), `fmt.Errorf("…: %w", err)`, recursive structs (v1 `pkgLockDep`), `errors.As` unwrapping via `ParseError.Unwrap()`, `errgroup` |
| `internal/parser/parser_test.go` | 51 table-driven tests for all parsers | `testing.T`, `t.TempDir()`, `t.Helper()`, table-driven test pattern, `t.Run` subtests, `os.WriteFile` for fixture setup |
| `internal/models/models_test.go` | Tests for `SeverityRank` | Basic `testing.T` usage, simple assertion pattern |
| `internal/advisory/client.go` | Fan-out to all CVE sources; deduplication | `interface` as dependency injection, goroutine fan-out with buffered channel, anonymous `result` struct, dedup via `map[string]struct{}` |
| `internal/advisory/osv.go` | OSV.dev REST API client | `http.Client` with `Timeout`, `http.NewRequestWithContext`, `defer resp.Body.Close()`, JSON request/response structs, CVSS vector parsing |
| `internal/advisory/github.go` | GitHub Advisory GraphQL client | GraphQL request/response structs, `Authorization: bearer` header, `json.NewDecoder`, nested anonymous struct fields |
| `internal/cve/client.go` | Full CVE client with worker pool | `semaphore.Weighted` from `golang.org/x/sync`, `sync.WaitGroup`, closing a channel after all writers finish, `Options` configuration struct pattern |
| `internal/scorer/scorer.go` | Normalise, filter, and sort vulnerabilities | Struct embedding (`RiskScore` embeds `models.Vulnerability`), `sort.Slice` with a closure comparator, `time.Since` for age calculation, `zap.Logger` structured logging |
| `internal/reporter/reporter.go` | Render results as table, JSON, or HTML | `Reporter` interface with factory function (`New`), `text/tabwriter` for column alignment, `fatih/color` for ANSI escape codes, `html/template`, `encoding/json.NewEncoder`, `io.Writer` as output abstraction |

---

## 4. When something breaks

### The five most common Go errors in this codebase

#### 1. `nil pointer dereference` — panic at runtime

```
goroutine 1 [running]:
github.com/dep-shield/dep-shield/internal/scanner.(*impl).Scan(...)
    internal/scanner/scanner.go:292
```

**What it means:** Something is `nil` when you tried to use it as if it
weren't.  Common causes:

- `opts.Log` was never set — many functions call `log.Info(…)` without a nil
  guard.  Fix: always pass `zap.NewNop()` in tests; check `NewClient` for the
  nil-logger guard pattern.
- A map is declared but never initialised.  `var m map[string]string` is nil;
  writing to it panics.  Fix: `m := make(map[string]string)`.
- A function returned an error and you kept using the result anyway:
  ```go
  pkg, err := parser.Parse(dir)
  fmt.Println(pkg.Name)  // ← panics if err != nil and pkg is zero-value
  ```
  Fix: always `if err != nil { return err }` before using the result.

#### 2. `index out of range` — panic at runtime

```
panic: runtime error: index out of range [0] with length 0
```

**Where it happens:** The scanner and parser files split lines into fields and
then index into them:

```go
fields := strings.Fields(line)
module := fields[0]  // panics when line is blank
```

Fix: always guard:

```go
if len(fields) < 2 {
    continue
}
```

The pattern is consistent in this codebase — every `fields[0]` access is
preceded by a length check.  If you add a new parser and forget this, the test
with an empty lockfile will catch it.

#### 3. `declared but not used` — compile error

```
./cmd/scan.go:42:6: ctx declared and not used
```

Go refuses to compile if you declare a variable and never read it.  Fix:
either use the variable or replace it with `_`:

```go
_, err := someFunc()  // discard the first return value intentionally
```

This is intentional: unused variables in Go almost always indicate a mistake.

#### 4. `cannot use X (type Y) as type Z` — compile error

The most common form in this codebase: forgetting the `*` on a pointer
receiver.

```go
var s scanner.Scanner = impl{}   // wrong — impl has pointer receivers
var s scanner.Scanner = &impl{}  // correct
```

If `Query` is defined as `func (o *osvSource) Query(…)`, then `osvSource`
(without `*`) does *not* satisfy the `Source` interface.  `*osvSource` does.

#### 5. `context deadline exceeded` — runtime error, not a panic

```
osv http: context deadline exceeded (Client.Timeout exceeded while awaiting headers)
```

This is normal behaviour, not a bug — it means a request timed out.  If you
see it unexpectedly:

- Is the `http.Client.Timeout` set too low?  Default in this codebase is 15s.
- Is `ctx` already cancelled before the HTTP call?  Check that `cancel()` is
  deferred, not called immediately.
- Is the test calling a real network endpoint?  Tests should mock HTTP; search
  for `httptest.NewServer` or `fetchMock` patterns.

---

### Diagnostic tools

#### `go vet` — catch common mistakes before they panic

```bash
go vet ./...
```

`go vet` catches things the compiler misses: `fmt.Errorf` with `%w` used
incorrectly, unreachable code, incorrect mutex usage, `printf` verbs that
don't match argument types.  Run it before every commit.  The CI workflow runs
it automatically.

Useful targeted checks:

```bash
go vet -printf ./...      # mismatched printf verbs
go vet -structtag ./...   # malformed JSON struct tags like `json:"name" ` (trailing space)
```

#### `go test -race` — catch data races

```bash
go test -race ./...
```

The race detector instruments memory accesses and reports when two goroutines
read and write the same variable without synchronisation.  This is the most
common bug class in concurrent Go.  It's slower (~3–5×) but should be run
before any PR that touches goroutine code.

```bash
# Run just the scanner tests with race detection (faster during development):
go test -race ./internal/scanner/...
```

#### Adding a print statement without breaking anything

Use `fmt.Println` to dump a value during development:

```go
fmt.Printf("DEBUG pkg: %+v\n", pkg)  // %+v prints field names too
```

Remove it before committing.  A linter (`go vet`) will warn about some misuses
but won't catch all debug prints — use `grep -r 'DEBUG' .` before pushing.

For structured logging that *stays* in the code, use the `zap.Logger` that's
already threaded through every struct:

```go
o.log.Debug("osv response", zap.String("id", v.ID), zap.Float64("cvss", cvss))
```

Set `--log-level debug` at the CLI to see these messages.  They are silent in
production.

#### Running a single test

```bash
# Run one specific test function:
go test ./internal/parser/... -run TestGoParser_DirectFromGoMod

# Run all tests whose name contains "Yarn":
go test ./internal/parser/... -run Yarn

# Run tests with verbose output (see each PASS/FAIL line):
go test -v ./internal/scanner/...

# Run tests and see coverage:
go test -cover ./...
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```

#### Inspecting what goreleaser would build

```bash
# Check your .goreleaser.yaml is valid:
goreleaser check

# Build all binaries locally without creating a release:
goreleaser build --snapshot --clean

# Built binaries land in dist/:
ls dist/
```

---

## 5. Your first contribution

### The suggested feature: Ruby Gemfile.lock support

dep-shield currently scans npm, Go, PyPI, and Cargo.  Ruby (Bundler) is the
most-requested missing ecosystem.  Adding it touches every layer of the stack
— a complete, reviewable contribution.

Here's a Gemfile.lock to understand the format:

```
GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.8)
    rails (7.1.3)
      rack (>= 3.0.2)

BUNDLED WITH
   2.5.6
```

#### Step 1 — Add the model constant (5 minutes)

In `internal/models/models.go`, add:

```go
EcosystemRubyGems Ecosystem = "RubyGems"
```

Run `go build ./...` — everything should still compile.

#### Step 2 — Write the detector (20 minutes)

Create `internal/scanner/rubygems.go`.  Model it on `internal/scanner/npm.go`
(the simplest existing detector).  Your type must satisfy the `Detector`
interface:

```go
type Detector interface {
    Name() string
    Recognises(dir string) bool
    Extract(ctx context.Context, dir string) ([]models.Package, error)
}
```

- `Recognises` should return `true` when `Gemfile.lock` exists in `dir`.
- `Extract` should open the file, iterate lines with `bufio.Scanner`, and
  return one `models.Package` per `    name (version)` line in the `specs:`
  section.

Hints:
- The `specs:` block ends when a line starts without leading whitespace.
- Each package line looks like `    rack (3.0.8)` — four spaces of indent,
  then `name (version)`.
- `strings.TrimSpace`, `strings.HasPrefix`, and `strings.Split` are all you
  need.
- Guard every `strings.Fields(line)[0]` access with a `len` check (see
  section 4 above).

#### Step 3 — Register the detector (2 minutes)

In `internal/scanner/scanner.go`, find where the existing detectors are
registered (look for `newNPMScanner`, `newGoScanner`, etc.) and add:

```go
newRubyGemsScanner(),
```

#### Step 4 — Write a parser (30 minutes)

In `internal/parser/parser.go`, add a `RubyParser` that implements the
`Parser` interface:

```go
type Parser interface {
    Parse(dir string) ([]Package, error)
    Ecosystem() string
}
```

`RubyParser.Parse` should read `Gemfile.lock` and return `[]Package`.  The
logic will be almost identical to what you wrote in Step 2.

Register it in `Dispatcher.ParseAll` alongside the other parsers.

#### Step 5 — Write tests (20 minutes)

In `internal/parser/parser_test.go`, add a `TestRubyParser` function.  Use
the table-driven pattern already in the file:

```go
func TestRubyParser_DirectPackages(t *testing.T) {
    dir := t.TempDir()
    writeFile(t, filepath.Join(dir, "Gemfile.lock"), `
GEM
  specs:
    rack (3.0.8)
    rails (7.1.3)
`)
    p := RubyParser{}
    pkgs, err := p.Parse(dir)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    got, ok := findPkg(pkgs, "rack")
    if !ok {
        t.Fatal("rack not found")
    }
    if got.Version != "3.0.8" {
        t.Errorf("got version %q, want 3.0.8", got.Version)
    }
}
```

Run with `go test ./internal/parser/... -run RubyParser -v`.

#### Step 6 — Ecosystem mapping (5 minutes)

In `internal/cve/client.go`, find `ghEcosystem` and add the Ruby mapping:

```go
case models.EcosystemRubyGems:
    return "RUBYGEMS", true
```

The OSV ecosystem string for Ruby is `"RubyGems"` — already used by your
`Ecosystem()` method.

#### Verification checklist

```bash
go build ./...                           # compiles
go vet ./...                             # no static errors
go test ./...                            # all tests pass
go test -race ./internal/scanner/...    # no data races
dep-shield scan /path/to/ruby/project   # try it on a real project
```

#### What a good PR description looks like

```
Add Ruby Gemfile.lock scanner and parser

Closes #<issue number>

- Add EcosystemRubyGems constant in models
- rubygems.go: Detector that recognises Gemfile.lock and extracts specs: block
- RubyParser in parser.go: same logic, returns parser.Package
- Tests: TestRubyParser_DirectPackages, TestRubyParser_EmptyFile, TestRubyParser_MissingFile
- ghEcosystem mapping: RubyGems → RUBYGEMS for GitHub Advisory queries

Tested against:
  rails 7.1.3 project (142 gems, 3 CVEs found via OSV)
  Empty Gemfile.lock (0 packages, no error)
```

---

## Quick reference card

```bash
# Build
CGO_ENABLED=0 go build -o dep-shield .

# Test
go test ./...                   # all packages
go test -v ./internal/parser/...    # verbose, one package
go test -run TestGoParser ./...     # one test function
go test -race ./...             # with race detector
go test -cover ./...            # with coverage

# Vet and format
go vet ./...
gofmt -w .                      # reformat all files in place

# Run
./dep-shield scan .
./dep-shield scan . --fail-on high
./dep-shield scan . --log-level debug

# Release (local preview, no publish)
goreleaser build --snapshot --clean
goreleaser release --snapshot --clean
```
