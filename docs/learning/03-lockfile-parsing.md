# Guide 03 — Lockfile Parsing

> **Files covered:** `internal/parser/parser.go`, `internal/parser/parser_test.go`
>
> **Prerequisite:** Guide 02 (goroutines and channels — the Dispatcher uses the same fan-out pattern).

---

## Why a separate parser package?

After the scanner locates `node_modules/`, a Go module root, a `.cargo/registry/` dir, or a `site-packages/`, we still only know *where* packages live — not *what* they are.  The parser package's job is to read the manifest files inside each directory and emit `models.Package` values that the rest of the pipeline (CVE lookup, scoring, reporting) can consume without caring which file format they came from.

The design rule is: **each parser only knows about its own file format and the `models` package**.  No parser ever imports `scanner`, `cve`, or any other internal package.  This keeps dependency cycles impossible and makes each parser trivially unit-testable in isolation.

---

## The `Parser` interface

```go
type Parser interface {
    Ecosystem() models.Ecosystem
    Parse(ctx context.Context, dir string) ([]models.Package, error)
}
```

Two methods.  That's it.

`Ecosystem()` is purely a routing key — the `Dispatcher` calls it once at startup to build its map.

`Parse()` receives the directory the scanner already found.  It must:
- Not walk into sub-directories (the scanner already handled recursion).
- Return a `nil` slice (not an error) when the expected file is simply absent.
- Return a `*ParseError` when a file exists but is malformed.
- Honour `ctx` cancellation (check `ctx.Err()` inside loops).

### Why `dir` instead of a file path?

Different ecosystems store metadata in different places relative to the hit directory:

| Ecosystem | Hit directory | File read |
|-----------|--------------|-----------|
| npm       | `node_modules/` | `<pkg>/package.json` (many files) |
| Go        | module root  | `go.sum` |
| Cargo     | crate root   | `Cargo.lock` |
| PyPI      | `site-packages/` | `*.dist-info/METADATA` (many files) |

Passing the directory instead of a specific file allows each parser to decide how to navigate its own layout.

---

## Reading files in Go

### `os.Open` vs `os.ReadFile`

```go
// os.ReadFile — reads the whole file into memory at once.
// Good for small, single files (e.g. package.json — rarely > 1 KB).
data, err := os.ReadFile(path)

// os.Open + bufio.Scanner — streams line by line.
// Good for large files (go.sum can be thousands of lines).
f, err := os.Open(path)
defer f.Close()
sc := bufio.NewScanner(f)
for sc.Scan() {
    line := sc.Text() // one line, no trailing newline
}
```

The parser uses `ReadFile` for `package.json` (small, needs JSON decode anyway) and `bufio.Scanner` everywhere else.

### The `defer f.Close()` pattern

```go
f, err := os.Open(path)
if err != nil {
    return nil, err
}
defer f.Close()   // ← runs when the function returns, no matter how
```

`defer` is covered in depth in Guide 02.  The important thing here: **always defer `Close()` on the very next line after a successful open**.  If you open two files, defer two closes.  If you forget, the OS file descriptor leaks until the process exits.

---

## `encoding/json` — decoding JSON

```go
type packageJSON struct {
    Name    string `json:"name"`
    Version string `json:"version"`
}

var pj packageJSON
if err := json.Unmarshal(data, &pj); err != nil {
    // malformed JSON
}
```

The backtick annotations are *struct tags*.  They tell `json.Unmarshal` which JSON key maps to which Go field.  Without tags, Go matches by lowercasing the field name — `Name` → `name` — but explicit tags are clearer and more robust.

`json.Unmarshal` needs a pointer (`&pj`), not a value, so it can write into the struct.

### What `json.Unmarshal` does NOT do

It does not validate that required fields are present.  After unmarshalling, always check that the fields you need are non-empty:

```go
if pj.Name == "" || pj.Version == "" {
    return models.Package{}, false
}
```

---

## `bufio.Scanner` — line-by-line reading

```go
sc := bufio.NewScanner(f)
for sc.Scan() {
    line := sc.Text()
    // process line...
}
if err := sc.Err(); err != nil {
    return pkgs, &ParseError{Path: path, Err: err}
}
```

Three things to remember:
1. `sc.Scan()` advances and returns `true` until EOF or an error.
2. `sc.Text()` returns the current line **without** the trailing `\n`.
3. **Check `sc.Err()` after the loop.**  `Scan()` returns `false` for both EOF (no error) and a read error.  If you don't check `sc.Err()`, you silently ignore I/O failures.

---

## go.sum format

```
github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owp...=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHB...=
```

Every module appears **twice**: once for the source tarball (`v0.9.1`) and once for its go.mod file (`v0.9.1/go.mod`).  We want packages, not metadata, so we skip `/go.mod` lines:

```go
if strings.HasSuffix(versionField, "/go.mod") {
    continue
}
```

The format is space-separated: `module version hash`.  `strings.Fields(line)` splits on any whitespace and handles multiple spaces, making it more robust than `strings.Split(line, " ")`.

---

## Cargo.lock format and state machines

Cargo.lock is TOML.  Rather than importing a TOML library (extra dependency, extra compile time), the parser uses a simple state machine:

```
state: outside a package block
  → see "[[package]]"  →  state: inside a package block
    → see `name = "..."`   →  record name
    → see `version = "..."` →  record version
    → see "[[package]]"  →  emit previous block, start new block
  → EOF  →  emit last block
```

In Go this looks like:

```go
inPackage := false
var curName, curVersion string

flush := func() {
    if inPackage && curName != "" && curVersion != "" {
        pkgs = append(pkgs, models.Package{ Name: curName, ... })
    }
    curName, curVersion = "", ""
}

for sc.Scan() {
    line := strings.TrimSpace(sc.Text())
    if line == "[[package]]" {
        flush()           // emit whatever we had
        inPackage = true  // start fresh block
        continue
    }
    if v, ok := tomlStringValue(line, "name"); ok    { curName = v }
    if v, ok := tomlStringValue(line, "version"); ok { curVersion = v }
}
flush() // emit the last block
```

The `flush` closure captures `curName`, `curVersion`, and `pkgs` by reference — that's what closures in Go do.  Calling `flush()` both emits and resets state in one place, avoiding a copy-paste bug where you reset in one branch but forget another.

### `tomlStringValue` — parsing `key = "value"`

```go
func tomlStringValue(line, key string) (string, bool) {
    prefix := key + ` = "`
    if !strings.HasPrefix(line, prefix) {
        return "", false
    }
    rest := line[len(prefix):]
    idx := strings.Index(rest, `"`)
    if idx < 0 {
        return "", false
    }
    return rest[:idx], true
}
```

This is a deliberate micro-parser instead of `strings.Split(line, "=")` because:
- `=` can appear inside a value (e.g. base64 checksums).
- We need the value without quotes.
- We want to match only specific keys, not any key.

---

## Python dist-info / METADATA format

When pip installs a package into `site-packages/`, it creates a directory like:

```
site-packages/
  requests-2.31.0.dist-info/
    METADATA
    RECORD
    WHEEL
  requests/
    __init__.py
    ...
```

The `METADATA` file uses the same format as email headers (RFC 822):

```
Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Summary: Python HTTP for Humans.
...

<long description after blank line>
```

The parser reads headers line by line until it finds both `Name:` and `Version:` (or hits a blank line, which signals end of headers):

```go
for sc.Scan() {
    line := sc.Text()
    if strings.HasPrefix(line, "Name: ")    { pkgName    = strings.TrimPrefix(line, "Name: ")    }
    if strings.HasPrefix(line, "Version: ") { pkgVersion = strings.TrimPrefix(line, "Version: ") }
    if pkgName != "" && pkgVersion != "" { break }
    if line == "" { break }  // end of headers
}
```

Breaking early is important: METADATA files can be megabytes long (they include the full README).

### requirements.txt format

```
requests==2.31.0
flask==2.3.2  # web framework
-r other-requirements.txt   ← include another file — we skip these
git+https://github.com/...  ← URL requirement — we skip these
Django>=3.0                 ← unpinned — we skip these
```

We only handle `==` (exact pin) because CVE queries require an exact version.  `>=`, `~=`, `!=` constraints don't tell us what version is actually installed.

---

## The `Dispatcher` — fan-out with `errgroup`

```go
g, ctx := errgroup.WithContext(ctx)

for _, hit := range hits {
    hit := hit  // ← capture the loop variable!
    g.Go(func() error {
        pkgs, err := p.Parse(ctx, hit.Path)
        ch <- result{pkgs, err}
        return nil
    })
}
```

`golang.org/x/sync/errgroup` is a `WaitGroup` plus error propagation baked in.  `g.Go()` starts a goroutine and tracks it.  `g.Wait()` blocks until all goroutines finish and returns the first non-nil error any of them returned.

**Why `hit := hit` inside the loop?**

In Go, the loop variable `hit` is a single memory location that gets overwritten each iteration.  If you close over `hit` directly, all goroutines will see the last value of `hit` after the loop finishes — a classic data race.  Assigning `hit := hit` creates a new copy of `hit` scoped to this iteration:

```go
for _, hit := range hits {
    // BAD — all goroutines see the same 'hit' after loop ends
    go func() { process(hit) }()
}

for _, hit := range hits {
    hit := hit  // NEW variable, one per iteration
    // GOOD — each goroutine captures its own copy
    go func() { process(hit) }()
}
```

> **Go 1.22+ note:** As of Go 1.22, loop variables are re-created per iteration, making `hit := hit` unnecessary.  dep-shield requires Go 1.22+, but the redundant capture is kept as explicit documentation.

### Non-fatal parse errors

The `Dispatcher.ParseAll()` call never returns an error for individual file failures:

```go
if err != nil {
    d.log.Warn("parse error", zap.String("path", hit.Path), zap.Error(err))
    ch <- result{nil, err}  // sent to channel but NOT returned
    return nil              // g.Go() goroutine returns nil — no abort
}
```

This is intentional: if one project's `go.sum` is corrupted, we still want to scan all other projects.  The errors are logged and available for diagnostics, but they don't stop the pipeline.

---

## Deduplication

When two `node_modules/` directories both contain `lodash@4.17.21` (e.g. a monorepo), we want to report it once:

```go
seen := make(map[string]struct{})
for r := range ch {
    for _, pkg := range r.pkgs {
        key := string(pkg.Ecosystem) + "|" + pkg.Name + "|" + pkg.Version
        if _, dup := seen[key]; dup {
            continue
        }
        seen[key] = struct{}{}
        all = append(all, pkg)
    }
}
```

`map[string]struct{}` is idiomatic Go for a *set*.  `struct{}` takes zero bytes.  The `_, ok := seen[key]` form reads "does this key exist?" without caring about the value.

---

## Error types — `*ParseError`

```go
type ParseError struct {
    Path string
    Err  error
}

func (e *ParseError) Error() string { return fmt.Sprintf("parse %s: %v", e.Path, e.Err) }
func (e *ParseError) Unwrap() error { return e.Err }
```

Wrapping errors with a custom type serves two purposes:
1. The error message includes the file path (essential for debugging).
2. Callers can use `errors.Is(err, os.ErrPermission)` and it will correctly unwrap through `ParseError` to find the underlying cause — because `Unwrap()` is defined.

Without `Unwrap()`, `errors.Is` would only compare the `*ParseError` itself, not what's inside it.

---

## Table-driven tests review

The test file contains 29 tests using a consistent pattern:

```go
func TestGoSumParser_Parse_BasicEntries(t *testing.T) {
    root := t.TempDir()                           // isolated temp dir, cleaned up automatically
    writeFile(t, filepath.Join(root, "go.sum"), `...content...`)

    p := &goSumParser{log: nopLog()}
    pkgs, err := p.Parse(context.Background(), root)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(pkgs) != 2 {
        t.Fatalf("expected 2 packages, got %d: %v", len(pkgs), pkgs)
    }
}
```

Key helpers:
- `t.TempDir()` — creates a temp directory that is deleted when the test ends.  Every test gets its own isolated directory so tests cannot interfere with each other.
- `nopLog()` — returns `zap.NewNop()`, a logger that discards all output.  Tests should be silent unless they fail.
- `writeFile(t, path, content)` — creates parent directories and writes a file, calling `t.Fatal` on any error.
- `findPkg(pkgs, name)` — searches a slice by name, returns `(pkg, bool)`.

### `t.Fatalf` vs `t.Errorf`

| Function | Stops current test? | Use when |
|----------|---------------------|----------|
| `t.Fatalf` | Yes — calls `t.FailNow()` | A prerequisite failed (e.g. file couldn't be created, no packages returned when > 0 expected) |
| `t.Errorf` | No — continues test | A specific field has the wrong value; you want to see all failures at once |

---

## Debug this

### Symptom: parser returns 0 packages but no error

```bash
# Run just the parser tests with verbose output
go test ./internal/parser/... -v -run TestNpmParser

# Add a temporary fmt.Println inside Parse() to see what's being read:
# (remember to remove before committing)
fmt.Println("DEBUG entries:", len(entries))
for _, e := range entries {
    fmt.Printf("  dir=%v name=%s\n", e.IsDir(), e.Name())
}
```

Common causes:
- The directory structure doesn't match what the parser expects (e.g. package.json is two levels deep, not one).
- The file exists but the field name has a different capitalisation in the JSON.
- `strings.HasSuffix` / `strings.HasPrefix` check is wrong.

### Symptom: `go.sum` parser returns duplicate entries

Run with `-race` to catch concurrent map writes:

```bash
go test ./internal/parser/... -race
```

The `seen` map is built in a single goroutine (the collector loop after `g.Wait()`), so there should be no race.  If you see a race, check that you haven't accidentally moved deduplication inside a `g.Go()` closure.

### Symptom: Cargo.lock parser skips the last package

The `flush()` call after the scanner loop is easy to forget.  The last `[[package]]` block has no following `[[package]]` to trigger emission, so it must be flushed explicitly at EOF.  Add a test that has a Cargo.lock ending without a trailing newline:

```go
writeFile(t, path, "[[package]]\nname = \"foo\"\nversion = \"0.1.0\"")
// Note: no trailing newline — bufio.Scanner handles this correctly.
```

### Checking what errgroup captures

```go
// Print the error returned by ParseAll:
pkgs, err := d.ParseAll(ctx, hits)
fmt.Printf("err=%v pkgs=%d\n", err, len(pkgs))
```

`ParseAll` currently swallows per-hit errors (logs them, returns nil).  To surface them during debugging, temporarily change `return nil` inside `g.Go()` to `return err` and you'll see `g.Wait()` return the first failure.

---

## Exercises

1. **Add PNPM support.**  pnpm uses `node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>/package.json`.  The path structure is different from npm.  Write `pnpmParser` implementing `Parser`, add it to `New()`, and write three table-driven tests.

2. **Add Poetry support.**  Poetry generates `poetry.lock` (TOML) with a similar `[[package]]` structure to Cargo.lock but slightly different field names.  Read the [Poetry lock file spec](https://python-poetry.org/docs/basic-usage/#installing-with-poetrylock) and implement `poetryParser`.

3. **Trace a package through the pipeline.**  Starting from `scanner.Walk()` in `cmd/dep-shield/root/scan.go`, trace a single `node_modules/` directory all the way to a `models.Package` value.  Write down every function call and data transformation.  What does the `models.Package.Path` field contain at each stage?

4. **Benchmark the go.sum parser.**  Create a `go.sum` file with 1000 entries using a Go test helper, then write a `BenchmarkGoSumParser` function.  Run with `go test -bench=. -benchmem ./internal/parser/...`.  What is the allocation count per operation?  Can you reduce it by pre-allocating the `pkgs` slice with `make([]models.Package, 0, estimatedCount)`?
