# Guide 03 — Interfaces, JSON, and the Parser Package

> **Files covered:** `internal/parser/parser.go`, `internal/parser/parser_test.go`
>
> **Prerequisites:** Guide 01 (project structure), Guide 02 (goroutines and channels — the Dispatcher reuses the same fan-out pattern).

---

## Overview: what the parser package actually does

After the scanner hands us a slice of `DirHit` values — each one saying "I found a `node_modules/` at this path" or "there's a `Cargo.lock` over here" — the parser package opens the relevant files and converts them into `Package` structs the rest of the pipeline can reason about.

The interesting design problem is that four completely different file formats all need to produce the same output type.  That's exactly the situation interfaces were invented for.

---

## 1. Interfaces in Go

### What an interface is

An interface in Go is a **named set of method signatures**.  Any type that has those methods automatically satisfies the interface — no explicit declaration required.

```go
// From parser.go
type Parser interface {
    Parse(dir string) ([]Package, error)
    Ecosystem() string
}
```

That's all there is to the `Parser` interface: two methods with specific signatures.

Now look at `NodeParser` and `CargoParser`:

```go
type NodeParser struct {
    log *zap.Logger
}

func (n *NodeParser) Parse(dir string) ([]Package, error)  { ... }
func (n *NodeParser) Ecosystem() string { return string(models.EcosystemNPM) }

// ───

type CargoParser struct {
    log *zap.Logger
}

func (c *CargoParser) Parse(dir string) ([]Package, error) { ... }
func (c *CargoParser) Ecosystem() string { return string(models.EcosystemCargo) }
```

Neither struct has any `implements Parser` line.  The Go compiler checks at the point of **use**: when you try to assign a `*NodeParser` somewhere a `Parser` is expected, the compiler verifies that all interface methods exist with the right signatures.  If they do, it works.  If a method is missing or has the wrong return type, you get a compile error.

You can verify the constraint explicitly with a blank identifier assignment — a common Go idiom:

```go
// Compile-time assertion: "if *NodeParser does not satisfy Parser, fail here."
var _ Parser = (*NodeParser)(nil)
var _ Parser = (*CargoParser)(nil)
```

This produces no runtime code; it is purely a check for the reader and the compiler.

### Why an interface instead of a struct?

Imagine we had used a single struct instead:

```go
// hypothetical — don't do this
type Parser struct {
    ecosystem string
}

func (p *Parser) Parse(dir string) ([]Package, error) {
    switch p.ecosystem {
    case "npm":   // ... 200 lines of npm logic
    case "Go":    // ... 150 lines of go logic
    case "cargo": // ... 180 lines of cargo logic
    case "pypi":  // ... 200 lines of python logic
    default:
        return nil, fmt.Errorf("unknown ecosystem: %s", p.ecosystem)
    }
}
```

Problems:
- Adding a new ecosystem means editing a shared file and a growing switch.
- The npm code can accidentally reference cargo variables (or vice versa) because they share a scope.
- Testing one ecosystem requires running all the others' code paths.
- The function grows without bound.

With the interface, adding Ruby support is entirely self-contained:

```go
type GemfileParser struct { log *zap.Logger }
func (g *GemfileParser) Ecosystem() string { return "RubyGems" }
func (g *GemfileParser) Parse(dir string) ([]Package, error) { ... }
```

Then one line in `New()`:

```go
&GemfileParser{log: log},
```

That is the **Open/Closed Principle** expressed naturally in Go: the `Dispatcher` is open for extension (new parsers) but closed for modification (you never touch `Dispatcher.ParseAll`).

### Comparison with Python

Python uses *duck typing* — there is no interface keyword.  Any object that has the right methods works:

```python
class NodeParser:
    def ecosystem(self) -> str:
        return "npm"
    def parse(self, dir: str) -> list[Package]:
        ...

class CargoParser:
    def ecosystem(self) -> str:
        return "crates.io"
    def parse(self, dir: str) -> list[Package]:
        ...

def parse_all(parsers, hits):
    for hit in hits:
        parser = parsers[hit.ecosystem]
        pkgs = parser.parse(hit.path)   # works regardless of concrete type
```

This is flexible but invisible to tools.  If `CargoParser` is missing a `parse()` method, Python won't tell you until that code path runs at runtime.  Go tells you at compile time.

Python 3.8+ added `typing.Protocol` to make this explicit:

```python
from typing import Protocol

class Parser(Protocol):
    def ecosystem(self) -> str: ...
    def parse(self, dir: str) -> list[Package]: ...
```

This is the closest Python equivalent to Go interfaces, and it was added precisely because duck typing at scale is hard to reason about.

### Comparison with TypeScript

TypeScript uses the `interface` keyword, and like Go, a class satisfies an interface simply by having the right shape:

```typescript
interface Parser {
    ecosystem(): string;
    parse(dir: string): Promise<Package[]>;
}

class NodeParser implements Parser {   // ← explicit in TypeScript
    ecosystem() { return "npm"; }
    async parse(dir: string) { ... }
}
```

The key difference: TypeScript requires `implements Parser` at the class declaration.  Go does not.  In Go, satisfaction is determined entirely by method matching — no keyword needed on the implementor.

This matters for one practical reason: a Go interface can be defined **after** the concrete types.  You can write four parsers, then later extract an interface that they all happen to satisfy, without modifying any of them.  In TypeScript you'd have to go back and add `implements` to each class.

### How the Dispatcher uses the interface

```go
// New() builds a map from ecosystem string → Parser interface value.
for _, p := range []Parser{
    &NodeParser{log: log},
    &GoParser{log: log},
    &CargoParser{log: log},
    &PythonParser{log: log},
} {
    d.parsers[models.Ecosystem(p.Ecosystem())] = p
}
```

The slice literal `[]Parser{...}` works because all four pointer types satisfy `Parser`.  The `Dispatcher` only ever sees the `Parser` interface — it has no idea that `*NodeParser` exists.  This is *polymorphism*: the same `p.Parse(hit.Path)` call does completely different work depending on which concrete type is stored in `p`.

---

## 2. Struct embedding

`parser.go` does not embed structs — each parser is a standalone struct with its own fields.  But embedding comes up often enough in Go that it is worth understanding here.

### What embedding is

Embedding is putting one struct *inside* another without a field name:

```go
type base struct {
    log *zap.Logger
}

func (b *base) logError(path string, err error) {
    b.log.Warn("parse error", zap.String("path", path), zap.Error(err))
}

// NodeParser "has a" base — embedding promotes base's methods.
type NodeParser struct {
    base                // ← embedded, no field name
    someNodeSpecificField string
}
```

With embedding, `NodeParser` automatically gets `logError()` as if it were its own method.  You can call `n.logError(path, err)` without writing a delegating method.  This is Go's form of inheritance — but it is *composition*, not a subclass relationship.

The reason we don't use embedding in `parser.go` is that each parser has no shared behaviour beyond holding a logger.  Embedding `base` would add one abstraction layer with minimal benefit.  The direct approach — each struct has its own `log *zap.Logger` field — is clearer at this scale.

If parsers grew to share significant logic (e.g. a common "try to open file, return nil on not-found" pattern), embedding or helper types would be worth it.

---

## 3. JSON unmarshalling — decoding package-lock.json

### The three structs that mirror the JSON

```go
// pkgLockRoot mirrors the top-level object in package-lock.json.
type pkgLockRoot struct {
    LockfileVersion int                    `json:"lockfileVersion"`
    Packages        map[string]pkgLockFlat `json:"packages"`
    Dependencies    map[string]pkgLockDep  `json:"dependencies"`
}

// pkgLockFlat is one entry in the v2/v3 "packages" map.
type pkgLockFlat struct {
    Version      string            `json:"version"`
    Resolved     string            `json:"resolved"`
    Dev          bool              `json:"dev"`
    Dependencies map[string]string `json:"dependencies"`
}

// pkgLockDep is one entry in the v1 nested "dependencies" map.
type pkgLockDep struct {
    Version      string                `json:"version"`
    Resolved     string                `json:"resolved"`
    Dev          bool                  `json:"dev"`
    Dependencies map[string]pkgLockDep `json:"dependencies"` // recursive!
}
```

And the call that drives the whole thing:

```go
data, err := os.ReadFile(path)
var root pkgLockRoot
if err := json.Unmarshal(data, &root); err != nil { ... }
```

### What struct tags do

Every field in the structs above has a *struct tag* — the backtick string after the type:

```go
LockfileVersion int `json:"lockfileVersion"`
```

Struct tags are metadata attached to fields.  They are inert strings that libraries can read using reflection at runtime.  The `encoding/json` package reads the `json:"..."` tag to know which JSON key maps to which Go field.

Without a tag, `json.Unmarshal` matches by lowercasing the field name.  `LockfileVersion` would match the JSON key `"lockfileversion"` (all lowercase) — but the actual key is `"lockfileVersion"` (camelCase with a capital V).  The tag provides the exact match:

```
JSON key          Go field
──────────────    ──────────────────
"lockfileVersion" → LockfileVersion int
"packages"        → Packages map[string]pkgLockFlat
"dependencies"    → Dependencies map[string]pkgLockDep
```

Tags can carry multiple directives separated by spaces.  The `json` package supports:

```go
Name string `json:"name,omitempty"`  // omit from output if empty
ID   string `json:"-"`               // always skip this field
Raw  []byte `json:",string"`         // encode/decode as JSON string
```

`parser.go` only needs the name mapping, so tags are just `json:"key"`.

### Walking through the decode step by step

Given this v2 package-lock.json fragment:

```json
{
  "lockfileVersion": 2,
  "packages": {
    "": {
      "dependencies": { "express": "^4.18.2" }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "dependencies": { "accepts": "^1.3.8" }
    },
    "node_modules/accepts": {
      "version": "1.3.8"
    }
  }
}
```

`json.Unmarshal(data, &root)` does the following:

1. Sees the top-level object `{...}` → assigns to `pkgLockRoot`.
2. Sees `"lockfileVersion": 2` → assigns `2` to `root.LockfileVersion` (matched by tag).
3. Sees `"packages": {...}` → creates a `map[string]pkgLockFlat`.
4. For each key in `"packages"`:
   - Key `""` → creates a `pkgLockFlat`, fills `Dependencies` from the nested object.
   - Key `"node_modules/express"` → creates a `pkgLockFlat` with `Version: "4.18.2"`, `Resolved: "https://..."`, and `Dependencies: map{"accepts":"^1.3.8"}`.
   - Key `"node_modules/accepts"` → creates a `pkgLockFlat` with `Version: "1.3.8"`.
5. `"dependencies"` key is absent → `root.Dependencies` stays `nil`.

After this one call, `root` holds the entire parsed tree.  The parser then inspects `root.LockfileVersion` to decide which path to follow:

```go
switch {
case root.LockfileVersion >= 2 && root.Packages != nil:
    return n.fromPackageLockFlat(root.Packages, nodeModulesDir), nil
case root.LockfileVersion == 1 || root.Dependencies != nil:
    return n.fromPackageLockNested(root.Dependencies, nodeModulesDir), nil
default:
    if root.Packages != nil {
        return n.fromPackageLockFlat(root.Packages, nodeModulesDir), nil
    }
    return n.fromPackageLockNested(root.Dependencies, nodeModulesDir), nil
}
```

### The recursive struct — v1's nested dependencies

`pkgLockDep` contains a field whose type is `map[string]pkgLockDep` — itself.  This is legal in Go because the field is a map (a reference type), not a direct `pkgLockDep` value (which would have infinite size):

```go
type pkgLockDep struct {
    Version      string                `json:"version"`
    Dependencies map[string]pkgLockDep `json:"dependencies"` // ← recursive
}
```

The JSON for a v1 lockfile is a tree:

```json
{
  "dependencies": {
    "express": {
      "version": "4.18.2",
      "dependencies": {
        "accepts": {
          "version": "1.3.8"
        }
      }
    }
  }
}
```

`json.Unmarshal` follows the recursion naturally.  The parser mirrors this with a recursive `walkV1Deps` function:

```go
func (n *NodeParser) walkV1Deps(
    deps    map[string]pkgLockDep,
    depth   int,
    parents []string,
    out     *[]Package,
) {
    for name, dep := range deps {
        pkg := Package{
            Name:         name,
            Version:      dep.Version,
            IsTransitive: depth > 1,
            Depth:        depth,
            Parents:      append([]string(nil), parents...),
        }
        *out = append(*out, pkg)

        // recurse into this package's own dependencies
        if len(dep.Dependencies) > 0 {
            n.walkV1Deps(dep.Dependencies, depth+1, append(parents, name), out)
        }
    }
}
```

`append([]string(nil), parents...)` creates a *copy* of the parents slice.  This is critical: if you just wrote `Parents: parents`, every Package would share the same backing array, and appending to it for the next level would corrupt the parent records you already stored.

---

## 4. Error wrapping with `%w`

### The problem without wrapping

```go
// Without wrapping — you lose all context
return nil, err   // caller sees "no such file or directory"
```

When an error surfaces through three or four function calls, the original message `"no such file or directory"` tells you nothing about *which* file or *which* path triggered it.

### Wrapping with `fmt.Errorf` and `%w`

```go
// From NodeParser.parsePackageLock:
data, err := os.ReadFile(path)
if err != nil {
    return nil, fmt.Errorf("parsing %s: %w", path, err)
}
```

`%w` — unlike `%v` or `%s` — *wraps* the error.  The resulting error:
1. Has a string representation: `"parsing /home/user/project/package-lock.json: open /home/user/project/package-lock.json: no such file or directory"`
2. Still carries the original `*os.PathError` inside it, accessible via `errors.Unwrap()`.

### `ParseError` — a typed wrapper

Some errors in `parser.go` use the custom `ParseError` struct instead of `fmt.Errorf`:

```go
type ParseError struct {
    Path string
    Err  error
}

func (e *ParseError) Error() string {
    return fmt.Sprintf("parsing %s: %v", e.Path, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }
```

The difference: a `*ParseError` lets the caller *extract the path* programmatically, not just read it from a string.

### How a caller uses `errors.Is` and `errors.As`

```go
pkgs, err := p.Parse(dir)
if err != nil {
    // errors.Is unwraps until it finds a matching value.
    // Works through chains: ParseError → *os.PathError → syscall.ENOENT
    if errors.Is(err, os.ErrNotExist) {
        // The file was simply missing — not our bug.
        log.Warn("lockfile not found", zap.String("dir", dir))
        return nil, nil
    }

    // errors.As unwraps until it finds a value assignable to the target type.
    var pe *ParseError
    if errors.As(err, &pe) {
        // We have a *ParseError — we can read pe.Path.
        log.Error("parse failed", zap.String("file", pe.Path), zap.Error(pe.Err))
    }

    return nil, err
}
```

`errors.Is(err, target)` asks: is `target` anywhere in this error's chain?
`errors.As(err, &target)` asks: is there a value assignable to `target`'s type anywhere in the chain, and if so, assign it.

Both functions call `Unwrap()` repeatedly until they find a match or run out of chain.  That is why `ParseError.Unwrap()` is essential — without it, `errors.Is(parseErr, os.ErrNotExist)` would return `false` even though `os.ErrNotExist` is inside the wrapper.

### `%w` vs `%v` — when to use each

| Use | Verb | Why |
|-----|------|-----|
| You want callers to inspect the underlying error | `%w` | Preserves the error chain |
| You only need a human-readable message | `%v` | Simpler, no chain needed |
| You're logging the final error at the top level | Either | By then you've already unwrapped |

`ParseError.Error()` uses `%v` (not `%w`) because `Sprintf` doesn't wrap — `Sprintf` always formats to a string.  The wrapping happens through the `Unwrap()` method, not through the string.

---

## 5. Table-driven tests

### What they are and why Go uses them

Most Go test functions follow the same pattern: define a slice of test cases, iterate over them, run each one as a named sub-test.  This is called *table-driven testing*.

```go
func TestTomlStringValue(t *testing.T) {
    tests := []struct {
        line   string
        key    string
        want   string
        wantOK bool
    }{
        {`name = "serde"`,             "name",    "serde",   true},
        {`version = "1.0.0"`,          "version", "1.0.0",   true},
        {`source = "registry+https"`,  "name",    "",        false},
        {`name = no-quotes`,           "name",    "",        false},
        {``,                           "name",    "",        false},
    }
    for _, tt := range tests {
        got, ok := tomlStringValue(tt.line, tt.key)
        if ok != tt.wantOK || got != tt.want {
            t.Errorf("tomlStringValue(%q, %q) = (%q, %v), want (%q, %v)",
                tt.line, tt.key, got, ok, tt.want, tt.wantOK)
        }
    }
}
```

Benefits:
- **Readability**: the test cases read like a specification.  Add a row to add a case.
- **No duplication**: the assertion logic is written once.
- **All failures visible**: `t.Errorf` (not `t.Fatalf`) continues after a failure, so you see every broken case at once instead of stopping at the first.

### The `t.Run` sub-test variant

When test cases need setup code or you want them individually runnable, use `t.Run`:

```go
for _, tt := range tests {
    tt := tt // capture — required before Go 1.22 if you use t.Parallel()
    t.Run(tt.name, func(t *testing.T) {
        // each case gets its own t — failures are scoped to this sub-test
        got, ok := tomlStringValue(tt.line, tt.key)
        if ok != tt.wantOK {
            t.Errorf(...)
        }
    })
}
```

You can then run a single sub-test:

```bash
go test ./internal/parser/... -run TestTomlStringValue/name_=_"serde"
```

The parser tests use direct `t.Errorf` calls (without `t.Run`) for most cases because each test function covers one named scenario — the function name itself is the label.

### Testing the NodeParser's v1 lockfile — reading a full test

```go
func TestNodeParser_PackageLockV1_DirectAndTransitive(t *testing.T) {
    // 1. Create an isolated temp directory — cleaned up when the test ends.
    root := t.TempDir()

    // 2. Build the directory structure the parser expects.
    nm := mkdir(t, root, "node_modules")

    // 3. Write a realistic package-lock.json v1 fixture.
    writeFile(t, filepath.Join(root, "package-lock.json"), `{
        "lockfileVersion": 1,
        "dependencies": {
            "express": {
                "version": "4.18.2",
                "dependencies": {
                    "accepts": {"version": "1.3.8"}
                }
            },
            "lodash": {"version": "4.17.21"}
        }
    }`)

    // 4. Instantiate the parser directly — no Dispatcher needed.
    p := &NodeParser{log: nopLog()}
    pkgs, err := p.Parse(nm)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    // 5. Assert on specific packages.
    express, ok := findPkg(pkgs, "express")
    if !ok {
        t.Fatal("express not found")
    }
    if express.IsTransitive {
        t.Error("express should be direct (depth=1)")
    }
    if express.Depth != 1 {
        t.Errorf("express depth: got %d, want 1", express.Depth)
    }

    accepts, ok := findPkg(pkgs, "accepts")
    if !ok {
        t.Fatal("accepts not found")
    }
    if !accepts.IsTransitive {
        t.Error("accepts should be transitive")
    }
    if accepts.Depth != 2 {
        t.Errorf("accepts depth: got %d, want 2", accepts.Depth)
    }
    if len(accepts.Parents) == 0 || accepts.Parents[0] != "express" {
        t.Errorf("accepts parents: got %v, want [express]", accepts.Parents)
    }
}
```

**Why `t.Fatal` vs `t.Error`?**

| Function | Stops the test? | Use when |
|----------|----------------|----------|
| `t.Fatalf` | Yes | A prerequisite failed (e.g. package not found — subsequent checks have no object to check) |
| `t.Errorf` | No | A specific field is wrong — continue to see all broken fields |

In the test above, `t.Fatal("express not found")` stops immediately because there is nothing to check about a package that doesn't exist.  But `t.Error("express should be direct")` continues so we can see if `Depth` is also wrong.

**Why `nopLog()`?**

`nopLog()` returns `zap.NewNop()`, a logger that discards all output.  Tests should produce no output on success — noisy tests make it hard to spot real failures.

**`t.TempDir()` — automatic cleanup**

`t.TempDir()` creates a temp directory and registers a cleanup function with `t.Cleanup()`.  When the test ends (pass or fail), the directory is deleted.  This means tests can write files freely without leaving debris and without needing explicit cleanup code.

### Test helpers — `mkdir`, `writeFile`, `findPkg`

```go
func mkdir(t *testing.T, parts ...string) string {
    t.Helper()
    p := filepath.Join(parts...)
    if err := os.MkdirAll(p, 0o755); err != nil {
        t.Fatalf("mkdir %s: %v", p, err)
    }
    return p
}
```

`t.Helper()` marks this as a helper function.  When a helper calls `t.Fatalf`, the failure is reported at the *call site* in the test, not inside the helper — so you see the test line number, not line 22 in the helper.  Without `t.Helper()`, all failures would appear to come from inside `mkdir`.

---

## Debug this

### Silent empty results: the v1 vs v3 format trap

**Symptom:** The parser returns 0 packages, no error.  You know there's a lockfile.

**Cause:** A `package-lock.json` with `lockfileVersion: 3` but no `packages` key (e.g. an unusual generator) hits the `default` branch and falls through to `fromPackageLockNested(root.Dependencies, ...)`.  `Dependencies` is `nil` because v3 doesn't use that key.  The recursive walk receives a nil map, produces nothing, and returns cleanly.

**How to add a version check assertion in tests:**

```go
func TestNodeParser_PackageLockVersionIsRecognised(t *testing.T) {
    tests := []struct {
        name    string
        content string
        wantN   int
    }{
        {
            name: "v1_nested",
            content: `{
                "lockfileVersion": 1,
                "dependencies": {
                    "lodash": {"version": "4.17.21"}
                }
            }`,
            wantN: 1,
        },
        {
            name: "v2_flat",
            content: `{
                "lockfileVersion": 2,
                "packages": {
                    "node_modules/lodash": {"version": "4.17.21"}
                }
            }`,
            wantN: 1,
        },
        {
            name: "v3_flat",
            content: `{
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/lodash": {"version": "4.17.21"}
                }
            }`,
            wantN: 1,
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            root := t.TempDir()
            nm := mkdir(t, root, "node_modules")
            writeFile(t, filepath.Join(root, "package-lock.json"), tt.content)

            p := &NodeParser{log: nopLog()}
            pkgs, err := p.Parse(nm)
            if err != nil {
                t.Fatalf("unexpected error: %v", err)
            }
            if len(pkgs) != tt.wantN {
                // This makes the problem visible:
                t.Errorf("[%s] got %d packages, want %d — check lockfileVersion routing",
                    tt.name, len(pkgs), tt.wantN)
            }
        })
    }
}
```

**Debugging the routing logic itself:**

Add a temporary log line immediately after the `switch`:

```go
func (n *NodeParser) parsePackageLock(path, nmDir string) ([]Package, error) {
    // ...
    switch {
    case root.LockfileVersion >= 2 && root.Packages != nil:
        fmt.Printf("DEBUG: v2/v3 flat path, %d package entries\n", len(root.Packages))
        return n.fromPackageLockFlat(root.Packages, nmDir), nil
    case root.LockfileVersion == 1 || root.Dependencies != nil:
        fmt.Printf("DEBUG: v1 nested path, %d dep entries\n", len(root.Dependencies))
        return n.fromPackageLockNested(root.Dependencies, nmDir), nil
    default:
        fmt.Printf("DEBUG: default path — packages=%d, deps=%d\n",
            len(root.Packages), len(root.Dependencies))
        // ...
    }
}
```

Remove debug prints before committing.  The production way is to use the zap logger:

```go
n.log.Debug("lockfile routing",
    zap.Int("version", root.LockfileVersion),
    zap.Int("packages", len(root.Packages)),
    zap.Int("dependencies", len(root.Dependencies)))
```

Then run with `dep-shield scan --debug` to enable the DEBUG level.

### Running just the parser tests

```bash
# All tests in the parser package
go test ./internal/parser/...

# Verbose — show each test name and PASS/FAIL
go test ./internal/parser/... -v

# Run one specific test function
go test ./internal/parser/... -run TestNodeParser_PackageLockV1_DirectAndTransitive

# Run all NodeParser tests (prefix match)
go test ./internal/parser/... -run TestNodeParser

# Run with race detector — catches concurrent map access bugs
go test ./internal/parser/... -race

# Run with coverage — shows which lines are exercised
go test ./internal/parser/... -cover

# Open a coverage report in your browser
go test ./internal/parser/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Adding a new ecosystem parser — Ruby `Gemfile.lock`

Here is the complete step-by-step process.  Use this whenever dep-shield needs to support a new ecosystem.

**Step 1 — Understand the file format.**

A Gemfile.lock looks like this:

```
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.6)
      actionview (= 7.0.6)
      rack (~> 2.2, >= 2.2.4)
    actionview (7.0.6)
      builder (~> 3.1)
    rack (2.2.7)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  actionpack (~> 7.0)
```

The `GEM` block lists all resolved versions.
The `DEPENDENCIES` block lists what the project directly requires.

**Step 2 — Add the ecosystem constant to `models/models.go`.**

```go
const (
    EcosystemNPM   Ecosystem = "npm"
    EcosystemGo    Ecosystem = "Go"
    EcosystemCargo Ecosystem = "crates.io"
    EcosystemPyPI  Ecosystem = "PyPI"
    EcosystemRuby  Ecosystem = "RubyGems"   // ← add this
)
```

**Step 3 — Teach the scanner to recognise Ruby projects.**

In `internal/scanner/scanner.go`, add a detection rule.  The scanner looks for directory names like `node_modules`, `vendor`, `.venv` — add a check for paths containing a `Gemfile.lock`:

```go
// In the classify() function, add a case for vendor/bundle (Bundler's install dir)
// or detect projects by checking for Gemfile.lock in the parent.
```

The exact change depends on how Bundler installs gems (typically into `vendor/bundle/ruby/<version>/gems/` or a shared gem path).  For now you can emit a DirHit for any directory that is the parent of a `Gemfile.lock`.

**Step 4 — Write the parser struct.**

Create the new type in `internal/parser/parser.go` (or a new file `internal/parser/ruby.go` if it grows large):

```go
// GemfileParser reads Gemfile.lock (Bundler format).
type GemfileParser struct {
    log *zap.Logger
}

func (g *GemfileParser) Ecosystem() string { return string(models.EcosystemRuby) }

func (g *GemfileParser) Parse(dir string) ([]Package, error) {
    path := filepath.Join(dir, "Gemfile.lock")
    f, err := os.Open(path)
    if err != nil {
        if os.IsNotExist(err) {
            return nil, nil
        }
        return nil, fmt.Errorf("parsing %s: %w", path, err)
    }
    defer f.Close()

    return g.parseGemfileLock(f, path, dir)
}

func (g *GemfileParser) parseGemfileLock(f *os.File, path, dir string) ([]Package, error) {
    // The DEPENDENCIES section tells us which gems are direct deps.
    // Parse it first, then parse GEM specs.
    directNames := g.parseDependenciesSection(f)

    // Reset to start of file.
    f.Seek(0, 0)

    // Parse the GEM / specs block for resolved versions.
    return g.parseGEMSpecs(f, path, dir, directNames)
}

func (g *GemfileParser) parseDependenciesSection(f *os.File) map[string]bool {
    direct := make(map[string]bool)
    inDeps := false
    sc := bufio.NewScanner(f)
    for sc.Scan() {
        line := sc.Text()
        if line == "DEPENDENCIES" {
            inDeps = true
            continue
        }
        // New section starts at column 0 with an upper-case word
        if inDeps && len(line) > 0 && line[0] != ' ' {
            break
        }
        if inDeps && strings.HasPrefix(line, "  ") {
            // "  actionpack (~> 7.0)"
            parts := strings.Fields(strings.TrimSpace(line))
            if len(parts) > 0 {
                direct[parts[0]] = true
            }
        }
    }
    return direct
}

func (g *GemfileParser) parseGEMSpecs(
    f *os.File, path, dir string, directNames map[string]bool,
) ([]Package, error) {
    inSpecs := false
    var out []Package
    sc := bufio.NewScanner(f)

    for sc.Scan() {
        line := sc.Text()
        if strings.TrimSpace(line) == "specs:" {
            inSpecs = true
            continue
        }
        if inSpecs && len(line) > 0 && line[0] != ' ' {
            break // left the GEM block
        }
        if inSpecs && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") {
            // "    actionpack (7.0.6)"
            content := strings.TrimSpace(line)
            lparen := strings.Index(content, " (")
            if lparen < 0 {
                continue
            }
            name := content[:lparen]
            version := strings.Trim(content[lparen+2:], "()")

            isDirect := directNames[name]
            out = append(out, Package{
                Name:            name,
                Version:         version,
                Ecosystem:       string(models.EcosystemRuby),
                ResolvedVersion: version,
                IsTransitive:    !isDirect,
                Depth:           ternary(isDirect, 1, 2),
            })
        }
    }

    if err := sc.Err(); err != nil {
        return nil, fmt.Errorf("parsing %s: %w", path, err)
    }
    return out, nil
}
```

**Step 5 — Register the parser in `New()`.**

```go
func New(log *zap.Logger) Dispatcher {
    // ...
    for _, p := range []Parser{
        &NodeParser{log: log},
        &GoParser{log: log},
        &CargoParser{log: log},
        &PythonParser{log: log},
        &GemfileParser{log: log},   // ← add this line
    } {
        d.parsers[models.Ecosystem(p.Ecosystem())] = p
    }
    return d
}
```

The `Dispatcher` picks it up automatically — no other changes needed.

**Step 6 — Write the tests.**

Create test functions following the existing pattern:

```go
func TestGemfileParser_Ecosystem(t *testing.T) {
    p := &GemfileParser{log: nopLog()}
    if p.Ecosystem() != "RubyGems" {
        t.Fatalf("expected RubyGems, got %s", p.Ecosystem())
    }
}

func TestGemfileParser_Parse_DirectAndTransitive(t *testing.T) {
    root := t.TempDir()
    writeFile(t, filepath.Join(root, "Gemfile.lock"), `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.6)
      rack (~> 2.2)
    rack (2.2.7)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  actionpack (~> 7.0)
`)

    p := &GemfileParser{log: nopLog()}
    pkgs, err := p.Parse(root)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    ap, ok := findPkg(pkgs, "actionpack")
    if !ok { t.Fatal("actionpack not found") }
    if ap.IsTransitive { t.Error("actionpack should be direct") }

    rack, ok := findPkg(pkgs, "rack")
    if !ok { t.Fatal("rack not found") }
    if !rack.IsTransitive { t.Error("rack should be transitive") }
}

func TestGemfileParser_Parse_MissingFile(t *testing.T) {
    root := t.TempDir()
    p := &GemfileParser{log: nopLog()}
    pkgs, err := p.Parse(root)
    if err != nil {
        t.Fatalf("missing Gemfile.lock should not error: %v", err)
    }
    if pkgs != nil {
        t.Errorf("expected nil, got %v", pkgs)
    }
}
```

**Step 7 — Run all tests to make sure nothing broke.**

```bash
go test ./... -race
```

You should see the new parser tests pass and all existing tests continue passing.  The only files you touched were `models.go` (one constant), `scanner.go` (one detection rule), and `parser.go` (new type + one line in `New()`).  That is the interface design paying off.

---

## Exercises

1. **Trace a `Package` from disk to advisory query.**  Starting from `dispatcher.ParseAll()` in `cmd/dep-shield/root/scan.go`, follow exactly how a `package-lock.json` entry becomes a `models.Package` passed to `advisory.Client.QueryAll()`.  Write down every type conversion and function call.

2. **Add the `omitempty` tag.**  Change `pkgLockFlat.Dev` to `json:"dev,omitempty"`.  Does anything break?  Why or why not?  (Hint: `omitempty` affects marshalling — encoding a Go struct to JSON — not unmarshalling.)

3. **Implement `errors.As` in a test.**  Write a test that deliberately triggers a `*ParseError` (e.g. pass a directory with a malformed `Cargo.lock`), then use `errors.As` to extract the `ParseError` and assert that `pe.Path` ends with `"Cargo.lock"`.

4. **Make the Dispatcher return all parse errors.**  Currently `ParseAll` logs per-hit errors and continues.  Add a second return value `[]error` that collects every non-nil error without aborting.  Update the caller in `scan.go` to log the collected errors at the end.

5. **Benchmark JSON unmarshalling.**  Write a `BenchmarkParsePackageLock` that calls `parsePackageLock` on a fixture file with 500 packages.  Run with `go test -bench=. -benchmem ./internal/parser/...`.  Then try replacing `os.ReadFile` + `json.Unmarshal` with `json.NewDecoder(f).Decode(&root)` (streaming decode) and measure whether memory allocations change.
