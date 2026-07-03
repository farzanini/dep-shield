# Guide 01 — Project Structure & Core Go Concepts

**Files this guide covers:**
`go.mod` · `main.go` · `cmd/root.go` · `cmd/scan.go` · `internal/parser/parser.go` · `internal/scanner/scanner.go`

**Prerequisite knowledge:** You should be comfortable with the idea that programs
are made of files, that functions take inputs and return outputs, and that you can
run commands in a terminal. No prior Go knowledge required.

---

## Table of Contents

1. [The module system — what `go.mod` actually is](#1-the-module-system--what-gomod-actually-is)
2. [The directory layout — what lives where and why](#2-the-directory-layout--what-lives-where-and-why)
3. [Why `internal/` is special in Go](#3-why-internal-is-special-in-go)
4. [`package main` and `func main()` — the program's front door](#4-package-main-and-func-main--the-programs-front-door)
5. [What a package is — `package scanner` vs `package main`](#5-what-a-package-is--package-scanner-vs-package-main)
6. [How cobra structures a CLI — `root.go` and `scan.go`](#6-how-cobra-structures-a-cli--rootgo-and-scango)
7. [Interfaces — the most important concept in Go](#7-interfaces--the-most-important-concept-in-go)
8. [Running the project locally](#8-running-the-project-locally)
9. [Debug this — fixing common `go build` errors](#9-debug-this--fixing-common-go-build-errors)
10. [Exercises](#10-exercises)

---

## 1. The module system — what `go.mod` actually is

Open `go.mod`. Here is the whole file:

```
module github.com/farzanini/dep-shield

go 1.25.0

require (
    github.com/fatih/color v1.19.0       // terminal colour output
    github.com/spf13/cobra v1.8.1        // CLI framework
    go.uber.org/zap v1.27.0              // structured logging
    golang.org/x/sync v0.7.0             // errgroup + semaphore
)

require (
    github.com/inconshreveable/mousetrap v1.1.0 // indirect
    github.com/mattn/go-colorable v0.1.14        // indirect
    ...
)
```

There are four things to understand here.

### 1a. The module name

```
module github.com/farzanini/dep-shield
```

This is the **module path** — a globally unique name for the whole project.
It looks like a URL, and Go uses it exactly like a URL when two projects need
to import each other. But it does *not* need to be a real website. It is just
a name that will never collide with anyone else's module.

Every `import` statement inside dep-shield that starts with
`github.com/farzanini/dep-shield/` refers to *this* project, not the internet.

```go
// In cmd/scan.go — importing our own internal/parser package:
import "github.com/farzanini/dep-shield/internal/parser"
//      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  this module
//                                        ^^^^^^^^^^^^^^^ this sub-directory
```

**Comparison with other ecosystems:**

| Ecosystem | Identity file | How packages are named |
|-----------|---------------|------------------------|
| npm       | `package.json` (`"name"`) | `lodash`, `@babel/core` |
| pip       | `pyproject.toml` / `setup.py` | `requests`, `flask` |
| Cargo     | `Cargo.toml` (`[package] name`) | `tokio`, `serde` |
| **Go**    | **`go.mod`** (`module …`) | **full URL-style path** |

Go's URL-style names are verbose but eliminate the class of bugs where two
packages accidentally have the same name.

### 1b. The Go version

```
go 1.25.0
```

This pins the *minimum* Go toolchain version this module needs. If someone
tries to build dep-shield with Go 1.19 they get a clear error rather than
mysterious compile failures. Think of it as `engines` in `package.json` or
`python_requires` in `setup.py`.

### 1c. Direct dependencies — `require`

The first `require` block lists packages this project explicitly `import`s:

```
github.com/spf13/cobra v1.8.1   // CLI framework — we call this in cmd/root.go
go.uber.org/zap v1.27.0         // structured logger — we call this everywhere
```

### 1d. Indirect dependencies — `// indirect`

The second `require` block lists packages that *our* dependencies need, but
we never import directly. You did not write these — `go mod tidy` computed them.

```
github.com/mattn/go-colorable v0.1.14 // indirect
```

`go-colorable` is a dependency of `fatih/color`. We never `import` it ourselves,
but Go needs to know its exact version to build a reproducible binary.

**Key difference from npm `node_modules`:** Go downloads source code into a
global cache (`~/go/pkg/mod/`) once, then reuses it across all your projects.
You do *not* have a `vendor/` directory checked into each project by default.
Running `go mod tidy` reads `go.mod` and produces `go.sum` (a file of
cryptographic checksums that lock every dependency's content, similar to
`package-lock.json` or `Cargo.lock`).

---

## 2. The directory layout — what lives where and why

```
dep-shield/
├── main.go                  ← program entry point (one file, ~15 lines)
├── go.mod                   ← module identity + dependency list
├── go.sum                   ← cryptographic checksums (do not edit by hand)
│
├── cmd/                     ← CLI commands (what the user types)
│   ├── root.go              ← "dep-shield" command + global flags
│   ├── scan.go              ← "dep-shield scan" sub-command
│   └── report.go            ← "dep-shield report" sub-command
│
├── internal/                ← business logic (hidden from outside callers)
│   ├── scanner/scanner.go   ← filesystem walker
│   ├── parser/parser.go     ← lockfile readers
│   ├── cve/client.go        ← CVE database queries
│   ├── scorer/scorer.go     ← risk scoring
│   ├── reporter/reporter.go ← terminal + HTML output
│   └── models/models.go     ← shared data types
│
└── docs/
    └── learning/            ← these guides
```

The three layers correspond to three levels of abstraction:

```
main.go          — I/O boundary: talks to the OS (args, exit codes)
cmd/             — User interface: parses flags, calls the pipeline
internal/        — Business logic: does the actual work
```

This separation means you can change the CLI flags without touching the CVE
query logic, or swap the scoring algorithm without touching the reporter.

---

## 3. Why `internal/` is special in Go

`internal/` is not a convention — it is enforced by the Go compiler.

**The rule:** Code inside `internal/` can only be imported by code in the
parent directory and its children.

For dep-shield, the parent of `internal/` is the module root
(`github.com/farzanini/dep-shield`). So:

```
✅  cmd/scan.go       can import  internal/parser
✅  internal/cve      can import  internal/models
✅  main.go           can import  internal/reporter

❌  github.com/someone-else/their-tool  CANNOT import  internal/parser
```

If someone writes a Go program that tries to `import "github.com/farzanini/dep-shield/internal/parser"`,
the Go compiler refuses with:

```
use of internal package github.com/farzanini/dep-shield/internal/parser
not allowed
```

**Why does this matter?** Without `internal/`, if you published dep-shield as
a library, other people could start importing your internal types. You would
then be unable to rename or restructure them without breaking those callers.
`internal/` gives you freedom to refactor your own code without worrying about
external compatibility.

**Comparison with other ecosystems:**

| Ecosystem | How to hide implementation details |
|-----------|------------------------------------|
| Python | `_` prefix (`_my_private_func`) — convention only, not enforced |
| JavaScript | No official mechanism; bundlers handle it |
| Rust | `pub(crate)` — similar concept, also compiler-enforced |
| **Go** | **`internal/` directory — compiler-enforced at the path level** |

---

## 4. `package main` and `func main()` — the program's front door

Open `main.go`:

```go
package main                              // ← (1)

import (
    "os"
    "github.com/farzanini/dep-shield/cmd"
)

func main() {                             // ← (2)
    if err := cmd.Execute(); err != nil { // ← (3)
        os.Exit(1)                        // ← (4)
    }
}
```

**(1) `package main`** — Every Go file belongs to a package. The special name
`main` tells the compiler: "this package produces an executable binary".
If you change this to `package anything_else`, `go build` will build a library
instead of a runnable program.

**(2) `func main()`** — The function the OS calls when you run `./dep-shield`.
There is exactly one `func main()` in the whole program. Its signature is
fixed — no parameters, no return value. Arguments come from `os.Args`;
exit codes come from `os.Exit()`.

**(3) `cmd.Execute()`** — This calls into `cmd/root.go`. Notice we are calling
a function exported from *our own* `cmd` package — not a standard library
function. `Execute()` starts with a capital letter, which in Go means it is
exported (visible outside the package). Lowercase names are package-private.

**(4) `os.Exit(1)`** — Terminates the process with exit code 1. We only do
this here, in `main.go`. Deeper code (inside `internal/`) must never call
`os.Exit` — it would kill the program without any chance to clean up, and it
makes testing impossible.

**Why is `main.go` so small?** Keeping `main.go` thin is a deliberate choice.
It is the only place in the codebase that cannot be tested (you can't call
`main()` from a test). By pushing all logic into `cmd/` and `internal/`, we
maximise the amount of code that *can* be tested.

---

## 5. What a package is — `package scanner` vs `package main`

Every `.go` file starts with a `package` declaration. All files in the same
directory must declare the same package name (except test files ending in
`_test.go`, which may use `package scanner_test`).

```
internal/scanner/scanner.go    → package scanner
internal/scanner/scanner_test.go → package scanner_test
internal/parser/parser.go      → package parser
internal/models/models.go      → package models
cmd/root.go                    → package cmd
cmd/scan.go                    → package cmd     (same package, different file)
main.go                        → package main
```

A package is both a **namespace** (prevents name collisions) and a
**compilation unit** (Go compiles one package at a time).

### Exporting names: Capital letter = public

```go
// In internal/parser/parser.go:

type Parser interface { … }    // ← exported: usable from cmd/scan.go
type ParseError struct { … }   // ← exported: usable from cmd/scan.go
type dispatcher struct { … }   // ← unexported: only usable inside package parser

func New(log *zap.Logger) Dispatcher { … }  // ← exported
func (d *dispatcher) ParseAll(…) { … }     // ← exported (method on unexported type — allowed)
```

The capital-letter rule replaces `public`/`private` keywords from other languages.
It applies to: types, functions, methods, variables, constants, and struct fields.

### How one package uses another

```go
// In cmd/scan.go:
import "github.com/farzanini/dep-shield/internal/parser"

// Now we can use everything exported from package parser:
p := parser.New(log)              // call exported function
pkgs, err := p.ParseAll(ctx, hits) // call method on returned value
```

The import path is the module name + the directory path from the module root.
`internal/parser` → `github.com/farzanini/dep-shield/internal/parser`.

---

## 6. How cobra structures a CLI — `root.go` and `scan.go`

[Cobra](https://github.com/spf13/cobra) is the Go library that turns function
calls into CLI commands. Every `git`, `kubectl`, and `docker` sub-command style
tool in the Go ecosystem uses it.

### The command tree

```
dep-shield           ← rootCmd    (defined in cmd/root.go)
├── scan             ← scanCmd    (defined in cmd/scan.go)
├── report           ← reportCmd  (defined in cmd/report.go)
└── version          ← versionCmd (defined in cmd/root.go)
```

When you run `dep-shield scan --min-severity HIGH /srv/app`, cobra:
1. Matches `scan` to `scanCmd`
2. Parses `--min-severity HIGH` into `sf.MinSeverity`
3. Passes `/srv/app` as a positional argument
4. Calls `scanCmd.RunE`

### `root.go` — the parent command

```go
// cmd/root.go

var rootCmd = &cobra.Command{
    Use:   "dep-shield",
    Short: "Scan your system for vulnerable dependencies",
    Long:  `dep-shield walks your filesystem …`,

    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        return initLogger(flags.Debug)   // runs before EVERY sub-command
    },
}

func init() {
    // PersistentFlags are inherited by ALL sub-commands automatically.
    pf := rootCmd.PersistentFlags()
    pf.BoolVar(&flags.Debug,    "debug",     false, "enable debug logging")
    pf.BoolVar(&flags.NoColour, "no-colour", false, "disable ANSI colour")

    // Wire up sub-commands:
    rootCmd.AddCommand(scanCmd())
    rootCmd.AddCommand(reportCmd())
}
```

**`PersistentFlags`** — flags that work on every sub-command.
`dep-shield --debug scan` and `dep-shield scan --debug` both work.

**`PersistentPreRunE`** — a function cobra calls *before* the sub-command's
`RunE`. We use it to initialise the logger, because by the time it runs,
`--debug` has already been parsed.

**`init()`** — a special Go function that runs automatically when the package
is loaded, before `main()`. We use it to register sub-commands and flags.
You cannot call `init()` yourself; Go calls it for you.

### `scan.go` — a sub-command

```go
// cmd/scan.go

func scanCmd() *cobra.Command {
    sf := scanFlags{MinSeverity: "LOW", Workers: runtime.NumCPU() * 2}

    cmd := &cobra.Command{
        Use:  "scan [paths...]",
        RunE: func(cmd *cobra.Command, args []string) error {
            return runScan(cmd.Context(), sf)  // all logic lives here
        },
    }

    // Local flags — only visible on "dep-shield scan", not on "dep-shield report".
    cmd.Flags().StringVar(&sf.MinSeverity, "min-severity", "LOW", "…")
    return cmd
}
```

Notice that `scanCmd()` is a **function that returns a command**, not a variable.
This pattern is used so that the `sf` (scanFlags) struct is created fresh each
time the command is called, instead of being a shared package-level variable
that accumulates state between invocations (important in tests).

**`RunE` vs `Run`:** If your function can fail, use `RunE` (returns `error`).
Cobra prints the error and sets exit code 1 for you. `Run` (no return value)
is only for commands that cannot fail, like `version`.

---

## 7. Interfaces — the most important concept in Go

An interface in Go is a **list of method signatures**. Any type that has those
methods automatically satisfies the interface — no `implements` keyword needed.

### The `Parser` interface from our code

Open `internal/parser/parser.go`:

```go
// Parser extracts Package records from one matched directory.
// Every ecosystem (npm, go, cargo, pip) implements this interface.
type Parser interface {
    Ecosystem() models.Ecosystem
    Parse(ctx context.Context, dir string) ([]models.Package, error)
}
```

This says: *"A Parser is anything that has an `Ecosystem()` method and a
`Parse()` method with those exact signatures."*

Now look at the concrete types:

```go
type npmParser struct { log *zap.Logger }

func (n *npmParser) Ecosystem() models.Ecosystem { return models.EcosystemNPM }
func (n *npmParser) Parse(ctx context.Context, dir string) ([]models.Package, error) {
    // TODO: read package.json files
}

type goSumParser struct { log *zap.Logger }

func (g *goSumParser) Ecosystem() models.Ecosystem { return models.EcosystemGo }
func (g *goSumParser) Parse(ctx context.Context, dir string) ([]models.Package, error) {
    // TODO: read go.sum files
}
```

Both `*npmParser` and `*goSumParser` implement `Parser` because they both have
`Ecosystem()` and `Parse()` with matching signatures. Go figures this out at
compile time — you never write `npmParser implements Parser`.

### Why this matters in dep-shield

The `Dispatcher` stores a map of parsers:

```go
type dispatcher struct {
    parsers map[models.Ecosystem]Parser  // value type is the interface
    log     *zap.Logger
}
```

This means `dispatcher` can hold *any* type that satisfies `Parser`. The
`ParseAll` loop calls `p.Parse(ctx, hit.Path)` without knowing or caring
whether `p` is an npm parser, a Go parser, or a hypothetical Maven parser
added next year:

```go
for _, hit := range hits {
    p, ok := d.parsers[hit.Ecosystem]  // p has type Parser (the interface)
    if !ok { continue }
    pkgs, err := p.Parse(ctx, hit.Path) // works for ALL ecosystems
```

**What interfaces prevent:** Without interfaces, `ParseAll` would need a
`switch` statement for every ecosystem:

```go
// WITHOUT interfaces — must be updated every time a new ecosystem is added:
switch hit.Ecosystem {
case models.EcosystemNPM:
    pkgs, err = parseNPM(ctx, hit.Path)
case models.EcosystemGo:
    pkgs, err = parseGo(ctx, hit.Path)
// ... add Maven, NuGet, RubyGems, Hex, ...
}
```

With the interface, adding Maven support means writing one struct that satisfies
`Parser` and registering it in `New()`. The `ParseAll` loop never changes.

### The same pattern repeats everywhere in dep-shield

```go
// internal/scanner/scanner.go
type Detector interface { Ecosystem() models.Ecosystem; Match(dir string) bool }
type Walker   interface { Walk(ctx context.Context) ([]DirHit, error) }

// internal/cve/client.go
type Source   interface { Name() string; Query(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error) }

// internal/reporter/reporter.go
type Reporter interface { Write(w io.Writer, result models.ScanResult) error; WriteFile(…) error }

// internal/scorer/scorer.go
type Scorer   interface { Score(vulns []models.Vulnerability, min models.Severity) (models.ScanResult, error) }
```

Every major "seam" in the program is an interface. This means every package
can be tested in isolation by swapping the real implementation for a fake one.

---

## 8. Running the project locally

### Prerequisites

```bash
go version   # must print go1.22 or higher
```

If you don't have Go installed: https://go.dev/dl/ — download the installer
for your OS, run it, then open a new terminal.

### Method 1 — `go run` (development only)

```bash
cd dep-shield

# Run without building a binary first:
go run . version          # prints: dep-shield dev
go run . scan --help      # prints scan sub-command help
go run . scan /tmp        # scan the /tmp directory
```

`go run .` compiles the code in memory and runs it immediately. The `.` means
"the package in the current directory" (which is `package main` in `main.go`).
There is no output binary — it disappears after the program exits.

Use `go run` while you are making frequent changes. It is slightly slower to
start than a pre-built binary but saves you from remembering to rebuild.

### Method 2 — `go build` (the real binary)

```bash
go build -o dep-shield .
```

This produces a binary named `dep-shield` (or `dep-shield.exe` on Windows)
in the current directory. Run it directly:

```bash
./dep-shield version
./dep-shield scan --help
./dep-shield scan --min-severity HIGH ~/projects
```

### Method 3 — Static binary for distribution

```bash
CGO_ENABLED=0 go build \
  -ldflags="-s -w -X github.com/farzanini/dep-shield/cmd.Version=v0.1.0" \
  -o dep-shield .
```

| Flag | What it does |
|------|-------------|
| `CGO_ENABLED=0` | Disables C extensions. Binary links nothing at runtime. Copy it to any Linux/Mac and it runs. |
| `-ldflags="-s -w"` | `-s` strips symbol table. `-w` strips DWARF debug info. Shrinks binary ~30%. |
| `-X …cmd.Version=v0.1.0` | Sets the `Version` variable in `cmd/root.go` at link time — no source change needed. |

### Running the tests

```bash
go test ./...          # run all tests in all packages
go test ./internal/... # run only tests inside internal/
go test -v ./internal/scanner/...  # verbose: shows each test name
go test -run TestWalk  # run only tests whose name contains "TestWalk"
```

### Other useful commands

```bash
go vet ./...    # static analysis — catches common bugs the compiler misses
go fmt ./...    # auto-format all files (like prettier for Go)
go mod tidy     # add missing / remove unused entries in go.mod and go.sum
go doc internal/parser  # show docs for the parser package
```

---

## 9. Debug this — fixing common `go build` errors

### Error: `cannot find module providing package …`

```
no required module provides package github.com/some/new-dep
```

**Cause:** You added an `import` but haven't run `go mod tidy`.

**Fix:**
```bash
go mod tidy
go build ./...
```

`go mod tidy` downloads any missing dependencies and adds them to `go.mod`.

---

### Error: `imported and not used`

```
./cmd/scan.go:8:2: "fmt" imported and not used
```

**Cause:** Go treats unused imports as *compilation errors*, not warnings.
This is intentional — unused imports slow down compilation and indicate dead code.

**Fix:** Remove the import line, or if you added it as a placeholder, suppress
it with a blank identifier (only acceptable in stub/TODO code):

```go
import _ "fmt"   // keeps the import without using it — only for stub code
```

Or just delete it if you don't need it yet.

---

### Error: `undefined: scanner.Deduplicate`

```
cmd/dep-shield/root/scan.go:63:8: undefined: scanner.Deduplicate
```

**Cause:** You are calling a function that no longer exists. This happened in
our project when `scanner.go` was rewritten with the new `Walker` API.

**Diagnosis steps:**
```bash
# 1. Find what the package actually exports:
go doc github.com/farzanini/dep-shield/internal/scanner

# 2. Search for the old function name:
grep -r "Deduplicate" ./internal/scanner/

# 3. Check git history to see what changed:
git log --oneline internal/scanner/
```

**Fix:** Update the calling code to use the new API.

---

### Error: `too many arguments in call to scanner.New`

```
cmd/dep-shield/root/scan.go:58:29: too many arguments in call to scanner.New
    have ([]string, *zap.Logger)
    want (scanner.Options)
```

**Cause:** The function signature changed. The old `New(paths, log)` became
`New(scanner.Options{…})` (an options struct).

**Fix:** Change the call site to pass an `Options` struct:

```go
// Old (broken):
sc := scanner.New(paths, log)

// New (correct):
sc := scanner.New(scanner.Options{
    Roots: paths,
    Log:   log,
})
```

---

### Error: `cannot use X (type *npmParser) as type Parser`

```
cannot use &npmParser{} (value of type *npmParser) as type Parser
    in assignment: *npmParser does not implement Parser
    (missing method Parse)
```

**Cause:** You declared a type intending it to implement `Parser`, but one or
more required methods are missing or have the wrong signature.

**Diagnosis:**
```bash
# Go 1.18+ has a better error message if you add this to your type:
var _ Parser = (*npmParser)(nil)   // compile-time assertion
```

This line does nothing at runtime but forces a compile error that lists *exactly*
which methods are missing.

**Fix:** Add the missing method with the exact signature from the interface:

```go
// The interface requires:
Parse(ctx context.Context, dir string) ([]models.Package, error)

// Make sure your implementation matches exactly:
func (n *npmParser) Parse(ctx context.Context, dir string) ([]models.Package, error) {
    // ...
}
```

---

### Error: `use of internal package … not allowed`

```
use of internal package github.com/farzanini/dep-shield/internal/parser not allowed
```

**Cause:** Something *outside* the module (a different project on your machine)
is trying to import our `internal/` packages.

**Fix:** You cannot fix this by changing code — it is intentional. If you need
to share types across projects, move them to a non-`internal` package or publish
a separate module.

---

### Error: `go: inconsistent vendoring`

```
go: inconsistent vendoring in /path/to/dep-shield:
    github.com/spf13/cobra@v1.8.1: is explicitly required in go.mod,
    but not marked as explicit in vendor/modules.txt
```

**Cause:** Someone ran `go mod vendor` to create a `vendor/` directory, then
updated `go.mod` without re-running `go mod vendor`.

**Fix:**
```bash
go mod vendor   # re-sync the vendor directory
# OR:
rm -rf vendor/  # delete vendor entirely (Go will download from cache)
go mod tidy
```

---

## 10. Exercises

These are small, targeted changes you can make to deepen your understanding.
After each one, run `go build ./...` and `go test ./...` to confirm nothing broke.

### Exercise 1 — Add a `--version` flag to `scan`

Currently, `dep-shield version` is its own sub-command.
Add `--version` as a flag to the `scan` sub-command that, when present, prints
the version and exits before doing any scanning.

**Hint:** Add `var showVersion bool` to `scanFlags`. In `RunE`, check it before
calling `runScan`. `cmd.Version` is accessible because both are in `package cmd`.

**What you will learn:** How cobra flags work, how to access package-level
variables across files in the same package, early-return patterns.

---

### Exercise 2 — Add a `Maven` ecosystem stub

Add a new ecosystem type to `internal/models/models.go`:

```go
const EcosystemMaven Ecosystem = "Maven"
```

Then add a `mavenParser` stub to `internal/parser/parser.go` that:
1. Implements the `Parser` interface
2. Returns `models.EcosystemMaven` from `Ecosystem()`
3. Has a `Parse` stub that returns a `fmt.Errorf("TODO: mavenParser …")` error

Register it in `New()` alongside the other parsers.

**What you will learn:** How the interface + registration pattern makes adding
a feature purely additive (you only add code, never change existing logic).

---

### Exercise 3 — Observe the `internal/` enforcement

Create a temporary file anywhere *outside* the `dep-shield` directory, for example:

```bash
mkdir /tmp/test-import
cat > /tmp/test-import/main.go << 'EOF'
package main

import (
    "fmt"
    "github.com/farzanini/dep-shield/internal/models"
)

func main() {
    fmt.Println(models.EcosystemNPM)
}
EOF
cd /tmp/test-import
go mod init test-import
go mod edit -replace github.com/farzanini/dep-shield=/path/to/your/dep-shield
go mod tidy
go build .
EOF
```

You will see:

```
use of internal package github.com/farzanini/dep-shield/internal/models not allowed
```

Now try importing `github.com/farzanini/dep-shield/cmd` instead (which is *not*
inside `internal/`). It will work. This is the exact boundary that `internal/`
enforces.

**What you will learn:** How Go's `internal/` enforcement works in practice,
and why it is more reliable than convention-based privacy in other languages.

---

*Next guide: [02 — Cobra CLI framework in depth](02-cobra-cli.md)*
