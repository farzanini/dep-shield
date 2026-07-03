# Guide 02 — The Scanner & Go Concurrency

**File this guide covers:** `internal/scanner/scanner.go`

**What this file does in one sentence:** It walks one or more directory trees
concurrently, identifies dependency directories by name or path, and streams
each match back to the caller the instant it is found — without waiting for
the entire filesystem walk to complete.

**Prerequisite:** Guide 01 (packages, interfaces, `go.mod`).
You should be comfortable with the idea of a function and a struct.

---

## Table of Contents

1. [Goroutines — what they are and how we use them](#1-goroutines--what-they-are-and-how-we-use-them)
2. [Channels — streaming results with `<-chan ScanResult`](#2-channels--streaming-results-with--chan-scanresult)
3. [sync.WaitGroup — waiting for all workers to finish](#3-syncwaitgroup--waiting-for-all-workers-to-finish)
4. [The worker pool pattern — ASCII diagram included](#4-the-worker-pool-pattern--ascii-diagram-included)
5. [filepath.WalkDir vs filepath.Walk — why we chose WalkDir](#5-filepathwalkdir-vs-filepathwalk--why-we-chose-walkdir)
6. [Error handling — why Go has no exceptions](#6-error-handling--why-go-has-no-exceptions)
7. [defer — every use in scanner.go explained](#7-defer--every-use-in-scannergo-explained)
8. [Debug this](#8-debug-this)
9. [Exercises](#9-exercises)

---

## 1. Goroutines — what they are and how we use them

### What a goroutine is

A goroutine is a function that runs concurrently with the rest of your program.
You create one by putting the keyword `go` in front of a function call:

```go
go someFunction()   // starts immediately, runs alongside your code
```

That is the entire syntax. No `Thread.start()`, no `async/await`, no executor
service. One keyword.

**How goroutines differ from OS threads:**

| Property | OS Thread | Goroutine |
|----------|-----------|-----------|
| Starting cost | ~1 MB stack, OS syscall | ~2 KB stack, no syscall |
| Switching cost | Kernel context switch | Cooperative, in user space |
| How many fit in RAM | Hundreds–low thousands | Hundreds of thousands |
| Managed by | Operating system | Go runtime scheduler |
| Blocking on I/O | Blocks the thread | Go parks the goroutine, runs another |

The key difference: when a goroutine blocks waiting for disk I/O (which is
exactly what our scanner does constantly), the Go runtime transparently parks
that goroutine and runs a different one. The OS thread underneath stays busy.
This is why Go programs can handle thousands of simultaneous I/O operations
with a handful of OS threads.

### Where our scanner spawns goroutines

There are **three** `go` statements in `scanner.go`. Find them:

**Goroutine 1 — the orchestrator (line 293):**

```go
func (s *impl) Scan(ctx context.Context) <-chan ScanResult {
    resultCh := make(chan ScanResult, resultBuf)

    go func() {           // ← goroutine 1 starts here
        defer close(resultCh)

        roots := s.effectiveRoots()
        // ... sets up work channel ...
        // ... starts worker goroutines ...
        wg.Wait()
        // resultCh closed by defer when this goroutine exits
    }()

    return resultCh       // ← returns immediately, BEFORE the walk starts
}
```

`Scan()` returns a channel to the caller, then this goroutine does all the
actual work in the background. The caller can start reading results
*before the walk is complete*.

Without this goroutine, `Scan()` would have to finish walking the entire
filesystem before returning anything — potentially minutes of silence before
the first result appears.

**Goroutines 2 through N+1 — the workers (line 312):**

```go
for i := 0; i < s.numWorkers; i++ {
    wg.Add(1)
    go func() {           // ← goroutine per worker
        defer wg.Done()
        for work := range workCh {
            s.walkRoot(ctx, work, resultCh)
        }
    }()
}
```

`s.numWorkers` goroutines are started. Each one loops: grab a root from
`workCh`, walk its entire directory tree, repeat until `workCh` is empty.
`runtime.NumCPU()` workers means we use all available CPU cores for
concurrent directory listing.

### Why one goroutine per directory *batch*, not per file

A naïve design might spawn one goroutine per file or per directory:

```go
// NAÏVE — do NOT do this
filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
    go func() { check(path) }()  // one goroutine per entry
    return nil
})
```

On a home directory with 500,000 files this creates 500,000 goroutines
simultaneously. Even at 2 KB each that is 1 GB of stack memory. The Go
scheduler then spends more time context-switching between goroutines than
doing actual work.

Our design spawns exactly `runtime.NumCPU()` worker goroutines — typically
8–16 — and each handles *an entire directory tree*. The filesystem walk is
I/O-bound (waiting for the OS to read directory entries), so `NumCPU` workers
saturate the I/O bandwidth without creating scheduling overhead.

---

## 2. Channels — streaming results with `<-chan ScanResult`

### What a channel is

A channel is a typed pipe that goroutines use to communicate. One goroutine
writes into one end; another reads from the other end. The type system
enforces direction.

```go
ch := make(chan ScanResult, 256)  // a buffered channel of ScanResults

// Writer (inside scanner.go):
ch <- result    // send one ScanResult into the channel

// Reader (in cmd/scan.go):
r := <-ch       // receive one ScanResult from the channel
```

### The `<-chan ScanResult` return type

Look at the signature of `Scan`:

```go
func (s *impl) Scan(ctx context.Context) <-chan ScanResult
```

The return type `<-chan ScanResult` is a **receive-only channel of ScanResult**.
The arrow direction tells you: the caller can only *read* from it, never write.
This is enforced by the compiler — if the caller tries to send into it, the
code will not compile.

```go
ch := sc.Scan(ctx)  // ch has type <-chan ScanResult

result := <-ch      // OK  — read
ch <- result        // COMPILE ERROR — cannot send on receive-only channel
```

Compare with `chan<- ScanResult` (send-only, used inside the scanner to write
results) and `chan ScanResult` (bidirectional, used when creating the channel).

### What "streaming" means and why it matters

Compare two designs:

**Design A — collect everything, return a slice:**

```go
func (s *impl) ScanAll() []ScanResult {
    var results []ScanResult
    // ... walk entire filesystem ...
    return results
    // caller receives ALL results at once — after minutes of waiting
}
```

**Design B — stream results as found (what we do):**

```go
func (s *impl) Scan(ctx context.Context) <-chan ScanResult {
    ch := make(chan ScanResult, resultBuf)
    go func() {
        defer close(ch)
        // send each result the instant it is found
        ch <- result
    }()
    return ch
    // caller receives the FIRST result in milliseconds
}
```

With Design B, `cmd/scan.go` can print each result as it arrives:

```go
for r := range sc.Scan(ctx) {    // range over channel until it's closed
    fmt.Printf("found: %s (%s)\n", r.AbsPath, r.Ecosystem)
}
// Loop ends when the channel is closed (when walk completes)
```

The `range` keyword on a channel loops until the channel is closed.
That closing happens in our `defer close(resultCh)` — explained in Section 7.

### Buffered vs unbuffered channels

```go
resultCh := make(chan ScanResult, resultBuf)  // buffered: capacity 256
workCh   := make(chan rootWork, len(roots))    // buffered: capacity = number of roots
```

An **unbuffered** channel (`make(chan T)`) blocks the sender until a receiver
is ready. If the worker goroutine sends a result but the caller is slow reading,
the worker waits — losing parallelism.

A **buffered** channel (`make(chan T, n)`) holds up to `n` items before
blocking. Our `resultBuf = 256` means workers can find up to 256 directories
before the caller's reading speed starts to matter. On most systems the
caller (printing to a terminal) reads far faster than the scanner produces
results, so the buffer rarely fills.

The `workCh` is buffered to exactly `len(roots)` because we fill it all at
once and then close it before any worker starts — without the buffer, each
`workCh <- r` would block until a worker was ready to receive.

### The two-channel architecture visualised

```
Scan() creates two channels:

workCh  (rootWork items, sent once, closed before workers start)
resultCh (ScanResult items, written by workers, read by caller)

         ┌─────────────────────────────────────────────────────────┐
         │  orchestrator goroutine                                  │
         │                                                          │
         │  workCh ◄── pre-filled with roots, then closed          │
         └──────────────────────┬──────────────────────────────────┘
                                │  range workCh
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                  ▼
         worker 1           worker 2          worker N
         walkRoot()         walkRoot()        walkRoot()
              │                 │                  │
              └─────────────────┼──────────────────┘
                                ▼
                         resultCh ──────────────► caller
                                                  range resultCh { … }
```

---

## 3. sync.WaitGroup — waiting for all workers to finish

### What a WaitGroup is

A `sync.WaitGroup` is a counter that lets one goroutine wait for a group of
other goroutines to finish. It has three methods:

```go
var wg sync.WaitGroup

wg.Add(1)    // increment counter by 1 (call BEFORE starting the goroutine)
wg.Done()    // decrement counter by 1 (call WHEN the goroutine finishes)
wg.Wait()    // block here until counter reaches 0
```

Think of it as "I am expecting N goroutines to finish. Tell me when they're
all done."

### The exact lines in our scanner

```go
// scanner.go lines 310–323

var wg sync.WaitGroup
for i := 0; i < s.numWorkers; i++ {
    wg.Add(1)                   // (A) counter: 0 → 1 → 2 → ... → numWorkers
    go func() {
        defer wg.Done()         // (B) counter decrements when this goroutine exits
        for work := range workCh {
            if ctx.Err() != nil {
                return
            }
            s.walkRoot(ctx, work, resultCh)
        }
    }()
}
wg.Wait()                       // (C) blocks until counter reaches 0
// resultCh is closed by the defer close(resultCh) above
```

Walk through what happens step by step when `numWorkers = 4`:

```
Loop iteration 0:  wg.Add(1)    counter = 1,  goroutine A starts
Loop iteration 1:  wg.Add(1)    counter = 2,  goroutine B starts
Loop iteration 2:  wg.Add(1)    counter = 3,  goroutine C starts
Loop iteration 3:  wg.Add(1)    counter = 4,  goroutine D starts

wg.Wait()  ← orchestrator blocks here

(time passes while goroutines walk directories)

goroutine C finishes → wg.Done()   counter = 3
goroutine A finishes → wg.Done()   counter = 2
goroutine D finishes → wg.Done()   counter = 1
goroutine B finishes → wg.Done()   counter = 0  ← wg.Wait() unblocks

Orchestrator resumes, falls off the end of go func(){}, defer fires:
    defer close(resultCh)   ← channel is now closed, caller's range loop ends
```

### What would break without WaitGroup

Suppose you removed `wg.Wait()`:

```go
// BROKEN — no WaitGroup
for i := 0; i < s.numWorkers; i++ {
    go func() {
        for work := range workCh {
            s.walkRoot(ctx, work, resultCh)
        }
    }()
}
// wg.Wait() removed — falls through immediately
// defer close(resultCh) fires HERE, BEFORE workers finish
```

Result: `resultCh` is closed while workers are still running. A worker that
tries to send a result after the channel is closed causes an **immediate
panic**:

```
panic: send on closed channel
goroutine 17 [running]:
github.com/farzanini/dep-shield/internal/scanner.(*impl).walkRoot(...)
    .../internal/scanner/scanner.go:551
```

The WaitGroup ensures `close(resultCh)` never fires before the last worker
has sent its last result.

### Why `wg.Add(1)` must come BEFORE `go func()`

This is a subtle but critical ordering requirement:

```go
// CORRECT
wg.Add(1)          // increment FIRST
go func() {
    defer wg.Done()
    // work
}()

// BROKEN
go func() {
    wg.Add(1)      // goroutine might not be scheduled before wg.Wait() sees 0
    defer wg.Done()
    // work
}()
```

In the broken version, `wg.Wait()` could execute before any of the goroutines
have had a chance to call `wg.Add(1)`. The counter is 0, `Wait()` returns
immediately, and `close(resultCh)` fires before the workers run. The fix:
always call `wg.Add(n)` in the same goroutine that calls `wg.Wait()`, before
starting the goroutines.

---

## 4. The worker pool pattern — ASCII diagram included

### The concept

A worker pool solves the "spawn N goroutines, not infinite goroutines"
problem. The key ingredients are:

1. A **work channel** that holds tasks to be done.
2. A **fixed number of worker goroutines** that each loop reading tasks.
3. The work channel is **closed when no more tasks will be added**, which
   causes every worker's `for work := range workCh` to exit naturally.

### Our implementation, step by step

```go
// Step 1: gather work
roots := s.effectiveRoots()

// Step 2: fill work channel and close it (all in ONE goroutine, atomically)
workCh := make(chan rootWork, len(roots))
for _, r := range roots {
    workCh <- r      // never blocks because channel is as big as the slice
}
close(workCh)        // closing tells workers "no more work will come"

// Step 3: start exactly numWorkers workers
var wg sync.WaitGroup
for i := 0; i < s.numWorkers; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        for work := range workCh {   // exits when workCh is empty AND closed
            s.walkRoot(ctx, work, resultCh)
        }
    }()
}
wg.Wait()
```

### Full ASCII diagram with 4 workers and 7 roots

```
effectiveRoots() returns 7 items:
  ~/projects/app1      (project)
  ~/projects/app2      (project)
  ~/projects/app3      (project)
  ~/projects/lib1      (project)
  ~/projects/lib2      (project)
  ~/.cargo/registry    (global)
  ~/go/pkg/mod         (global)

workCh (capacity 7, pre-filled, closed):
  ┌─────┬─────┬─────┬─────┬─────┬──────┬──────┐
  │app1 │app2 │app3 │lib1 │lib2 │cargo │gomod │
  └──┬──┴──┬──┴──┬──┴──┬──┴──┬──┴──┬───┴──┬───┘
     │     │     │     │     │     │      │
     │ claimed   │     │     │     │      │
     ▼     ▼     ▼     ▼     │     │      │
  [W1]  [W2]  [W3]  [W4]  ...workers loop...
  app1  app2  app3  lib1

  W1 finishes app1 → claims lib2
  W2 finishes app2 → claims cargo
  W3 finishes app3 → claims gomod
  W4 finishes lib1 → workCh empty AND closed → W4 exits, wg.Done()

  W1 finishes lib2  → workCh empty → W1 exits, wg.Done()
  W2 finishes cargo → workCh empty → W2 exits, wg.Done()
  W3 finishes gomod → workCh empty → W3 exits, wg.Done()

  wg counter: 4 → 3 → 2 → 1 → 0
  wg.Wait() unblocks → defer close(resultCh) fires

                                    resultCh:
  ┌────────────────────────────────────────────────────────────────────┐
  │  ScanResult{app1/node_modules}                                     │
  │  ScanResult{app2/node_modules}    ← arrive in non-deterministic   │
  │  ScanResult{app3/.venv}              order (whichever worker finds │
  │  ScanResult{lib1/vendor}             them first sends them first)  │
  │  ...                                                               │
  └────────────────────────────────────────────────────────────────────┘
                            │
                   for r := range resultCh {
                       // caller processes each result as it arrives
                   }
                   // loop exits when resultCh is closed
```

### Why the pre-seeded + closed channel is deadlock-free

A common pitfall with work channels:

```go
// POTENTIAL DEADLOCK if workers produce new work:
for work := range workCh {
    process(work)
    if found_sub_work {
        workCh <- subWork   // blocks if channel is full!
        // workers are all blocked trying to send, nobody is reading → DEADLOCK
    }
}
```

Our design avoids this entirely: all work is known *before* the first worker
starts. Workers never write to `workCh`. The channel is static: it holds
exactly `len(roots)` items from birth to death.

---

## 5. filepath.WalkDir vs filepath.Walk — why we chose WalkDir

### The problem with filepath.Walk (pre-Go 1.16)

```go
// OLD: filepath.Walk
func Walk(root string, fn func(path string, info os.FileInfo, err error) error) error
```

The callback receives `os.FileInfo`. To get that, `filepath.Walk` must call
`os.Lstat()` on *every entry in every directory* — one system call per file.
On a home directory with 1 million files, that is 1 million extra system calls.

### Why filepath.WalkDir is faster (Go 1.16+)

```go
// NEW: filepath.WalkDir
func WalkDir(root string, fn func(path string, d fs.DirEntry, err error) error) error
```

The callback receives `fs.DirEntry`. The operating system already returns the
entry type (file/directory/symlink) when it reads a directory — no extra
`Lstat()` call needed. We only call `Lstat()` when we specifically need more
information (like file size or permissions), and in our scanner we almost
never do.

### How we use DirEntry in our scanner

```go
// scanner.go line 477:
if !d.IsDir() {
    return nil   // skip files — only directories interest us
}

// line 506:
if d.Type()&fs.ModeSymlink != 0 {
    // handle symlink
}
```

`d.IsDir()` and `d.Type()` are free — they use data the OS already returned
when listing the directory. With `filepath.Walk`, the equivalent `info.IsDir()`
required a separate `Lstat()` call for every single file.

### The fs.SkipDir sentinel

`filepath.WalkDir` uses a special return value to control traversal:

```go
// Return fs.SkipDir from the callback to stop descending into this directory.
return fs.SkipDir
```

We use this in three places:

| Location in scanner.go | Reason |
|------------------------|--------|
| After classifying a match | Don't recurse inside node_modules |
| Guard: path too long | Stop descending into pathological trees |
| Guard: virtual filesystem | Don't enter /proc, /sys, /dev |

`fs.SkipDir` is not an error — it is a signal to WalkDir's internal machinery.
WalkDir checks for it with `errors.Is(err, fs.SkipDir)` internally and simply
stops queuing that subtree.

### Visualising what WalkDir visits

```
~/projects/my-app/
├── main.go              ← WalkDir calls callback with this (d.IsDir()=false → nil)
├── go.mod               ← same
├── go.sum               ← same
└── node_modules/        ← WalkDir calls callback (d.IsDir()=true)
    │                         classify() matches → send result → return fs.SkipDir
    ├── lodash/          ← NEVER VISITED (SkipDir skips entire subtree)
    │   └── index.js
    └── express/
        └── index.js
```

Without `fs.SkipDir`, WalkDir would recurse into every file inside
`node_modules` — potentially hundreds of thousands of files — for no benefit,
since the parser handles enumeration later.

---

## 6. Error handling — why Go has no exceptions

### The design choice

Go deliberately has no `try/catch/throw`. Every function that can fail returns
an error as its last return value:

```go
// Standard Go function signature with error:
func os.ReadDir(name string) ([]DirEntry, error)

// Calling it:
entries, err := os.ReadDir(path)
if err != nil {
    // handle the error
}
// entries is safe to use here
```

This is not a limitation — it is a design choice. In Go, every error is
explicit and visible at the call site. There are no "surprise" exceptions
propagating up the stack invisibly.

### Reading Go error handling: a mental model

When you see:

```go
result, err := someFunction()
if err != nil {
    // ...
}
// use result
```

Read it as: *"someFunction either succeeded (err == nil) or failed (err != nil).
If it failed, handle the failure here. If it succeeded, result is safe to use."*

The `if err != nil` block always appears immediately after the call. This is
so consistent that Go programmers read it at a glance, the same way you read
`i++` in a for loop without thinking about it.

### Our three error-handling patterns in scanner.go

**Pattern A — fatal early return (function cannot proceed):**

```go
// walkRoot, line 441:
if _, err := os.Lstat(absRoot); err != nil {
    if !errors.Is(err, fs.ErrNotExist) {
        s.log.Debug("skipping root", zap.String("path", absRoot), zap.Error(err))
    }
    return   // ← cannot walk a root that doesn't exist; abort this root
}
```

Used when the error makes the current function's work impossible. We return
early rather than proceeding with invalid state.

**Pattern B — non-fatal skip (one item fails, rest continue):**

```go
// walkRoot WalkDir callback, lines 465–474:
if err != nil {
    if isPermissionErr(err) {
        s.log.Debug("permission denied, skipping", zap.String("path", path))
        return nil   // ← return nil (not the error) to keep walking
    }
    s.log.Warn("walk error, skipping", zap.String("path", path), zap.Error(err))
    return nil       // ← same: skip this entry, continue with siblings
}
```

Returning `nil` from a `WalkDir` callback tells WalkDir "I handled it, keep
going." Returning the actual `err` would abort the entire walk.

**Pattern C — expected error, filtered away:**

```go
// walkRoot, lines 561–565:
if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
    s.log.Warn("walk finished with error", zap.String("root", absRoot), zap.Error(err))
}
```

`WalkDir` returns `context.Canceled` when we cancelled the walk on purpose.
That is not a bug — we explicitly cancelled it. Filtering it out prevents a
log message that would mislead the user into thinking something went wrong.

### errors.Is vs == for error comparison

```go
// WRONG — may miss wrapped errors:
if err == fs.ErrPermission { … }

// CORRECT — unwraps error chains:
if errors.Is(err, fs.ErrPermission) { … }
```

Why? On many systems, a permission error looks like:
`&PathError{Op: "open", Path: "/etc/shadow", Err: syscall.EACCES}`.
The `==` comparison fails because the outer `PathError` is not the same value
as `fs.ErrPermission`. `errors.Is` unwraps the chain and checks whether any
layer in the chain matches — so it correctly identifies this as a permission
error.

---

## 7. defer — every use in scanner.go explained

### What defer does

`defer` schedules a function call to run *when the surrounding function returns*,
regardless of how it returns (normal return, early return, even panic).

```go
func example() {
    defer fmt.Println("I run last")   // registered but not called yet
    fmt.Println("I run first")
    return                             // deferred call runs here
}
// Output:
// I run first
// I run last
```

Multiple `defer`s in one function run in **LIFO** order (last registered,
first called). This matches the "undo stack" mental model: the last thing you
set up should be the first thing you tear down.

### Every defer in scanner.go

There are exactly **two** `defer` statements in scanner.go. Here they are with
a precise explanation of what breaks without each one.

---

**Defer 1: `defer close(resultCh)` — line 294**

```go
func (s *impl) Scan(ctx context.Context) <-chan ScanResult {
    resultCh := make(chan ScanResult, resultBuf)

    go func() {
        defer close(resultCh)   // ← DEFER 1
        
        roots := s.effectiveRoots()
        if len(roots) == 0 {
            return               // ← early return: defer fires here
        }
        // ... start workers ...
        wg.Wait()
        // ← normal return: defer fires here too
    }()

    return resultCh
}
```

`close(resultCh)` is what tells the caller's `for r := range resultCh { }`
loop to stop. Without it, the loop would block forever after the scan
finishes — a goroutine leak.

Why `defer` specifically, instead of putting `close(resultCh)` at the end of
the function? Because of the early return on line 298 (`if len(roots) == 0 { return }`).
Without `defer`, an empty-roots scan would return from the goroutine without
closing the channel, and the caller would wait forever. The `defer` ensures
the channel is *always* closed, no matter which `return` statement executes.

**What breaks without it:**

```go
// WITHOUT defer close(resultCh):
go func() {
    roots := s.effectiveRoots()
    if len(roots) == 0 {
        return               // channel never closed!
    }
    // ...
    wg.Wait()
    close(resultCh)          // only reached on the happy path
}()

// Caller:
for r := range resultCh {   // DEADLOCK if roots were empty —
    // ...                   // or if any early-return path was taken
}
```

The test `TestScan_EmptyRoot` would hang indefinitely instead of returning
quickly.

---

**Defer 2: `defer wg.Done()` — line 314**

```go
for i := 0; i < s.numWorkers; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()   // ← DEFER 2

        for work := range workCh {
            if ctx.Err() != nil {
                return           // early return: defer fires here
            }
            s.walkRoot(ctx, work, resultCh)
        }
        // normal return: defer fires here too
    }()
}
```

`wg.Done()` decrements the WaitGroup counter. When the counter reaches 0,
`wg.Wait()` (back in the orchestrator) unblocks and `defer close(resultCh)`
fires.

The `ctx.Err() != nil` check causes an early `return` when the context is
cancelled. Without `defer`, that early return would never call `wg.Done()`,
the counter would never reach 0, and `wg.Wait()` would block forever —
another goroutine leak.

**What breaks without it:**

```go
// WITHOUT defer wg.Done():
go func() {
    for work := range workCh {
        if ctx.Err() != nil {
            return           // wg counter never decremented!
        }
        s.walkRoot(ctx, work, resultCh)
    }
    wg.Done()                // only reached when workCh is empty
}()
```

Cancelling the context during a long scan would cause `wg.Wait()` to block
forever. The scan would appear to hang even after cancellation, and the
`resultCh` would never be closed, leaking the caller's goroutine too.

---

### Summary table

| defer | Where | What it closes/decrements | What leaks without it |
|-------|-------|---------------------------|-----------------------|
| `defer close(resultCh)` | orchestrator goroutine | the result channel | caller's `range` loop blocks forever |
| `defer wg.Done()` | each worker goroutine | WaitGroup counter | `wg.Wait()` blocks → `resultCh` never closed → cascade leak |

**The pattern:** In Go, any goroutine that holds a resource (a channel that
needs closing, a WaitGroup counter that needs decrementing, a file that needs
closing, a mutex that needs unlocking) should release it with `defer` as the
very first statement in the goroutine, not the last. The "very first" part is
important: you cannot forget to add it later, and early returns are handled
automatically.

---

## 8. Debug this

### How to detect a goroutine leak using `go tool pprof`

A goroutine leak is when a goroutine starts and never exits — typically because
a channel it was trying to read or write is never unblocked. This is often
caused by a missing `defer close(ch)` or missing `defer wg.Done()`.

**Step 1 — add a pprof HTTP server to the binary (development mode only):**

```go
// In main.go or cmd/root.go, behind a --pprof flag:
import _ "net/http/pprof"
import "net/http"

go http.ListenAndServe("localhost:6060", nil)
```

**Step 2 — run the scan and check goroutines while it's running:**

```bash
dep-shield scan --pprof &   # run in background
sleep 5                     # wait a moment
curl -s localhost:6060/debug/pprof/goroutine?debug=1 | head -50
```

A healthy scan shows goroutine counts that rise (workers start) and then fall
back to baseline (workers exit). A leaked goroutine shows as a goroutine stuck
forever in a send or receive:

```
goroutine 42 [chan receive, 2 minutes]:    ← stuck receiving for 2 minutes
github.com/farzanini/dep-shield/internal/scanner.(*impl).Scan.func1.1()
    .../internal/scanner/scanner.go:315 +0x84
```

The number "2 minutes" is the duration this goroutine has been blocked. If
that number keeps growing while the program appears idle, you have a leak.

**Step 3 — capture a full profile and view it:**

```bash
go tool pprof http://localhost:6060/debug/pprof/goroutine
# Inside pprof interactive shell:
(pprof) top
(pprof) list scanner.Scan
(pprof) web    # opens a visual graph in your browser
```

**Step 4 — use the race detector during tests:**

```bash
go test -race ./internal/scanner/...
```

The race detector catches concurrent writes to the same variable without
synchronisation. A goroutine leak often manifests alongside a data race.

---

### What a deadlock looks like on our channel and how to fix it

Go detects certain deadlocks automatically and prints a diagnostic:

```
fatal error: all goroutines are asleep - deadlock!

goroutine 1 [chan receive]:
main.main()
        .../cmd/dep-shield/main.go:15 +0x7c

goroutine 7 [chan send]:
github.com/farzanini/dep-shield/internal/scanner.(*impl).walkRoot(...)
        .../internal/scanner/scanner.go:551 +0x1a4
```

**Scenario: caller doesn't drain the channel fast enough**

```go
// Bug: caller only reads 3 items, then stops
ch := sc.Scan(ctx)
for i := 0; i < 3; i++ {
    <-ch
}
// ch is now abandoned — workers block trying to send to a full channel
```

Fix: always drain the full channel OR always cancel the context when done:

```go
// Fix A: drain everything
for r := range sc.Scan(ctx) {
    process(r)
}

// Fix B: cancel when you have enough
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
for r := range sc.Scan(ctx) {
    process(r)
    if done { cancel(); break }   // cancel() unblocks workers
}
// IMPORTANT: still drain the remaining items after break
for range sc.Scan(ctx) {}         // drain — actually, start fresh scan to drain
```

The cleanest pattern in our codebase: always use `range` on the channel,
and cancel the context if you want early exit. Workers watch `ctx.Err()` and
exit early; `defer wg.Done()` and `defer close(resultCh)` ensure everything
cleans up properly even with early cancellation.

**Scenario: `close(resultCh)` called twice**

```go
// Bug: calling close() on a closed channel panics
close(resultCh)
// ...
close(resultCh)  // panic: close of closed channel
```

Our design prevents this: `close(resultCh)` is in exactly one place — the
`defer` in the orchestrator goroutine — and that goroutine runs exactly once
per `Scan()` call.

---

### How to add a `--verbose` flag that prints each directory as it's scanned

This is an end-to-end exercise that touches `Options`, `scanner.go`,
`cmd/scan.go`, and `cmd/root.go`.

**Step 1 — add `Verbose` to `Options` in scanner.go:**

```go
type Options struct {
    // ... existing fields ...

    // Verbose, when true, logs each visited directory to stderr as it is
    // classified.  Use only during development — it produces enormous output
    // on large scans.
    Verbose bool
}
```

**Step 2 — log in `walkRoot` when verbose:**

```go
// In walkRoot, after the classify() call:
result, matched := s.classify(path, work.sourceHint)
if !matched {
    if s.opts.Verbose {
        s.log.Debug("visited (no match)", zap.String("path", path))
    }
    return nil
}

if s.opts.Verbose {
    s.log.Info("matched",
        zap.String("path",       result.AbsPath),
        zap.String("ecosystem",  string(result.Ecosystem)),
        zap.String("sourceType", string(result.SourceType)),
    )
}
```

**Step 3 — add `--verbose` flag in `cmd/scan.go`:**

```go
// In scanFlags struct:
type scanFlags struct {
    // ...
    Verbose bool
}

// In scanCmd(), in the Flags() block:
cmd.Flags().BoolVar(&sf.Verbose, "verbose", false,
    "print each directory visited during the scan")

// In runScan(), when constructing Options:
w := scanner.New(scanner.Options{
    Roots:   paths,
    HomeDir: "",       // use real home
    Verbose: sf.Verbose,
    Log:     log,
})
```

**Step 4 — test it:**

```bash
go run . scan --verbose /tmp 2>&1 | head -20
```

Because `zap.NewDevelopment()` prints to stderr, the verbose output will
interleave with the normal table output. In a production-quality
implementation you would write verbose output to a separate writer
(e.g. `os.Stderr`) or use a `--debug` flag that switches to the development
logger globally.

---

## 9. Exercises

### Exercise 1 — Trace one ScanResult from disk to caller

Pick the test `TestScan_NodeModules` in `scanner_test.go`. Set a breakpoint
(or add `fmt.Println` calls) at these five points:

1. Inside `effectiveRoots()` when the root is added to `all`
2. Inside the worker goroutine when it claims work from `workCh`
3. Inside `walkRoot` when `classify` returns `matched = true`
4. Inside the `select { case resultCh <- result: }` line
5. Inside the `for r := range ch` loop in `TestScan_NodeModules`

Run the test with `go test -v -run TestScan_NodeModules ./internal/scanner/`
and observe the order of prints. This is the complete life of one `ScanResult`:
from the filesystem into the test's hands.

**What you will learn:** How a value flows from one goroutine to another
through a channel, and how the Go scheduler interleaves execution.

---

### Exercise 2 — Intentionally cause a goroutine leak and detect it

Remove the `defer wg.Done()` from the worker goroutine:

```go
go func() {
    // defer wg.Done()    ← comment this out
    for work := range workCh {
        if ctx.Err() != nil {
            return
        }
        s.walkRoot(ctx, work, resultCh)
    }
}()
```

Run the tests:

```bash
go test -timeout 5s -run TestScan_CancelledContext ./internal/scanner/
```

The test has a 5-second timeout. With the leak, `wg.Wait()` never returns,
`close(resultCh)` never fires, the caller's goroutine blocks forever, and the
test times out:

```
panic: test timed out after 5s
```

Now restore `defer wg.Done()` and confirm the test passes.

**What you will learn:** The exact failure mode of a missing WaitGroup
decrement, and how test timeouts reveal goroutine leaks.

---

### Exercise 3 — Add a result-count progress display

Modify `cmd/scan.go`'s `runScan` function so it prints a live counter to
stderr as results stream in:

```
Scanning...  found 142 dependency directories so far
```

Hints:
- Use `\r` (carriage return, not `\n`) to overwrite the same terminal line.
- Count how many `ScanResult`s have arrived since the last print.
- Print the count every N results (e.g. every 10) to avoid flooding stderr.

```go
// Skeleton:
var count int
for r := range sc.Scan(ctx) {
    count++
    if count % 10 == 0 {
        fmt.Fprintf(os.Stderr, "\rScanning...  found %d dependency directories so far", count)
    }
    hits = append(hits, scanner.DirHit{Path: r.AbsPath, Ecosystem: r.Ecosystem})
}
fmt.Fprintln(os.Stderr)  // newline after the last \r update
```

**What you will learn:** How streaming channels enable real-time progress
displays — something impossible with the "collect everything, return a slice"
design — and how `\r` works for in-place terminal updates.

---

*Next guide: [03 — Lockfile parsing & bufio.Scanner](03-lockfile-parsing.md)*
