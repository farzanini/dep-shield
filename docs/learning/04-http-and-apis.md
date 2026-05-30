# 04 — HTTP and APIs

> **What this guide covers**
>
> - `http.Client` in Go vs `fetch` in JavaScript — what timeouts actually protect you from
> - `context.Context` — what it is, why every HTTP call in our codebase accepts one, and how to add a `--timeout` flag
> - Struct methods — the `(c *Client) QueryAll()` syntax explained from first principles
> - Retry with exponential back-off — a line-by-line walk-through of `fetchWithRetry` in `src/cve.ts`, then the equivalent pattern in Go

---

## 1. `http.Client` in Go vs `fetch` in JavaScript

### The JavaScript mental model

In JavaScript, `fetch` is a global function. You call it, you get a `Promise<Response>`. You trust the runtime to handle the socket.

```typescript
const resp = await fetch('https://api.osv.dev/v1/query', {
  method: 'POST',
  body: JSON.stringify(payload),
});
```

Two things you might not notice:

1. There is **no timeout** unless you pass an `AbortSignal`.
2. Every call uses the platform's shared HTTP machinery. You can't configure connection-pool size, keep-alive behaviour, or redirect policy per call-site.

### Go's explicit client

Go makes the HTTP client a **first-class value**. Instead of calling a package-level `http.Get`, you create an `*http.Client` struct and call methods on it:

```go
// internal/cve/client.go — NewClient()
httpClient := &http.Client{Timeout: opts.HTTPTimeout}
```

`opts.HTTPTimeout` is set to `15 * time.Second` when the caller doesn't specify one.

The field `Timeout` is `time.Duration`. Go's `time.Duration` is just an `int64` counting nanoseconds, but the standard library provides constants (`time.Second`, `time.Millisecond`, …) so you write human-readable arithmetic:

```go
15 * time.Second   // 15_000_000_000 nanoseconds, typed as time.Duration
```

#### What happens without the timeout?

Imagine the OSV server accepts the TCP connection but then hangs — it stops sending bytes. Without a timeout the `http.Do` call blocks forever. The goroutine that made the call is stuck. If you're scanning 500 packages with 4 workers and all 4 slots hit a hanging server, your whole scan freezes silently.

With `Timeout: 15 * time.Second`, the client closes the connection and returns an error after 15 seconds:

```
osv http: context deadline exceeded (Client.Timeout exceeded while awaiting headers)
```

The error message tells you exactly what happened. The goroutine is freed. The scan keeps going.

#### The client is reused across requests

Notice that `NewClient` creates **one** `*http.Client` and passes it to both sources:

```go
httpClient := &http.Client{Timeout: opts.HTTPTimeout}

return &Client{
    sources: []Source{
        newOSVSource(httpClient, log),   // same pointer
        newGHSource(httpClient, log),    // same pointer
    },
    ...
}
```

A single `http.Client` manages an internal connection pool. Reusing it across requests means TCP connections to the same host are kept alive and reused (HTTP keep-alive), saving the handshake cost on subsequent requests. If you created a `new(http.Client)` inside every `Query` call you'd pay the handshake on every single package lookup.

---

## 2. `context.Context`

### The problem it solves

Suppose a user runs:

```
dep-shield scan ./my-project --timeout 10s
```

Ten seconds into the scan, three of the ten goroutines are still waiting for HTTP responses. How do you tell them to stop?

You could use a channel, a global flag, a mutex-protected bool — there are many options. The Go standard library standardises on one: **`context.Context`**.

### What `context.Context` is

`context.Context` is an interface with four methods:

```go
type Context interface {
    Deadline() (deadline time.Time, ok bool)
    Done() <-chan struct{}
    Err() error
    Value(key any) any
}
```

The one you use most often is `Done()`. It returns a channel that is closed when the context is cancelled (or its deadline expires). Any code that's waiting on that channel will unblock.

You create a concrete context at the top of your program:

```go
ctx := context.Background()  // never cancelled, never has a deadline
```

Then you derive child contexts from it:

```go
// Cancel after 10 seconds — for a --timeout flag:
ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
defer cancel() // always call cancel() to free resources

// Cancel manually — for ctrl-C handling:
ctx, cancel := context.WithCancel(ctx)
defer cancel()
```

Every function that does I/O accepts a context as its **first parameter**. This is a strong Go convention — you'll see it everywhere:

```go
func (c *Client) QueryAll(ctx context.Context, pkgs []models.Package) ([]models.Vulnerability, error)
```

### How our code uses it

`QueryAll` passes the context down to each goroutine. Each goroutine passes it to `src.Query`, which passes it to the HTTP layer:

```go
// internal/advisory/osv.go
req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewReader(body))
```

`http.NewRequestWithContext` attaches the context to the request. When the context is cancelled, the HTTP client sees `ctx.Done()` close and aborts the in-flight request immediately — no waiting for the timeout, no leaked goroutine.

The chain looks like this:

```
cmd/scan.go
  └─ QueryAll(ctx, pkgs)
       └─ goroutine: src.Query(ctx, pkg)
            └─ http.NewRequestWithContext(ctx, ...)
                 └─ o.http.Do(req)   ← aborts when ctx.Done() fires
```

If you ever forget to thread the context and use `http.NewRequest` instead (no context), the HTTP call will ignore cancellation. The goroutine will keep running even after the user presses Ctrl-C. That's a goroutine leak.

### Adding a `--timeout` flag

Here's what wiring a timeout flag would look like in `cmd/dep-shield/root/scan.go`:

```go
// 1. Declare the flag (in init or as a persistent flag on rootCmd):
var timeout time.Duration
scanCmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "abort scan after this duration")

// 2. In RunE, derive a child context:
func runScan(cmd *cobra.Command, args []string) error {
    ctx := cmd.Context()  // already set by cobra from os.Signal handling

    if timeout > 0 {
        var cancel context.CancelFunc
        ctx, cancel = context.WithTimeout(ctx, timeout)
        defer cancel()
    }

    // 3. Pass ctx through — everything downstream respects it automatically:
    vulns, err := cveClient.QueryAll(ctx, pkgs)
    ...
}
```

No extra plumbing required. The three lines of context setup propagate the deadline to every HTTP call in the entire scan.

---

## 3. Struct methods — the `(c *Client) QueryAll()` syntax

### Functions vs methods: the key difference

A Go **function** is standalone:

```go
func queryAll(c *Client, ctx context.Context, pkgs []models.Package) ([]models.Vulnerability, error) {
    // ...
}
```

A Go **method** is a function with a *receiver* — a special first parameter declared before the function name:

```go
func (c *Client) QueryAll(ctx context.Context, pkgs []models.Package) ([]models.Vulnerability, error) {
    // c is available here, like `this` in JavaScript or `self` in Python
}
```

The syntax `(c *Client)` is the *receiver declaration*. It says: "this function belongs to the type `*Client`". Callers invoke it with dot notation:

```go
client := cve.NewClient(opts)
vulns, err := client.QueryAll(ctx, pkgs)  // Go dispatches to the method
```

This is Go's version of object-oriented programming. There are no classes — just types with methods attached.

### Pointer receivers vs value receivers

The receiver can be a pointer (`*Client`) or a value (`Client`). The rule is:

| Situation | Use |
|---|---|
| Method mutates the receiver's fields | `*Client` (pointer) |
| Method needs to be called on nil | `*Client` (pointer) |
| Receiver is large (copying is expensive) | `*Client` (pointer) |
| Receiver is a small, immutable value | `Client` (value) |

All our methods use pointer receivers because `Client` holds a slice of sources, a semaphore, and a logger — it's not something you want to copy on every call.

One practical consequence: if all methods on a type use pointer receivers, you should also use a pointer receiver on methods that *don't* mutate state, just for consistency. Mixing pointer and value receivers on the same type compiles but confuses the reader.

### Comparison to TypeScript and Python

**TypeScript:**
```typescript
class Client {
    private sources: Source[];

    queryAll(ctx: AbortSignal, pkgs: Package[]): Promise<Vulnerability[]> {
        // `this` is the receiver
    }
}
```

**Python:**
```python
class Client:
    def query_all(self, ctx, pkgs):
        # `self` is the receiver, always a value (Python passes reference automatically)
        pass
```

**Go:**
```go
type Client struct {
    sources []Source
}

func (c *Client) QueryAll(ctx context.Context, pkgs []models.Package) ([]models.Vulnerability, error) {
    // `c` is the receiver — explicit pointer
}
```

The concepts are identical. Go just makes the receiver explicit in the function signature rather than hiding it as `this` or `self`.

### The `Source` interface and how methods enable it

`QueryAll` iterates `c.sources`, each of which is a `Source`:

```go
type Source interface {
    Name() string
    Query(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error)
}
```

Both `*osvSource` and `*ghSource` have `Name()` and `Query()` methods with exactly those signatures, so they satisfy `Source` implicitly (no `implements` keyword needed). When `QueryAll` calls `src.Query(ctx, pkg)`, Go dispatches to whichever concrete type `src` holds at runtime. This is Go interfaces working exactly as described in guide 03.

---

## 4. Retry with exponential back-off

Vulnerability APIs rate-limit aggressively. OSV returns HTTP 429 if you send too many requests per second. GitHub's GraphQL endpoint returns 503 under heavy load. A naive "try once" strategy turns transient failures into scan failures.

The solution is to **retry with back-off**: wait before retrying, and wait longer on each successive failure.

### The implementation in `src/cve.ts`

```typescript
// src/cve.ts
const MAX_RETRIES = 3;
const RETRY_BASE_MS = 1_000;   // 1 second
const RETRY_CAP_MS = 30_000;   // 30 seconds ceiling

export async function fetchWithRetry(
  url: string,
  init: RequestInit,
  maxRetries = MAX_RETRIES,
  baseDelayMs = RETRY_BASE_MS,
): Promise<Response> {
  let lastError: unknown;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    // ① Wait before every attempt except the first.
    if (attempt > 0) {
      const ceiling = Math.min(RETRY_CAP_MS, baseDelayMs * Math.pow(2, attempt));
      const delay = Math.random() * ceiling;   // full jitter
      await sleep(delay);
    }

    try {
      const response = await fetch(url, init);

      // ② Only retry on rate-limit and server errors.
      if (response.status === 429 || response.status >= 500) {
        lastError = new Error(`HTTP ${response.status} from ${url}`);
        continue;   // go to next attempt
      }

      // ③ Anything else (200, 404, 401, …) is returned immediately.
      return response;
    } catch (err) {
      // ④ Network-level failures (DNS, TCP reset) are also retried.
      lastError = err;
    }
  }

  throw lastError;  // ⑤ All attempts exhausted.
}
```

Let's walk through each numbered point.

#### ① Exponential back-off with full jitter

On attempt 0: no wait.
On attempt 1: `ceiling = min(30s, 1s × 2¹) = 2s`. Wait `random(0, 2s)` — somewhere between 0 and 2 seconds.
On attempt 2: `ceiling = min(30s, 1s × 2²) = 4s`. Wait `random(0, 4s)`.

The *exponential* part: the ceiling doubles each attempt, so retries naturally spread out over time.

The *full jitter* part: `Math.random() * ceiling` picks a random point in [0, ceiling). Without jitter, every client that hits a 429 at the same moment waits the same fixed delay and hammers the server simultaneously again — the "thundering herd" problem. Randomising the delay desynchronises the clients.

The `cap` (30 seconds) prevents indefinite growth. Without it, attempt 20 would wait `1 000 × 2²⁰ ≈ 12 days`.

#### ② Only retry on transient errors

HTTP 429 (Too Many Requests) and 5xx (server errors) are transient — retrying might succeed. But HTTP 401 (Unauthorized), 403 (Forbidden), and 404 (Not Found) are permanent — retrying will not help. We return those immediately.

#### ③ Return immediately on success

As soon as we get a successful response, we return it. No need to wait for the loop to finish.

#### ④ Network failures are retried too

`fetch` can throw (rather than returning a non-200 response) when there's a DNS failure, a TCP reset, or a timeout. These are all potentially transient, so we catch them and retry.

#### ⑤ Throw the last error

If all attempts fail, we throw the error from the last attempt. The caller sees a rejected promise and can decide whether to log it, surface it to the user, or ignore it.

### The fourth parameter: `baseDelayMs`

You might wonder why `baseDelayMs` is a parameter at all rather than just `RETRY_BASE_MS`.

The answer is **testability**. The test file passes `baseDelayMs = 1` (one millisecond):

```typescript
// src/cve.test.ts
await fetchWithRetry(url, {}, 3, 1 /* baseDelayMs */);
```

With a 1ms base delay instead of 1000ms, the retry loop finishes in microseconds. The alternative — using `jest.useFakeTimers()` — intercepts `setTimeout` at the runtime level. While powerful, fake timers interact badly with async/await in some environments and require calling `jest.runAllTimersAsync()` between awaits. Passing a small `baseDelayMs` in tests is simpler and more reliable.

### The equivalent pattern in Go

Go doesn't have `async/await`. Blocking is done with `time.Sleep`. The equivalent retry loop looks like:

```go
// Illustrative — not in the dep-shield codebase (yet).
func doWithRetry(ctx context.Context, req *http.Request, maxRetries int) (*http.Response, error) {
    var lastErr error

    for attempt := 0; attempt < maxRetries; attempt++ {
        if attempt > 0 {
            base := time.Second
            cap_ := 30 * time.Second
            ceiling := time.Duration(math.Min(float64(cap_), float64(base)*math.Pow(2, float64(attempt))))
            jitter := time.Duration(rand.Int63n(int64(ceiling)))

            select {
            case <-time.After(jitter):  // wait for jitter duration
            case <-ctx.Done():          // OR give up if context is cancelled
                return nil, ctx.Err()
            }
        }

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
            lastErr = err
            continue
        }
        if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
            resp.Body.Close()
            lastErr = fmt.Errorf("http %d", resp.StatusCode)
            continue
        }
        return resp, nil
    }
    return nil, lastErr
}
```

The key difference from the TypeScript version:

- `time.Sleep(jitter)` is Go's equivalent of `await sleep(delay)`. It blocks the current goroutine (not the whole program — other goroutines keep running).
- The `select` statement waits on *either* `time.After` *or* `ctx.Done()`. This is critical: a plain `time.Sleep` ignores context cancellation, so a Ctrl-C during a 30-second back-off wait would appear to hang. The `select` makes cancellation instant.

Our actual codebase doesn't yet implement this retry loop in Go — `internal/advisory/osv.go` makes single-attempt requests. That's an exercise left for you. The TypeScript version in `src/cve.ts` is the reference implementation.

---

## Debug this

### HTTP call hangs forever

**Symptom:** `dep-shield scan` appears to freeze with no output.

**Diagnosis:** Check if the `http.Client` timeout is set:

```go
// Does your source's client have a timeout?
fmt.Println(httpClient.Timeout)  // 0 means no timeout
```

**Fix:** Always set a timeout when constructing the client. The codebase default is 15 seconds:

```go
httpClient := &http.Client{Timeout: 15 * time.Second}
```

### Retry test is slow

**Symptom:** A test that exercises 3 retry attempts takes 7+ seconds.

**Diagnosis:** The base delay is being used in the test. In `src/cve.ts` tests, pass `baseDelayMs = 1` as the fourth argument to `fetchWithRetry`:

```typescript
// Slow:
await fetchWithRetry(url, init);         // uses 1 000ms base

// Fast:
await fetchWithRetry(url, init, 3, 1);  // uses 1ms base
```

### Context cancelled immediately

**Symptom:** All queries fail with `context deadline exceeded` even with a generous timeout.

**Diagnosis:** `cancel()` is being called before the HTTP requests complete. A common mistake:

```go
ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
cancel()  // ← BUG: cancels the context immediately
defer cancel()  // should be here, not above
```

**Fix:** Always `defer cancel()` immediately after creating the context. The `defer` ensures it runs when the surrounding function returns, not now.

### Adding retry to the Go OSV source

The Go OSV source in `internal/cve/client.go` currently has no retry. Add it:

1. Write a `doWithRetry` helper function that takes `ctx`, `*http.Request`, and `maxAttempts int`.
2. Use a `select { case <-time.After(delay): case <-ctx.Done(): }` pattern instead of plain `time.Sleep`.
3. Update `osvSource.Query` to call `doWithRetry` instead of `o.http.Do`.
4. Verify with a test that mocks `http.RoundTripper` — inject a transport that returns 429 twice and succeeds on the third attempt.

---

## How to run the HTTP-related code

```bash
# Run the TypeScript tests (includes fetchWithRetry tests)
npm test

# Run just the retry tests
npm test -- --testNamePattern "fetchWithRetry"

# Run the Go advisory tests
go test ./internal/cve/...
go test ./internal/advisory/...

# See all test names
go test ./internal/... -v 2>&1 | grep "^--- "

# Run with a real network (integration-style, slow)
GITHUB_TOKEN=ghp_xxx go run ./cmd/dep-shield scan .
```

---

## Key takeaways

| Concept | Go | TypeScript |
|---|---|---|
| HTTP client | `&http.Client{Timeout: 15*time.Second}` | `fetch` with `AbortSignal` |
| Cancellation | `context.Context` threaded through every call | `AbortController` / `AbortSignal` |
| Blocking wait | `time.Sleep(d)` — blocks goroutine, not process | `await sleep(ms)` — suspends async function |
| Methods | `func (c *Client) QueryAll(...)` | `class Client { queryAll(...) }` |
| Retry | `select` on `time.After` + `ctx.Done()` | `await sleep()` in a for loop |

The big idea: **Go makes blocking explicit and cheap**. Goroutines are cheap enough that sleeping one for a few seconds during retry back-off costs almost nothing. The `context.Context` pattern ensures that sleep can always be interrupted by a cancellation signal, so your program stays responsive even while waiting.
