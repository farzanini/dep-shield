package cve

import (
	"context"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dep-shield/dep-shield/internal/models"
)

// ── CVSS v3 base-score calculator ─────────────────────────────────────────────
//
// Ported from the reference TypeScript implementation (src/cve.ts). Computes the
// CVSS v3.0/v3.1 base score from a vector string per the NIST specification §7.1.
// Returns 0 when the vector is empty or unparseable, letting callers treat the
// score as "unknown".

var (
	cvssAV  = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvssAC  = map[string]float64{"L": 0.77, "H": 0.44}
	cvssUI  = map[string]float64{"N": 0.85, "R": 0.62}
	cvssCIA = map[string]float64{"N": 0, "L": 0.22, "H": 0.56}
	cvssPRU = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27} // scope unchanged
	cvssPRC = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50} // scope changed
)

// cvssVectorToScore parses a CVSS v3 vector like
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" into a 0–10 base score.
func cvssVectorToScore(vector string) float64 {
	if vector == "" {
		return 0
	}

	// Strip an optional "CVSS:3.x/" prefix.
	raw := vector
	if strings.HasPrefix(raw, "CVSS:") {
		if slash := strings.IndexByte(raw, '/'); slash != -1 {
			raw = raw[slash+1:]
		}
	}

	metrics := map[string]string{}
	for _, part := range strings.Split(raw, "/") {
		if colon := strings.IndexByte(part, ':'); colon != -1 {
			metrics[part[:colon]] = part[colon+1:]
		}
	}

	scopeChanged := metrics["S"] == "C"
	prMap := cvssPRU
	if scopeChanged {
		prMap = cvssPRC
	}

	av, ok1 := cvssAV[metrics["AV"]]
	ac, ok2 := cvssAC[metrics["AC"]]
	pr, ok3 := prMap[metrics["PR"]]
	ui, ok4 := cvssUI[metrics["UI"]]
	c, ok5 := cvssCIA[metrics["C"]]
	i, ok6 := cvssCIA[metrics["I"]]
	a, ok7 := cvssCIA[metrics["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0
	}

	iscBase := 1 - (1-c)*(1-i)*(1-a)
	var isc float64
	if scopeChanged {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		isc = 6.42 * iscBase
	}
	if isc <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui
	var rawScore float64
	if scopeChanged {
		rawScore = math.Min(1.08*(isc+exploitability), 10)
	} else {
		rawScore = math.Min(isc+exploitability, 10)
	}

	// Roundup: one decimal place, always up.
	return math.Ceil(rawScore*10) / 10
}

// scoreToSeverity maps a numeric CVSS score onto our Severity enum.
func scoreToSeverity(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score > 0:
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}

// severityToScore maps a severity label (case-insensitive) to a midpoint CVSS
// score. Used as a fallback when no CVSS vector is available. GitHub uses
// "MODERATE" where OSV/CVSS use "MEDIUM".
func severityToScore(s string) float64 {
	switch strings.ToLower(s) {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium", "moderate":
		return 5.0
	case "low":
		return 2.0
	default:
		return 0
	}
}

// advisoryTimeLayouts are the timestamp formats the advisory sources emit. OSV
// and GitHub use RFC3339 ("2021-12-10T00:00:35Z"); NVD omits the zone and keeps
// milliseconds ("2022-01-14T21:15:00.000"), treated as UTC.
var advisoryTimeLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05",
}

// parseAdvisoryTime parses an advisory publish timestamp. An empty or
// unparseable value yields the zero time, which the scorer treats as "unknown
// age" (no age bonus applied).
func parseAdvisoryTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range advisoryTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ghSeverityToModel converts GitHub's severity string to our Severity type.
func ghSeverityToModel(s string) models.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MODERATE", "MEDIUM":
		return models.SeverityMedium
	case "LOW":
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}

// ── HTTP retry with truncated exponential back-off + full jitter ──────────────

const (
	maxRetries   = 3
	retryBaseMS  = 1000
	retryCapMS   = 30000
)

// doWithRetry executes req using client, retrying on HTTP 429 and 5xx responses
// and transient network errors. It honours ctx cancellation between attempts and
// respects a Retry-After header when present.
//
// The request must be repeatable: callers pass a getBody closure that returns a
// fresh *http.Request for each attempt so the body can be re-read.
func doWithRetry(ctx context.Context, client *http.Client, newReq func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			ceiling := math.Min(retryCapMS, retryBaseMS*math.Pow(2, float64(attempt)))
			delay := time.Duration(rand.Float64()*ceiling) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := newReq()
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			// Retriable. Honour Retry-After if there's an attempt left.
			if ra := resp.Header.Get("Retry-After"); ra != "" && attempt < maxRetries-1 {
				if wait := parseRetryAfter(ra); wait > 0 {
					select {
					case <-ctx.Done():
						resp.Body.Close()
						return nil, ctx.Err()
					case <-time.After(wait):
					}
				}
			}
			resp.Body.Close()
			lastErr = &httpStatusError{status: resp.StatusCode}
			continue
		}

		return resp, nil
	}

	if lastErr == nil {
		lastErr = &httpStatusError{status: 0}
	}
	return nil, lastErr
}

// httpStatusError represents a non-2xx response that exhausted its retries.
type httpStatusError struct{ status int }

func (e *httpStatusError) Error() string {
	return "http status " + strconv.Itoa(e.status)
}

// parseRetryAfter interprets a Retry-After header value, which is either a
// number of seconds or an HTTP date.
func parseRetryAfter(header string) time.Duration {
	if secs, err := strconv.Atoi(strings.TrimSpace(header)); err == nil {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(header); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
