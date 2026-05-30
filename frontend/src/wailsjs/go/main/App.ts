/**
 * Wails v2 auto-generated bindings for main.App.
 *
 * This file mirrors the exported methods on the Go *App struct in app.go.
 * After running `wails generate module` this file is regenerated; keep the
 * type signatures here in sync with app.go manually if you change the Go API
 * before running the generator.
 *
 * Each function bridges to the Wails webview IPC layer via window.go.main.App.
 */

// ── Shared types (must match Go structs in app.go exactly) ───────────────────

/** Emitted on the "scan:progress" event during StartScan. */
export interface ScanProgress {
  phase: 'walking' | 'parsing' | 'querying' | 'scoring' | 'done' | 'error';
  found: number;
  parsed: number;
  queried: number;
  percent: number;
  current: string;
  message: string;
  error?: string;
}

/** One vulnerability finding returned by GetResults. */
export interface ScoredVuln {
  id: string;
  cve: string;               // "CVE-2021-44228" or "" for GHSA-only entries
  severity: Severity;
  cvss: number;              // 0–10
  normScore: number;
  package: string;
  version: string;
  ecosystem: string;         // "npm" | "Go" | "crates.io" | "PyPI"
  fixedIn: string;
  hasFix: boolean;
  fixAdvice: string;
  summary: string;
  references: string[];
  daysSincePublished: number;
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

/** Returned by GetSuggestedFix. */
export interface FixSuggestion {
  package: string;
  current: string;
  recommended: string;
  changeType: 'patch' | 'minor' | 'major' | 'unknown';
  advice: string;
}

// ── Bridge helpers ────────────────────────────────────────────────────────────

/** Call a bound Go method via the Wails IPC bridge. */
function call<T>(method: string, ...args: unknown[]): Promise<T> {
  const ns = window.go?.['main'];
  const app = ns?.['App'] as Record<string, (...a: unknown[]) => Promise<unknown>> | undefined;
  if (!app) {
    return Promise.reject(
      new Error('[wails] Go bridge not available — is the app running inside Wails?'),
    );
  }
  return app[method]?.(...args) as Promise<T>;
}

// ── Exported method bindings ─────────────────────────────────────────────────

/**
 * StartScan begins an asynchronous vulnerability scan of the given path.
 * Returns immediately; progress arrives via the "scan:progress" event.
 * When the scan finishes the "scan:complete" event fires.
 */
export function StartScan(path: string): Promise<void> {
  return call<void>('StartScan', path);
}

/**
 * GetResults returns the findings from the most recently completed scan.
 * Returns null if no scan has completed yet.
 */
export function GetResults(): Promise<ScoredVuln[] | null> {
  return call<ScoredVuln[] | null>('GetResults');
}

/**
 * OpenInBrowser opens url in the system's default browser.
 */
export function OpenInBrowser(url: string): Promise<void> {
  return call<void>('OpenInBrowser', url);
}

/**
 * GetSuggestedFix returns upgrade advice for a specific package+version pair.
 */
export function GetSuggestedFix(
  pkgName: string,
  version: string,
): Promise<FixSuggestion> {
  return call<FixSuggestion>('GetSuggestedFix', pkgName, version);
}
