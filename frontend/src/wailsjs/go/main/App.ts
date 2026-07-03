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
  phase: 'cloning' | 'collecting' | 'walking' | 'parsing' | 'querying' | 'scoring' | 'done' | 'error';
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
  source: string;            // "project" | "vscode-ext" | "cursor-ext" | "global" | "system"
  sourceLabel: string;       // human-readable label
  path: string;              // where the package was found (e.g. the node_modules dir)
  repoPath: string;          // directory the fix command should be run in (project root)
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

/** Returns true when the Wails Go bridge is available (i.e. running inside the desktop app). */
export function isBridgeAvailable(): boolean {
  return typeof window !== 'undefined' && !!window.go?.['main']?.['App'];
}

/** Returns true when a specific Go method is registered on the bound App. */
export function isMethodAvailable(method: string): boolean {
  const app = window.go?.['main']?.['App'] as Record<string, unknown> | undefined;
  return typeof app?.[method] === 'function';
}

/** Call a bound Go method via the Wails IPC bridge. */
function call<T>(method: string, ...args: unknown[]): Promise<T> {
  const ns = window.go?.['main'];
  const app = ns?.['App'] as Record<string, (...a: unknown[]) => Promise<unknown>> | undefined;
  if (!app) {
    return Promise.reject(new Error('bridge-unavailable'));
  }
  const fn = app[method];
  if (typeof fn !== 'function') {
    return Promise.reject(new Error(`method-not-found:${method}`));
  }
  return fn(...args) as Promise<T>;
}

/** One package-repository directory found by DiscoverRepos. */
export interface RepoHit {
  path: string;
  ecosystem: string; // "npm" | "Go" | "crates.io" | "PyPI" | "RubyGems"
  label: string;     // human-readable description
}

/** A well-known dependency location returned by CommonLocations. */
export interface LocationHint {
  label: string;
  path: string;
  note: string; // ecosystem hint, e.g. "npm" | "Go"
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
 * StartScanRepo clones a remote git repository and scans the checkout.
 * `url` may be https:// (token used for private repos) or an SSH URL
 * (git@… / ssh://…, authenticated via the user's SSH keys — token ignored).
 * Progress arrives via the same "scan:progress"/"scan:complete" events.
 */
export function StartScanRepo(url: string, token: string): Promise<void> {
  return call<void>('StartScanRepo', url, token);
}

/**
 * StartSystemScan scans the host's system package managers (dpkg/apt, apk,
 * Homebrew) for vulnerable OS packages. Returns immediately; progress arrives
 * via the same "scan:progress"/"scan:complete" events as StartScan.
 */
export function StartSystemScan(): Promise<void> {
  return call<void>('StartSystemScan');
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
 * OpenTerminal opens the system terminal with its working directory set to dir
 * (or the home directory when dir is empty), so a fix command can be run there.
 * Rejects with an error when no terminal could be launched.
 */
export function OpenTerminal(dir: string): Promise<void> {
  return call<void>('OpenTerminal', dir);
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

/**
 * ExportReport shows a save-file dialog and writes an HTML vulnerability report.
 * Returns the path written, or an empty string if the user cancelled.
 */
export function ExportReport(): Promise<string> {
  return call<string>('ExportReport');
}

/**
 * SelectDirectory shows a native OS folder-picker dialog.
 * Returns the selected path, or "" if the user cancelled.
 */
export function SelectDirectory(): Promise<string> {
  // Wails unwraps (string, error) — the promise resolves to string or rejects with the error.
  return call<string>('SelectDirectory');
}

/**
 * DiscoverRepos walks root (up to 6 levels deep) looking for package
 * repositories and returns a list of hits, or rejects with a descriptive error.
 */
export function DiscoverRepos(root: string): Promise<RepoHit[]> {
  // Wails unwraps ([]RepoHit, error) — rejects on Go error.
  return call<RepoHit[]>('DiscoverRepos', root);
}

/**
 * CommonLocations returns well-known dependency directories (editor extensions,
 * global npm/Go/Cargo stores) that exist on this machine, for use as one-click
 * scan targets. Returns an empty list if none are present.
 */
export function CommonLocations(): Promise<LocationHint[]> {
  return call<LocationHint[]>('CommonLocations');
}
