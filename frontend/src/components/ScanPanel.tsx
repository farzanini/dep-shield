import { useEffect, useRef, useState } from 'react';
import { StartScan, SelectDirectory, DiscoverRepos, CommonLocations, isBridgeAvailable, isMethodAvailable } from '../wailsjs/go/main/App';
import type { ScanProgress, RepoHit, LocationHint } from '../wailsjs/go/main/App';

interface Props {
  phase: 'idle' | 'scanning' | 'done' | 'error';
  progress: ScanProgress | null;
  onScanStart: () => void;
}

// ── Bridge status detection ───────────────────────────────────────────────────

type BridgeStatus =
  | 'checking'         // still polling — don't show banner yet
  | 'ok'               // all methods available
  | 'missing-methods'  // bridge exists but new methods not registered (needs restart)
  | 'unavailable';     // window.go absent after exhausting retries (browser tab)

function detectBridge(): Exclude<BridgeStatus, 'checking'> {
  if (!isBridgeAvailable()) return 'unavailable';
  if (!isMethodAvailable('SelectDirectory') || !isMethodAvailable('DiscoverRepos')) {
    return 'missing-methods';
  }
  return 'ok';
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ScanPanel({ phase, progress, onScanStart }: Props) {
  // Start as 'checking' so we never flash the error banner on first render.
  const [bridgeStatus, setBridgeStatus] = useState<BridgeStatus>('checking');
  const [path, setPath] = useState('');
  const [validationError, setValidationError] = useState('');
  const [discovering, setDiscovering] = useState(false);
  const [repos, setRepos] = useState<RepoHit[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [discoverError, setDiscoverError] = useState('');
  const [locations, setLocations] = useState<LocationHint[]>([]);
  const [showLocations, setShowLocations] = useState(false);
  const [locationsLoading, setLocationsLoading] = useState(false);
  const [locationsLoaded, setLocationsLoaded] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const isScanning = phase === 'scanning';

  // Poll for window.go — Wails v2 injects the bridge asynchronously in dev
  // mode via a WebSocket handshake, so it may not exist on first render.
  const recheckBridge = () => setBridgeStatus(detectBridge());

  useEffect(() => {
    let cancelled = false;
    let attempts = 0;
    const MAX = 20;       // up to 6 seconds total
    const DELAY = 300;    // ms between attempts

    const tick = () => {
      if (cancelled) return;
      const s = detectBridge();
      if (s === 'ok' || attempts >= MAX) {
        setBridgeStatus(s);
        return;
      }
      attempts++;
      setTimeout(tick, DELAY);
    };

    // Small head-start so Wails has time to inject window.go before first check.
    const t = setTimeout(tick, 150);
    return () => { cancelled = true; clearTimeout(t); };
  }, []);

  // ── Path helpers ───────────────────────────────────────────────────────────

  const setPathAndReset = (p: string) => {
    setPath(p);
    setValidationError('');
    setRepos([]);
    setSelected(new Set());
    setDiscoverError('');
  };

  const handleBrowse = async () => {
    // Re-check bridge on every click — covers the case where Wails finished
    // injecting window.go after our initial polling window ended.
    const current = detectBridge();
    if (current !== 'ok') { setBridgeStatus(current); return; }
    setBridgeStatus('ok');
    try {
      const dir = await SelectDirectory();
      if (dir) setPathAndReset(dir);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.startsWith('bridge-unavailable') || msg.startsWith('method-not-found')) {
        setBridgeStatus(detectBridge());
      } else {
        setValidationError('Could not open folder picker — try typing the path instead.');
      }
    }
  };

  // Core discovery against an explicit target path. Shared by the Discover
  // button and the common-location chips (which pass their own path so they
  // don't race the async `path` state update).
  const runDiscover = async (target: string) => {
    setValidationError('');
    setDiscoverError('');
    setRepos([]);
    setSelected(new Set());
    // Re-check bridge on every click.
    const current = detectBridge();
    if (current !== 'ok') { setBridgeStatus(current); return; }
    setBridgeStatus('ok');

    setDiscovering(true);
    try {
      const hits = await DiscoverRepos(target);
      if (hits && hits.length > 0) {
        setRepos(hits);
        setSelected(new Set(hits.map((h) => h.path)));
      } else {
        setDiscoverError('No package repositories found. Try a broader directory.');
      }
    } catch (e) {
      const raw = e instanceof Error ? e.message : String(e);
      if (raw.startsWith('bridge-unavailable') || raw.startsWith('method-not-found')) {
        setBridgeStatus(detectBridge());
      } else {
        setDiscoverError(raw);
      }
    } finally {
      setDiscovering(false);
    }
  };

  const handleDiscover = async () => {
    const trimmed = path.trim();
    if (!trimmed) {
      setValidationError('Enter or browse to a directory first.');
      inputRef.current?.focus();
      return;
    }
    await runDiscover(trimmed);
  };

  // Common dependency locations (VS Code extensions, global npm, …). Loaded
  // lazily the first time the user expands the helper, since it needs the Go
  // bridge to stat the filesystem.
  const toggleLocations = async () => {
    const next = !showLocations;
    setShowLocations(next);
    if (!next || locationsLoaded || locationsLoading) return;

    const current = detectBridge();
    if (current !== 'ok' || !isMethodAvailable('CommonLocations')) {
      // Stale app or browser tab: surface the restart banner instead of failing silently.
      setBridgeStatus(current === 'ok' ? 'missing-methods' : current);
      return;
    }

    setLocationsLoading(true);
    try {
      const locs = await CommonLocations();
      setLocations(locs ?? []);
      setLocationsLoaded(true);
    } catch {
      setLocations([]);
      setLocationsLoaded(true);
    } finally {
      setLocationsLoading(false);
    }
  };

  const selectLocation = (loc: LocationHint) => {
    setPathAndReset(loc.path);
    void runDiscover(loc.path);
  };

  const toggleRepo = (p: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p);
      else next.add(p);
      return next;
    });
  };

  const toggleAll = () =>
    setSelected((prev) =>
      prev.size === repos.length ? new Set() : new Set(repos.map((r) => r.path)),
    );

  // ── Scan ───────────────────────────────────────────────────────────────────

  const handleScan = async () => {
    const trimmed = path.trim();
    if (!trimmed) {
      setValidationError('Enter a directory path to scan.');
      inputRef.current?.focus();
      return;
    }
    if (repos.length > 0 && selected.size === 0) {
      setValidationError('Select at least one repository to scan.');
      return;
    }
    setValidationError('');
    onScanStart();
    await StartScan(trimmed);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !isScanning) void handleScan();
  };

  // ── Progress ───────────────────────────────────────────────────────────────

  const pct = progress?.percent ?? 0;
  const phaseLabels: Record<string, string> = {
    walking:  'Walking filesystem…',
    parsing:  'Parsing lockfiles…',
    querying: 'Querying CVE databases…',
    scoring:  'Scoring findings…',
    done:     'Complete',
    error:    'Error',
  };

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-widest text-gray-300">
          Scan target
        </h2>
      </div>

      {/* ── Bridge status banner ─────────────────────────────────────────────── */}
      {bridgeStatus !== 'ok' && bridgeStatus !== 'checking' && (
        <BridgeBanner status={bridgeStatus} onRetry={recheckBridge} />
      )}

      {/* ── Path input + Browse ──────────────────────────────────────────────── */}
      <div className="flex flex-col gap-1.5">
        <label className="text-xs text-gray-400" htmlFor="scan-path">
          Directory path
        </label>

        <div className="flex gap-2">
          <input
            id="scan-path"
            ref={inputRef}
            type="text"
            value={path}
            onChange={(e) => setPathAndReset(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="/Users/me/my-project"
            disabled={isScanning}
            spellCheck={false}
            className={[
              'selectable min-w-0 flex-1 rounded-md border bg-gray-900 px-3 py-2',
              'text-sm text-gray-200 placeholder:text-gray-600',
              'focus:outline-none focus:ring-1',
              validationError
                ? 'border-red-600 focus:ring-red-600'
                : 'border-gray-700 focus:ring-blue-500',
              isScanning ? 'cursor-not-allowed opacity-50' : '',
            ].join(' ')}
          />

          {/* Browse */}
          <button
            onClick={() => void handleBrowse()}
            disabled={isScanning}
            className="flex items-center gap-1.5 rounded-md border border-gray-700 bg-gray-900 px-2.5 text-xs text-gray-400 hover:border-gray-500 hover:text-gray-200 disabled:cursor-not-allowed disabled:opacity-30"
          >
            <FolderIcon className="h-3.5 w-3.5" />
            Browse
          </button>

          {/* Clear */}
          {path && !isScanning && (
            <button
              onClick={() => setPathAndReset('')}
              title="Clear"
              className="rounded-md border border-gray-700 bg-gray-900 px-2 text-gray-500 hover:text-gray-300"
            >
              ✕
            </button>
          )}
        </div>

        {validationError && (
          <p className="text-xs text-red-400">{validationError}</p>
        )}
        <p className="text-xs text-gray-400">
          Type a path or click <span className="text-gray-200">Browse</span> to pick a folder.
        </p>

        {/* ── Common locations helper ──────────────────────────────────────── */}
        <button
          type="button"
          onClick={() => void toggleLocations()}
          disabled={isScanning}
          className="mt-0.5 flex items-center gap-1.5 self-start text-xs text-blue-400 transition-colors hover:text-blue-300 disabled:opacity-40"
        >
          <PinIcon className="h-3.5 w-3.5" />
          {showLocations ? 'Hide common locations' : 'Where do extensions & global packages live?'}
          <ChevronIcon className={`h-3 w-3 transition-transform ${showLocations ? 'rotate-180' : ''}`} />
        </button>

        {showLocations && (
          <div className="animate-fade-in rounded-md border border-gray-700 bg-gray-900/40 p-1.5">
            {locationsLoading ? (
              <p className="flex items-center gap-2 px-1.5 py-1.5 text-xs text-gray-500">
                <SpinnerIcon className="h-3.5 w-3.5 animate-spin" /> Looking for common locations…
              </p>
            ) : locations.length === 0 ? (
              <p className="px-1.5 py-1.5 text-xs text-gray-500">
                No common dependency folders found on this machine — type or browse to a path above.
              </p>
            ) : (
              <ul className="flex flex-col gap-0.5">
                {locations.map((loc) => (
                  <li key={loc.path}>
                    <button
                      type="button"
                      onClick={() => selectLocation(loc)}
                      disabled={isScanning || discovering}
                      title={loc.path}
                      className="group flex w-full items-center gap-2.5 rounded px-2 py-1.5 text-left transition-colors hover:bg-gray-700/50 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <span className={`w-14 flex-shrink-0 text-xs font-semibold ${ECO_COLOR[loc.note] ?? 'text-gray-400'}`}>
                        {loc.note}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-xs font-medium text-gray-200">{loc.label}</span>
                        <span className="block truncate font-mono text-[11px] text-gray-500">
                          {truncateMiddle(loc.path, 48)}
                        </span>
                      </span>
                      <span className="flex-shrink-0 text-xs text-blue-400 opacity-0 transition-opacity group-hover:opacity-100">
                        Discover →
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>

      {/* ── Discover button ──────────────────────────────────────────────────── */}
      <button
        onClick={() => void handleDiscover()}
        disabled={isScanning || discovering}
        className={[
          'flex items-center justify-center gap-2 rounded-md border px-4 py-2 text-sm font-medium transition-colors',
          'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800',
          isScanning
            ? 'cursor-not-allowed border-gray-700 bg-transparent text-gray-600'
            : discovering
            ? 'cursor-wait border-blue-800 bg-blue-950/40 text-blue-400'
            : 'border-gray-600 bg-gray-800 text-gray-300 hover:border-gray-500 hover:text-white',
        ].join(' ')}
      >
        {discovering ? (
          <>
            <SpinnerIcon className="h-3.5 w-3.5 animate-spin" />
            Discovering…
          </>
        ) : (
          <>
            <RadarIcon className="h-3.5 w-3.5" />
            Discover repositories
          </>
        )}
      </button>

      {/* ── Discover error ───────────────────────────────────────────────────── */}
      {discoverError && (
        <p className="rounded-md border border-amber-900 bg-amber-950/40 px-3 py-2 text-xs text-amber-400">
          {discoverError}
        </p>
      )}

      {/* ── Discovered repos ─────────────────────────────────────────────────── */}
      {repos.length > 0 && (
        <div className="flex flex-col gap-2 animate-fade-in">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-widest text-gray-500">
              {repos.length} {repos.length === 1 ? 'repo' : 'repos'} found
            </span>
            <button onClick={toggleAll} className="text-xs text-blue-400 hover:text-blue-300">
              {selected.size === repos.length ? 'Deselect all' : 'Select all'}
            </button>
          </div>

          <div className="flex max-h-72 flex-col gap-1 overflow-y-auto rounded-md border border-gray-700 bg-gray-800/50 p-1.5">
            {repos.map((repo) => (
              <RepoItem
                key={repo.path}
                repo={repo}
                checked={selected.has(repo.path)}
                onToggle={() => toggleRepo(repo.path)}
              />
            ))}
          </div>

          {selected.size > 0 && (
            <p className="text-xs text-gray-400">
              {selected.size} of {repos.length} selected · scan covers the root path above.
            </p>
          )}
        </div>
      )}

      {/* ── Scan button ──────────────────────────────────────────────────────── */}
      <button
        onClick={() => void handleScan()}
        disabled={isScanning}
        className={[
          'flex items-center justify-center gap-2 rounded-md px-4 py-2.5',
          'text-sm font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800',
          isScanning
            ? 'cursor-not-allowed bg-gray-700 text-gray-500'
            : 'bg-blue-600 text-white hover:bg-blue-500 active:bg-blue-700',
        ].join(' ')}
      >
        {isScanning ? (
          <>
            <SpinnerIcon className="h-4 w-4 animate-spin" />
            Scanning…
          </>
        ) : (
          <>
            <ScanIcon className="h-4 w-4" />
            {phase === 'done' || phase === 'error' ? 'Scan again' : 'Start scan'}
          </>
        )}
      </button>

      {/* ── Progress block ───────────────────────────────────────────────────── */}
      {(isScanning || phase === 'done') && progress && (
        <div className="flex flex-col gap-2 animate-fade-in">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400">
              {phaseLabels[progress.phase] ?? progress.phase}
            </span>
            <span className="text-xs tabular-nums text-gray-500">{Math.round(pct)}%</span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-700">
            <div
              className="h-full rounded-full bg-blue-500 transition-all duration-300"
              style={{ width: `${pct}%` }}
            />
          </div>
          <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-gray-500">
            {progress.found > 0  && <StatChip label="dirs" value={progress.found} />}
            {progress.parsed > 0 && <StatChip label="pkgs" value={progress.parsed} />}
            {progress.queried > 0 && <StatChip label="CVEs" value={progress.queried} color="text-amber-500" />}
          </div>
          {progress.current && (
            <p className="selectable truncate text-xs text-gray-400" title={progress.current}>
              {truncateMiddle(progress.current, 44)}
            </p>
          )}
        </div>
      )}

      {/* ── Error state ──────────────────────────────────────────────────────── */}
      {phase === 'error' && progress?.error && (
        <div className="rounded-md border border-red-900 bg-red-950 p-3 text-xs text-red-400 selectable">
          {progress.error}
        </div>
      )}
    </div>
  );
}

// ── BridgeBanner ──────────────────────────────────────────────────────────────

function BridgeBanner({ status, onRetry }: { status: BridgeStatus; onRetry: () => void }) {
  const isUnavailable = status === 'unavailable';

  return (
    <div className="rounded-md border border-yellow-800 bg-yellow-950/40 px-3 py-2.5">
      <div className="flex items-start gap-2.5">
        <WarnIcon className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-yellow-500" />
        <div className="min-w-0 flex-1">
          <p className="text-xs font-medium text-yellow-300">
            {isUnavailable ? 'Go bridge not detected yet' : 'App needs a restart'}
          </p>
          <p className="mt-0.5 text-xs text-yellow-600">
            {isUnavailable
              ? 'Wails may still be connecting. Click Retry — if it keeps failing, make sure you\'re using the desktop window, not a browser tab.'
              : 'New Go methods (Browse, Discover) were added since the app last started. Restart to pick them up.'}
          </p>
          <p className="mt-1.5 rounded bg-gray-900/60 px-2 py-1 font-mono text-xs text-gray-400">
            GONOSUMDB='*' GONOSUMCHECK='*' wails dev
          </p>
        </div>
      </div>
      <button
        onClick={onRetry}
        className="mt-2.5 w-full rounded border border-yellow-800 bg-yellow-950/60 py-1 text-xs font-medium text-yellow-400 hover:bg-yellow-900/40 hover:text-yellow-200 transition-colors"
      >
        ↻ Retry bridge detection
      </button>
    </div>
  );
}

// ── RepoItem ──────────────────────────────────────────────────────────────────

const ECO_COLOR: Record<string, string> = {
  npm:         'text-green-400',
  Go:          'text-cyan-400',
  'crates.io': 'text-orange-400',
  PyPI:        'text-yellow-400',
  RubyGems:   'text-red-400',
};

function RepoItem({
  repo, checked, onToggle,
}: {
  repo: RepoHit;
  checked: boolean;
  onToggle: () => void;
}) {
  return (
    <label
      className={[
        'flex cursor-pointer items-start gap-2.5 rounded px-2 py-2 text-sm transition-colors',
        checked ? 'bg-blue-950/40' : 'hover:bg-gray-700/40',
      ].join(' ')}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={onToggle}
        className="mt-0.5 h-4 w-4 flex-shrink-0 accent-blue-500"
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className={`flex-shrink-0 font-semibold ${ECO_COLOR[repo.ecosystem] ?? 'text-gray-300'}`}>
            {repo.ecosystem}
          </span>
          <span className="flex-shrink-0 text-gray-600">·</span>
          {/* Project name = folder above node_modules (or the lockfile dir).
              Hover reveals the full path. */}
          <span className="truncate font-medium text-gray-200" title={repo.path}>
            {projectName(repo.path)}
          </span>
        </div>
        <p
          className="selectable mt-0.5 truncate font-mono text-xs text-gray-500"
          title={repo.path}
        >
          {truncateMiddle(repo.path, 52)}
        </p>
      </div>
    </label>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatChip({ label, value, color = 'text-gray-400' }: {
  label: string; value: number; color?: string;
}) {
  return (
    <span>
      <span className={`font-semibold tabular-nums ${color}`}>{value.toLocaleString()}</span>{' '}
      {label}
    </span>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function truncateMiddle(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  const half = Math.floor((maxLen - 1) / 2);
  return str.slice(0, half) + '…' + str.slice(str.length - half);
}

// Derive a human-readable project name from a repo path. For a path that ends
// in `node_modules`, the project is the folder one level up; otherwise it's the
// last path segment (the lockfile's own directory). Handles both POSIX and
// Windows separators and any trailing slash.
function projectName(p: string): string {
  const parts = p.replace(/[\\/]+$/, '').split(/[\\/]/);
  const last = parts[parts.length - 1] ?? p;
  if (last === 'node_modules' && parts.length >= 2) return parts[parts.length - 2];
  return last || p;
}

// ── Icons ─────────────────────────────────────────────────────────────────────

function FolderIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
    </svg>
  );
}

function RadarIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 3a9 9 0 100 18A9 9 0 0012 3z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 7a5 5 0 100 10A5 5 0 0012 7z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 12l4.5-4.5" />
      <circle cx="12" cy="12" r="1" fill="currentColor" />
    </svg>
  );
}

function ScanIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
    </svg>
  );
}

function SpinnerIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

function PinIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M15 10.5a3 3 0 11-6 0 3 3 0 016 0z" />
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M19.5 10.5c0 7.142-7.5 11.25-7.5 11.25S4.5 17.642 4.5 10.5a7.5 7.5 0 1115 0z" />
    </svg>
  );
}

function ChevronIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
    </svg>
  );
}

function WarnIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path fillRule="evenodd"
        d="M9.401 3.003c1.155-2 4.043-2 5.197 0l7.355 12.748c1.154 2-.29 4.5-2.599 4.5H4.645c-2.309 0-3.752-2.5-2.598-4.5L9.4 3.003zM12 8.25a.75.75 0 01.75.75v3.75a.75.75 0 01-1.5 0V9a.75.75 0 01.75-.75zm0 8.25a.75.75 0 100-1.5.75.75 0 000 1.5z"
        clipRule="evenodd" />
    </svg>
  );
}
