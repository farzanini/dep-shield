import { useCallback, useEffect, useRef, useState } from 'react';
import { EventsOn } from './wailsjs/runtime/runtime';
import { GetResults } from './wailsjs/go/main/App';
import type { ScanProgress, ScoredVuln } from './wailsjs/go/main/App';
import ScanPanel from './components/ScanPanel';
import SummaryBar from './components/SummaryBar';
import ResultsTable from './components/ResultsTable';
import CVEDetail from './components/CVEDetail';

// ── App state machine ─────────────────────────────────────────────────────────

type AppPhase = 'idle' | 'scanning' | 'done' | 'error';

interface AppState {
  phase: AppPhase;
  progress: ScanProgress | null;
  results: ScoredVuln[];
  errorMsg: string;
}

const INITIAL_STATE: AppState = {
  phase: 'idle',
  progress: null,
  results: [],
  errorMsg: '',
};

// ── App ───────────────────────────────────────────────────────────────────────

export default function App() {
  const [state, setState] = useState<AppState>(INITIAL_STATE);
  const [selectedVuln, setSelectedVuln] = useState<ScoredVuln | null>(null);
  // Keep a ref to the cleanup functions returned by EventsOn so we can
  // remove listeners when the scan ends or the component unmounts.
  const cleanupRef = useRef<Array<() => void>>([]);

  const clearListeners = () => {
    cleanupRef.current.forEach((fn) => fn());
    cleanupRef.current = [];
  };

  // Fetch results after scan:complete fires.
  const handleScanComplete = useCallback(async (ok: unknown) => {
    if (!ok) return;
    try {
      const vulns = await GetResults();
      setState((prev) => ({
        ...prev,
        phase: 'done',
        results: vulns ?? [],
      }));
    } catch (e) {
      setState((prev) => ({
        ...prev,
        phase: 'error',
        errorMsg: String(e),
      }));
    }
  }, []);

  // Called by ScanPanel when the user clicks "Scan".
  const handleScanStart = useCallback(() => {
    // Tear down any previous event listeners.
    clearListeners();
    setSelectedVuln(null);
    setState({ phase: 'scanning', progress: null, results: [], errorMsg: '' });

    // Wire up progress stream.
    const offProgress = EventsOn('scan:progress', (data: unknown) => {
      setState((prev) => ({
        ...prev,
        progress: data as ScanProgress,
        // Mirror error state from events.
        phase: (data as ScanProgress).phase === 'error' ? 'error' : 'scanning',
        errorMsg: (data as ScanProgress).error ?? '',
      }));
    });

    const offComplete = EventsOn('scan:complete', (ok: unknown) => {
      clearListeners();
      handleScanComplete(ok);
    });

    cleanupRef.current = [offProgress, offComplete];
  }, [handleScanComplete]);

  // Clean up on unmount.
  useEffect(() => () => clearListeners(), []);

  const { phase, progress, results, errorMsg } = state;

  return (
    <div className="flex h-full overflow-hidden bg-gray-900">
      {/* ── Sidebar ──────────────────────────────────────────────────────── */}
      <aside className="flex w-72 flex-shrink-0 flex-col border-r border-gray-700 bg-gray-800">
        {/* Title bar / drag region */}
        <div className="drag-region flex h-12 items-center gap-2.5 border-b border-gray-700 px-4">
          <ShieldIcon className="h-5 w-5 text-blue-400" />
          <span className="text-sm font-semibold tracking-wide text-gray-100">
            dep-shield
          </span>
          <span className="ml-auto text-xs text-gray-500">v0.1.0</span>
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          <ScanPanel
            phase={phase}
            progress={progress}
            onScanStart={handleScanStart}
          />
        </div>
      </aside>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <main className="flex flex-1 flex-col overflow-hidden">
        {/* Top bar */}
        <div className="drag-region flex h-12 flex-shrink-0 items-center border-b border-gray-700 bg-gray-800 px-4">
          {phase === 'done' && results.length > 0 && (
            <SummaryBar vulns={results} />
          )}
          {phase === 'idle' && (
            <p className="text-sm text-gray-500">
              Enter a directory path and click Scan to begin.
            </p>
          )}
          {phase === 'scanning' && progress && (
            <p className="text-sm text-blue-400 animate-pulse">
              {progress.message}
            </p>
          )}
          {phase === 'error' && (
            <p className="text-sm text-red-400">
              ⚠ {errorMsg || 'Scan failed — see sidebar for details.'}
            </p>
          )}
          {phase === 'done' && results.length === 0 && (
            <p className="text-sm text-green-400">
              ✓ No vulnerabilities found.
            </p>
          )}
        </div>

        {/* Content area */}
        <div className="relative flex-1 overflow-hidden">
          {phase === 'done' && results.length > 0 ? (
            <ResultsTable
              vulns={results}
              selected={selectedVuln}
              onSelect={setSelectedVuln}
            />
          ) : (
            <EmptyState phase={phase} progress={progress} />
          )}

          {/* CVE detail drawer — slides in from the right over the table */}
          {selectedVuln && (
            <CVEDetail
              vuln={selectedVuln}
              onClose={() => setSelectedVuln(null)}
            />
          )}
        </div>
      </main>
    </div>
  );
}

// ── EmptyState ────────────────────────────────────────────────────────────────

function EmptyState({
  phase,
  progress,
}: {
  phase: AppPhase;
  progress: ScanProgress | null;
}) {
  if (phase === 'scanning' && progress) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-6 text-gray-400">
        <ShieldIcon className="h-16 w-16 text-blue-500 opacity-30" />
        <div className="text-center">
          <p className="text-lg font-medium text-gray-300">{progress.message}</p>
          <p className="mt-1 text-sm">
            {progress.found > 0 && `${progress.found} directories · `}
            {progress.parsed > 0 && `${progress.parsed} packages · `}
            {progress.queried > 0 && `${progress.queried} CVEs`}
          </p>
        </div>
        <SpinnerIcon className="h-6 w-6 animate-spin text-blue-400" />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 text-gray-600">
      <ShieldIcon className="h-20 w-20 opacity-20" />
      <p className="text-sm">Results will appear here after scanning.</p>
    </div>
  );
}

// ── Inline SVG icons ──────────────────────────────────────────────────────────
// Kept inline to avoid an extra icon-library dependency.

function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path
        fillRule="evenodd"
        d="M11.484 2.17a.75.75 0 01.032 0l8.25 3a.75.75 0 01.484.706v2.124a15.75 15.75 0 01-7.5 13.5A15.75 15.75 0 014.25 8v-2.124a.75.75 0 01.484-.706l6.75-2.45v-.001z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function SpinnerIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none">
      <circle
        className="opacity-25"
        cx="12" cy="12" r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}
