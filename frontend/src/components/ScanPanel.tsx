import { useRef, useState } from 'react';
import { StartScan } from '../wailsjs/go/main/App';
import type { ScanProgress } from '../wailsjs/go/main/App';

interface Props {
  phase: 'idle' | 'scanning' | 'done' | 'error';
  progress: ScanProgress | null;
  onScanStart: () => void;
}

export default function ScanPanel({ phase, progress, onScanStart }: Props) {
  const [path, setPath] = useState('');
  const [validationError, setValidationError] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const isScanning = phase === 'scanning';

  const handleScan = async () => {
    const trimmed = path.trim();
    if (!trimmed) {
      setValidationError('Enter a directory path to scan.');
      inputRef.current?.focus();
      return;
    }
    setValidationError('');
    onScanStart();           // update parent state first
    await StartScan(trimmed); // fire-and-forget; events drive the rest
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !isScanning) void handleScan();
  };

  // ── Progress bar ────────────────────────────────────────────────────────────
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
      {/* Section label */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-widest text-gray-500">
          Scan target
        </h2>
      </div>

      {/* Path input */}
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
            onChange={(e) => {
              setPath(e.target.value);
              if (validationError) setValidationError('');
            }}
            onKeyDown={handleKeyDown}
            placeholder="/Users/me/my-project"
            disabled={isScanning}
            spellCheck={false}
            className={[
              'selectable flex-1 rounded-md border bg-gray-900 px-3 py-2',
              'text-sm text-gray-200 placeholder:text-gray-600',
              'focus:outline-none focus:ring-1',
              validationError
                ? 'border-red-600 focus:ring-red-600'
                : 'border-gray-700 focus:ring-blue-500',
              isScanning ? 'opacity-50 cursor-not-allowed' : '',
            ].join(' ')}
          />
          <button
            onClick={() => setPath('')}
            disabled={isScanning || !path}
            title="Clear"
            className="rounded-md border border-gray-700 bg-gray-900 px-2 text-gray-500 hover:text-gray-300 disabled:opacity-30"
          >
            ✕
          </button>
        </div>
        {validationError && (
          <p className="text-xs text-red-400">{validationError}</p>
        )}
        <p className="text-xs text-gray-600">
          Tip: use <code className="text-gray-500">~</code> for your home directory.
        </p>
      </div>

      {/* Scan button */}
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

      {/* Progress block */}
      {(isScanning || phase === 'done') && progress && (
        <div className="flex flex-col gap-2 animate-fade-in">
          {/* Phase label + percentage */}
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-400">
              {phaseLabels[progress.phase] ?? progress.phase}
            </span>
            <span className="text-xs tabular-nums text-gray-500">
              {Math.round(pct)}%
            </span>
          </div>

          {/* Progress bar */}
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-700">
            <div
              className="h-full rounded-full bg-blue-500 transition-all duration-300"
              style={{ width: `${pct}%` }}
            />
          </div>

          {/* Stats row */}
          <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-gray-500">
            {progress.found > 0 && (
              <StatChip label="dirs" value={progress.found} />
            )}
            {progress.parsed > 0 && (
              <StatChip label="pkgs" value={progress.parsed} />
            )}
            {progress.queried > 0 && (
              <StatChip label="CVEs" value={progress.queried} color="text-amber-500" />
            )}
          </div>

          {/* Current path — truncate in the middle */}
          {progress.current && (
            <p
              className="truncate text-xs text-gray-600"
              title={progress.current}
            >
              {truncateMiddle(progress.current, 34)}
            </p>
          )}
        </div>
      )}

      {/* Error state */}
      {phase === 'error' && progress?.error && (
        <div className="rounded-md border border-red-900 bg-red-950 p-3 text-xs text-red-400 selectable">
          {progress.error}
        </div>
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatChip({
  label,
  value,
  color = 'text-gray-400',
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <span>
      <span className={`font-semibold tabular-nums ${color}`}>
        {value.toLocaleString()}
      </span>{' '}
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

// ── Icons ─────────────────────────────────────────────────────────────────────

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
      <circle className="opacity-25" cx="12" cy="12" r="10"
        stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}
