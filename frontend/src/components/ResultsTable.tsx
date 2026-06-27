import { useMemo, useState } from 'react';
import type { ScoredVuln, Severity } from '../wailsjs/go/main/App';
import { ExportReport } from '../wailsjs/go/main/App';
import EcosystemBadge from './EcosystemBadge';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface PackageRow {
  key: string;           // `${package}@${version}@${ecosystem}`
  package: string;
  version: string;
  ecosystem: string;
  source: string;        // "project" | "vscode-ext" | "cursor-ext" | "global" | "system"
  sourceLabel: string;
  worstSeverity: Severity;
  cveCount: number;
  hasFix: boolean;
  fixedIn: string;
  fixCommand: string;    // e.g. "npm install lodash@4.17.21"
  vulns: ScoredVuln[];
}

type SortKey = 'package' | 'version' | 'ecosystem' | 'severity' | 'cveCount' | 'hasFix' | 'source';
type SortDir = 'asc' | 'desc';

interface Props {
  vulns: ScoredVuln[];
  onSelectPackage: (pkg: PackageRow) => void;
}

// ── Severity ordering ─────────────────────────────────────────────────────────

const SEV_RANK: Record<string, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0,
};

// Light + dark dual-mode badge classes (Tailwind dark: prefix requires darkMode:'class')
const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 border border-red-300 dark:bg-red-950 dark:text-red-300 dark:border-red-800',
  HIGH:     'bg-orange-100 text-orange-800 border border-orange-300 dark:bg-orange-950 dark:text-orange-300 dark:border-orange-800',
  MEDIUM:   'bg-yellow-100 text-yellow-800 border border-yellow-300 dark:bg-yellow-950 dark:text-yellow-300 dark:border-yellow-800',
  LOW:      'bg-blue-100 text-blue-800 border border-blue-300 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-800',
  UNKNOWN:  'bg-gray-100 text-gray-600 border border-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-700',
};

// Pill style for filter buttons when active
const SEV_PILL_ACTIVE: Record<string, string> = {
  CRITICAL: 'bg-red-950 text-red-300 border-red-800',
  HIGH:     'bg-orange-950 text-orange-300 border-orange-800',
  MEDIUM:   'bg-yellow-950 text-yellow-300 border-yellow-800',
  LOW:      'bg-blue-950 text-blue-300 border-blue-800',
  UNKNOWN:  'bg-gray-800 text-gray-400 border-gray-700',
};

const ALL_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const ALL_ECOSYSTEMS = ['npm', 'Go', 'crates.io', 'PyPI'];
const ALL_SOURCES = [
  { value: 'project',    label: 'Project' },
  { value: 'vscode-ext', label: 'VS Code ext' },
  { value: 'cursor-ext', label: 'Cursor ext' },
  { value: 'global',     label: 'Global' },
  { value: 'system',     label: 'System' },
];

// ── Grouping helpers ──────────────────────────────────────────────────────────

function buildFixCommand(pkg: string, fixedIn: string, ecosystem: string): string {
  if (!fixedIn) return '';
  switch (ecosystem) {
    case 'npm':       return `npm install ${pkg}@${fixedIn}`;
    case 'Go':        return `go get ${pkg}@v${fixedIn.replace(/^v/, '')}`;
    case 'crates.io': return `cargo update -p ${pkg} --precise ${fixedIn}`;
    case 'PyPI':      return `pip install "${pkg}==${fixedIn}"`;
    default:          return `Update ${pkg} to ${fixedIn}`;
  }
}

function groupIntoPackageRows(vulns: ScoredVuln[]): PackageRow[] {
  const map = new Map<string, PackageRow>();
  for (const v of vulns) {
    const key = `${v.package}@${v.version}@${v.ecosystem}`;
    const existing = map.get(key);
    if (existing) {
      existing.vulns.push(v);
      existing.cveCount += 1;
      if ((SEV_RANK[v.severity] ?? 0) > (SEV_RANK[existing.worstSeverity] ?? 0)) {
        existing.worstSeverity = v.severity;
      }
      if (v.hasFix && !existing.hasFix) {
        existing.hasFix = true;
        existing.fixedIn = v.fixedIn;
        existing.fixCommand = buildFixCommand(v.package, v.fixedIn, v.ecosystem);
      }
    } else {
      map.set(key, {
        key,
        package: v.package,
        version: v.version,
        ecosystem: v.ecosystem,
        source: v.source || 'project',
        sourceLabel: v.sourceLabel || 'Project',
        worstSeverity: v.severity,
        cveCount: 1,
        hasFix: v.hasFix,
        fixedIn: v.fixedIn,
        fixCommand: buildFixCommand(v.package, v.fixedIn, v.ecosystem),
        vulns: [v],
      });
    }
  }
  return Array.from(map.values());
}

// ── ResultsTable ──────────────────────────────────────────────────────────────

export default function ResultsTable({ vulns, onSelectPackage }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>('severity');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set());
  const [ecoFilter, setEcoFilter] = useState<Set<string>>(new Set());
  const [sourceFilter, setSourceFilter] = useState<Set<string>>(new Set());
  const [exportState, setExportState] = useState<'idle' | 'success' | 'error'>('idle');

  function toggleFilter<T>(set: Set<T>, value: T, setter: (s: Set<T>) => void) {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    setter(next);
  }

  const handleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir(key === 'severity' || key === 'cveCount' ? 'desc' : 'asc');
    }
  };

  const handleExport = async () => {
    try {
      const path = await ExportReport();
      setExportState(path ? 'success' : 'idle');
      if (path) setTimeout(() => setExportState('idle'), 2500);
    } catch {
      setExportState('error');
      setTimeout(() => setExportState('idle'), 2500);
    }
  };

  const rows = useMemo(() => groupIntoPackageRows(vulns), [vulns]);

  const visible = useMemo(() => {
    let r = rows;

    if (query) {
      const q = query.toLowerCase();
      r = r.filter(
        (row) =>
          row.package.toLowerCase().includes(q) ||
          row.vulns.some(
            (v) => v.id.toLowerCase().includes(q) || v.cve.toLowerCase().includes(q),
          ),
      );
    }

    if (severityFilter.size > 0) {
      r = r.filter((row) => severityFilter.has(row.worstSeverity));
    }

    if (ecoFilter.size > 0) {
      r = r.filter((row) => ecoFilter.has(row.ecosystem));
    }

    if (sourceFilter.size > 0) {
      r = r.filter((row) => sourceFilter.has(row.source));
    }

    return [...r].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case 'severity':
          cmp = (SEV_RANK[a.worstSeverity] ?? 0) - (SEV_RANK[b.worstSeverity] ?? 0);
          break;
        case 'package':  cmp = a.package.localeCompare(b.package); break;
        case 'version':  cmp = a.version.localeCompare(b.version); break;
        case 'ecosystem': cmp = a.ecosystem.localeCompare(b.ecosystem); break;
        case 'cveCount': cmp = a.cveCount - b.cveCount; break;
        case 'hasFix':   cmp = Number(a.hasFix) - Number(b.hasFix); break;
        case 'source':   cmp = a.source.localeCompare(b.source); break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [rows, query, severityFilter, ecoFilter, sourceFilter, sortKey, sortDir]);

  return (
    <div className="flex h-full flex-col">
      {/* ── Filter / toolbar bar ─────────────────────────────────────────── */}
      <div className="flex flex-shrink-0 flex-wrap items-center gap-3 border-b border-gray-700 bg-gray-900 px-4 py-2.5">
        {/* Search */}
        <div className="relative">
          <SearchIcon className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-600" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search package or CVE…"
            className="selectable rounded-md border border-gray-700 bg-gray-800 py-1.5 pl-8 pr-3 text-xs text-gray-200 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-400"
            >
              ✕
            </button>
          )}
        </div>

        {/* Severity toggles */}
        <div className="flex items-center gap-1">
          {ALL_SEVERITIES.map((s) => (
            <FilterPill
              key={s}
              label={s.charAt(0) + s.slice(1).toLowerCase()}
              active={severityFilter.has(s)}
              onClick={() => toggleFilter(severityFilter, s, setSeverityFilter)}
              activeStyle={SEV_PILL_ACTIVE[s]}
            />
          ))}
        </div>

        {/* Ecosystem toggles */}
        <div className="flex items-center gap-1">
          {ALL_ECOSYSTEMS.map((e) => (
            <FilterPill
              key={e}
              label={e}
              active={ecoFilter.has(e)}
              onClick={() => toggleFilter(ecoFilter, e, setEcoFilter)}
              activeStyle="bg-gray-600 text-white border-gray-500"
            />
          ))}
        </div>

        {/* Source toggles */}
        <div className="flex items-center gap-1">
          {ALL_SOURCES.map(({ value, label }) => (
            <FilterPill
              key={value}
              label={label}
              active={sourceFilter.has(value)}
              onClick={() => toggleFilter(sourceFilter, value, setSourceFilter)}
              activeStyle={
                value === 'vscode-ext' || value === 'cursor-ext'
                  ? 'bg-amber-900 text-amber-200 border-amber-700'
                  : 'bg-indigo-900 text-indigo-200 border-indigo-700'
              }
            />
          ))}
        </div>

        {/* Count + Export */}
        <div className="ml-auto flex items-center gap-3">
          <span className="text-xs tabular-nums text-gray-600">
            {visible.length} / {rows.length} packages
          </span>
          <button
            onClick={() => void handleExport()}
            className={[
              'flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors',
              exportState === 'success'
                ? 'border-green-700 bg-green-950 text-green-300'
                : exportState === 'error'
                ? 'border-red-700 bg-red-950 text-red-300'
                : 'border-gray-600 bg-gray-800 text-gray-400 hover:border-gray-500 hover:text-gray-200',
            ].join(' ')}
          >
            <DownloadIcon className="h-3.5 w-3.5" />
            {exportState === 'success'
              ? '✓ Saved'
              : exportState === 'error'
              ? '✗ Failed'
              : 'Export HTML'}
          </button>
        </div>
      </div>

      {/* ── Table ────────────────────────────────────────────────────────── */}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 z-10 bg-gray-900">
            <tr className="border-b border-gray-700 text-xs text-gray-500">
              <Th label="Package"   sortKey="package"   current={sortKey} dir={sortDir} onSort={handleSort} />
              <Th label="Version"   sortKey="version"   current={sortKey} dir={sortDir} onSort={handleSort} />
              <Th label="Ecosystem" sortKey="ecosystem" current={sortKey} dir={sortDir} onSort={handleSort} />
              <Th label="Severity"  sortKey="severity"  current={sortKey} dir={sortDir} onSort={handleSort} />
              <Th label="CVEs"      sortKey="cveCount"  current={sortKey} dir={sortDir} onSort={handleSort} />
              <Th label="Fix"       sortKey="hasFix"    current={sortKey} dir={sortDir} onSort={handleSort} />
              <Th label="Source"    sortKey="source"    current={sortKey} dir={sortDir} onSort={handleSort} />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {visible.length === 0 && (
              <tr>
                <td colSpan={7} className="py-12 text-center text-sm text-gray-600">
                  No results match the current filters.
                </td>
              </tr>
            )}
            {visible.map((row) => (
              <PackageRowEl
                key={row.key}
                row={row}
                onClick={() => onSelectPackage(row)}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── PackageRowEl ──────────────────────────────────────────────────────────────

function PackageRowEl({
  row,
  onClick,
}: {
  row: PackageRow;
  onClick: () => void;
}) {
  const isRisky = row.source === 'vscode-ext' || row.source === 'cursor-ext';

  return (
    <tr
      onClick={onClick}
      className={[
        'cursor-pointer transition-colors duration-75',
        isRisky
          ? 'bg-amber-950/10 hover:bg-amber-950/25'
          : 'hover:bg-gray-800/60',
      ].join(' ')}
    >
      {/* Package */}
      <td className="max-w-[200px] px-4 py-2.5">
        <span className="block truncate font-medium text-gray-200" title={row.package}>
          {row.package}
        </span>
      </td>

      {/* Version */}
      <td className="px-4 py-2.5 text-xs tabular-nums text-gray-500">
        {row.version}
      </td>

      {/* Ecosystem */}
      <td className="px-4 py-2.5">
        <EcosystemBadge ecosystem={row.ecosystem} />
      </td>

      {/* Severity */}
      <td className="px-4 py-2.5">
        <span
          className={`inline-flex rounded px-2 py-0.5 text-xs font-semibold ${SEV_BADGE[row.worstSeverity] ?? SEV_BADGE['UNKNOWN']}`}
        >
          {row.worstSeverity}
        </span>
      </td>

      {/* CVE count */}
      <td className="px-4 py-2.5 text-xs tabular-nums text-gray-400">
        {row.cveCount}
      </td>

      {/* Fix available */}
      <td className="px-4 py-2.5">
        {row.hasFix ? (
          <span className="inline-flex items-center gap-1 text-xs text-green-400">
            <CheckIcon className="h-3 w-3" />
            {row.fixedIn}
          </span>
        ) : (
          <span className="text-xs text-gray-600">—</span>
        )}
      </td>

      {/* Source */}
      <td className="px-4 py-2.5">
        <span
          className={[
            'inline-flex items-center gap-1 text-xs',
            isRisky ? 'font-medium text-amber-400' : 'text-gray-500',
          ].join(' ')}
        >
          {isRisky && <WarnIcon className="h-3 w-3 flex-shrink-0" />}
          {row.sourceLabel}
        </span>
      </td>
    </tr>
  );
}

// ── Th ────────────────────────────────────────────────────────────────────────

function Th({
  label,
  sortKey,
  current,
  dir,
  onSort,
}: {
  label: string;
  sortKey: SortKey;
  current?: SortKey;
  dir?: SortDir;
  onSort?: (k: SortKey) => void;
}) {
  const isSorted = current === sortKey;
  return (
    <th
      className="cursor-pointer select-none px-4 py-2.5 font-medium text-gray-500 hover:text-gray-300"
      onClick={() => onSort?.(sortKey)}
    >
      <span className="flex items-center gap-1">
        {label}
        {isSorted ? (
          <span className="text-blue-400">{dir === 'asc' ? '↑' : '↓'}</span>
        ) : (
          <span className="text-gray-700">↕</span>
        )}
      </span>
    </th>
  );
}

// ── FilterPill ────────────────────────────────────────────────────────────────

function FilterPill({
  label,
  active,
  onClick,
  activeStyle,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  activeStyle: string;
}) {
  return (
    <button
      onClick={onClick}
      className={[
        'rounded border px-2 py-0.5 text-xs font-medium transition-colors',
        active
          ? activeStyle
          : 'border-gray-700 bg-transparent text-gray-600 hover:border-gray-500 hover:text-gray-400',
      ].join(' ')}
    >
      {label}
    </button>
  );
}

// ── Icons ─────────────────────────────────────────────────────────────────────

function SearchIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
    </svg>
  );
}

function DownloadIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
    </svg>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
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
