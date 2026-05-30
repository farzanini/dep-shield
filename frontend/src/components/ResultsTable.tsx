import { useMemo, useState } from 'react';
import type { ScoredVuln, Severity } from '../wailsjs/go/main/App';
import EcosystemBadge from './EcosystemBadge';

// ── Types ─────────────────────────────────────────────────────────────────────

type SortKey = 'severity' | 'package' | 'ecosystem' | 'cvss' | 'fixedIn';
type SortDir = 'asc' | 'desc';

interface Props {
  vulns: ScoredVuln[];
  selected: ScoredVuln | null;
  onSelect: (v: ScoredVuln | null) => void;
}

// ── Severity ordering ─────────────────────────────────────────────────────────

const SEV_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

const SEV_STYLES: Record<string, { badge: string; row: string }> = {
  CRITICAL: {
    badge: 'bg-red-950 text-red-300 border border-red-800',
    row: 'hover:bg-red-950/20',
  },
  HIGH: {
    badge: 'bg-orange-950 text-orange-300 border border-orange-800',
    row: 'hover:bg-orange-950/20',
  },
  MEDIUM: {
    badge: 'bg-yellow-950 text-yellow-300 border border-yellow-800',
    row: 'hover:bg-yellow-950/20',
  },
  LOW: {
    badge: 'bg-blue-950 text-blue-300 border border-blue-800',
    row: 'hover:bg-blue-950/20',
  },
  UNKNOWN: {
    badge: 'bg-gray-800 text-gray-400 border border-gray-700',
    row: 'hover:bg-gray-800/40',
  },
};

const ALL_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const ALL_ECOSYSTEMS = ['npm', 'Go', 'crates.io', 'PyPI'];

// ── ResultsTable ──────────────────────────────────────────────────────────────

export default function ResultsTable({ vulns, selected, onSelect }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>('severity');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set());
  const [ecoFilter, setEcoFilter] = useState<Set<string>>(new Set());

  // Toggle a set-based filter value.
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
      setSortDir(key === 'severity' || key === 'cvss' ? 'desc' : 'asc');
    }
  };

  // ── Filter then sort ───────────────────────────────────────────────────────
  const visible = useMemo(() => {
    let rows = vulns;

    // Text search: package name or CVE/ID.
    if (query) {
      const q = query.toLowerCase();
      rows = rows.filter(
        (v) =>
          v.package.toLowerCase().includes(q) ||
          v.id.toLowerCase().includes(q) ||
          v.cve.toLowerCase().includes(q) ||
          v.summary.toLowerCase().includes(q),
      );
    }

    // Severity filter.
    if (severityFilter.size > 0) {
      rows = rows.filter((v) => severityFilter.has(v.severity as Severity));
    }

    // Ecosystem filter.
    if (ecoFilter.size > 0) {
      rows = rows.filter((v) => ecoFilter.has(v.ecosystem));
    }

    // Sort.
    return [...rows].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case 'severity':
          cmp = (SEV_RANK[a.severity] ?? 0) - (SEV_RANK[b.severity] ?? 0);
          break;
        case 'package':
          cmp = a.package.localeCompare(b.package);
          break;
        case 'ecosystem':
          cmp = a.ecosystem.localeCompare(b.ecosystem);
          break;
        case 'cvss':
          cmp = a.cvss - b.cvss;
          break;
        case 'fixedIn':
          cmp = (a.fixedIn || 'zzz').localeCompare(b.fixedIn || 'zzz');
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [vulns, query, severityFilter, ecoFilter, sortKey, sortDir]);

  return (
    <div className="flex h-full flex-col">
      {/* ── Filter bar ───────────────────────────────────────────────────── */}
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
              activeStyle={SEV_STYLES[s].badge}
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

        <span className="ml-auto text-xs tabular-nums text-gray-600">
          {visible.length} / {vulns.length}
        </span>
      </div>

      {/* ── Table ────────────────────────────────────────────────────────── */}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 z-10 bg-gray-900">
            <tr className="border-b border-gray-700 text-xs text-gray-500">
              <Th label="Severity" sortKey="severity" current={sortKey} dir={sortDir} onSort={handleSort} />
              <Th label="Package"  sortKey="package"  current={sortKey} dir={sortDir} onSort={handleSort} />
              <Th label="Version"  sortKey={null} />
              <Th label="Ecosystem" sortKey="ecosystem" current={sortKey} dir={sortDir} onSort={handleSort} />
              <Th label="CVE / ID" sortKey={null} />
              <Th label="CVSS" sortKey="cvss" current={sortKey} dir={sortDir} onSort={handleSort} />
              <Th label="Fixed in" sortKey="fixedIn" current={sortKey} dir={sortDir} onSort={handleSort} />
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
            {visible.map((v) => (
              <ResultRow
                key={v.id + v.package + v.version}
                vuln={v}
                isSelected={selected?.id === v.id && selected?.package === v.package}
                onClick={() => onSelect(selected?.id === v.id && selected?.package === v.package ? null : v)}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── ResultRow ─────────────────────────────────────────────────────────────────

function ResultRow({
  vuln: v,
  isSelected,
  onClick,
}: {
  vuln: ScoredVuln;
  isSelected: boolean;
  onClick: () => void;
}) {
  const styles = SEV_STYLES[v.severity] ?? SEV_STYLES['UNKNOWN'];

  return (
    <tr
      onClick={onClick}
      className={[
        'cursor-pointer transition-colors duration-75',
        styles.row,
        isSelected ? 'bg-blue-950/30 ring-1 ring-inset ring-blue-700' : '',
      ].join(' ')}
    >
      {/* Severity */}
      <td className="px-4 py-2.5">
        <span className={`inline-flex rounded px-2 py-0.5 text-xs font-semibold ${styles.badge}`}>
          {v.severity}
        </span>
      </td>

      {/* Package */}
      <td className="max-w-[180px] px-4 py-2.5">
        <span className="block truncate font-medium text-gray-200" title={v.package}>
          {v.package}
        </span>
      </td>

      {/* Version */}
      <td className="px-4 py-2.5 text-xs tabular-nums text-gray-500">
        {v.version}
      </td>

      {/* Ecosystem */}
      <td className="px-4 py-2.5">
        <EcosystemBadge ecosystem={v.ecosystem} />
      </td>

      {/* CVE / ID */}
      <td className="max-w-[160px] px-4 py-2.5">
        <span className="block truncate text-xs tabular-nums text-gray-400" title={v.cve || v.id}>
          {v.cve || v.id}
        </span>
      </td>

      {/* CVSS */}
      <td className="px-4 py-2.5">
        <CvssBar score={v.cvss} />
      </td>

      {/* Fixed In */}
      <td className="px-4 py-2.5 text-xs tabular-nums">
        {v.hasFix ? (
          <span className="text-green-400">{v.fixedIn}</span>
        ) : (
          <span className="text-gray-600">—</span>
        )}
      </td>
    </tr>
  );
}

// ── CvssBar ───────────────────────────────────────────────────────────────────

function CvssBar({ score }: { score: number }) {
  const pct = Math.min(100, (score / 10) * 100);
  const color =
    score >= 9 ? 'bg-red-500'
    : score >= 7 ? 'bg-orange-500'
    : score >= 4 ? 'bg-yellow-500'
    : score > 0  ? 'bg-blue-500'
    : 'bg-gray-700';

  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-gray-800">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs tabular-nums text-gray-400">
        {score > 0 ? score.toFixed(1) : '—'}
      </span>
    </div>
  );
}

// ── Th — sortable column header ───────────────────────────────────────────────

function Th({
  label,
  sortKey,
  current,
  dir,
  onSort,
}: {
  label: string;
  sortKey: SortKey | null;
  current?: SortKey;
  dir?: SortDir;
  onSort?: (k: SortKey) => void;
}) {
  const isSorted = sortKey !== null && current === sortKey;

  if (!sortKey || !onSort) {
    return (
      <th className="px-4 py-2.5 font-medium text-gray-500">{label}</th>
    );
  }

  return (
    <th
      className="cursor-pointer select-none px-4 py-2.5 font-medium text-gray-500 hover:text-gray-300"
      onClick={() => onSort(sortKey)}
    >
      <span className="flex items-center gap-1">
        {label}
        <SortIndicator active={isSorted} dir={dir ?? 'asc'} />
      </span>
    </th>
  );
}

function SortIndicator({ active, dir }: { active: boolean; dir: SortDir }) {
  if (!active) return <span className="text-gray-700">↕</span>;
  return <span className="text-blue-400">{dir === 'asc' ? '↑' : '↓'}</span>;
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

function SearchIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
    </svg>
  );
}
