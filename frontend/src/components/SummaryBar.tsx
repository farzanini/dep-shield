import type { ScoredVuln, Severity } from '../wailsjs/go/main/App';

interface Props {
  vulns: ScoredVuln[];
}

interface SeverityMeta {
  label: string;
  bg: string;
  text: string;
  border: string;
  dot: string;
}

const SEVERITY_META: Record<Severity, SeverityMeta> = {
  CRITICAL: {
    label: 'Critical',
    bg: 'bg-red-950',
    text: 'text-red-300',
    border: 'border-red-800',
    dot: 'bg-red-400',
  },
  HIGH: {
    label: 'High',
    bg: 'bg-orange-950',
    text: 'text-orange-300',
    border: 'border-orange-800',
    dot: 'bg-orange-400',
  },
  MEDIUM: {
    label: 'Medium',
    bg: 'bg-yellow-950',
    text: 'text-yellow-300',
    border: 'border-yellow-800',
    dot: 'bg-yellow-400',
  },
  LOW: {
    label: 'Low',
    bg: 'bg-blue-950',
    text: 'text-blue-300',
    border: 'border-blue-800',
    dot: 'bg-blue-400',
  },
  UNKNOWN: {
    label: 'Unknown',
    bg: 'bg-gray-800',
    text: 'text-gray-400',
    border: 'border-gray-700',
    dot: 'bg-gray-500',
  },
};

const DISPLAY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

export default function SummaryBar({ vulns }: Props) {
  // Count by severity.
  const counts = vulns.reduce<Record<Severity, number>>(
    (acc, v) => {
      const sev = (v.severity as Severity) || 'UNKNOWN';
      acc[sev] = (acc[sev] ?? 0) + 1;
      return acc;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
  );

  const total = vulns.length;

  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-gray-500 tabular-nums">
        {total.toLocaleString()} finding{total !== 1 ? 's' : ''}
      </span>
      <span className="text-gray-700">·</span>
      <div className="flex items-center gap-2">
        {DISPLAY_ORDER.filter((s) => counts[s] > 0).map((sev) => {
          const meta = SEVERITY_META[sev];
          return (
            <SeverityChip
              key={sev}
              label={meta.label}
              count={counts[sev]}
              bg={meta.bg}
              text={meta.text}
              border={meta.border}
              dot={meta.dot}
            />
          );
        })}
      </div>
    </div>
  );
}

// ── SeverityChip ──────────────────────────────────────────────────────────────

function SeverityChip({
  label,
  count,
  bg,
  text,
  border,
  dot,
}: {
  label: string;
  count: number;
  bg: string;
  text: string;
  border: string;
  dot: string;
}) {
  return (
    <span
      className={[
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5',
        'text-xs font-medium',
        bg,
        text,
        border,
      ].join(' ')}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
      <span className="tabular-nums">{count}</span>
      <span>{label}</span>
    </span>
  );
}
