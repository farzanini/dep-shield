import { useEffect, useState } from 'react';
import type { ScoredVuln, FixSuggestion } from '../wailsjs/go/main/App';
import { GetSuggestedFix, OpenInBrowser } from '../wailsjs/go/main/App';
import EcosystemBadge from './EcosystemBadge';

interface Props {
  vuln: ScoredVuln;
  onClose: () => void;
}

const SEV_HEADER: Record<string, string> = {
  CRITICAL: 'border-red-800 bg-red-950/60',
  HIGH:     'border-orange-800 bg-orange-950/60',
  MEDIUM:   'border-yellow-800 bg-yellow-950/60',
  LOW:      'border-blue-800 bg-blue-950/60',
  UNKNOWN:  'border-gray-700 bg-gray-800/60',
};

const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-900 text-red-200',
  HIGH:     'bg-orange-900 text-orange-200',
  MEDIUM:   'bg-yellow-900 text-yellow-200',
  LOW:      'bg-blue-900 text-blue-200',
  UNKNOWN:  'bg-gray-700 text-gray-300',
};

const BUMP_LABEL: Record<string, string> = {
  patch:   '🟢 Patch',
  minor:   '🟡 Minor',
  major:   '🔴 Major',
  unknown: '⚪ Unknown',
};

export default function CVEDetail({ vuln: v, onClose }: Props) {
  const [fix, setFix] = useState<FixSuggestion | null>(null);
  const [loadingFix, setLoadingFix] = useState(false);

  // Load fix suggestion when the panel opens or the vuln changes.
  useEffect(() => {
    setFix(null);
    setLoadingFix(true);
    GetSuggestedFix(v.package, v.version)
      .then(setFix)
      .catch(() => setFix(null))
      .finally(() => setLoadingFix(false));
  }, [v.package, v.version]);

  // Close on Escape key.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  const headerStyle = SEV_HEADER[v.severity] ?? SEV_HEADER['UNKNOWN'];
  const badgeStyle  = SEV_BADGE[v.severity]  ?? SEV_BADGE['UNKNOWN'];

  return (
    <>
      {/* Backdrop — click to close */}
      <div
        className="absolute inset-0 bg-black/40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer */}
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="CVE detail"
        className={[
          'absolute inset-y-0 right-0 z-20 flex w-[480px] max-w-full flex-col',
          'border-l border-gray-700 bg-gray-900 shadow-2xl',
          'animate-slide-in',
        ].join(' ')}
      >
        {/* ── Header ─────────────────────────────────────────────────────── */}
        <div className={`flex-shrink-0 border-b px-5 py-4 ${headerStyle}`}>
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded px-2 py-0.5 text-xs font-bold ${badgeStyle}`}>
                  {v.severity}
                </span>
                <EcosystemBadge ecosystem={v.ecosystem} />
                {v.cvss > 0 && (
                  <span className="text-xs tabular-nums text-gray-400">
                    CVSS {v.cvss.toFixed(1)}
                  </span>
                )}
              </div>
              <h2 className="selectable mt-2 text-base font-semibold leading-tight text-gray-100 break-all">
                {v.package}
                <span className="ml-2 text-sm font-normal text-gray-400">
                  {v.version}
                </span>
              </h2>
              {(v.cve || v.id) && (
                <p className="selectable mt-0.5 text-xs tabular-nums text-gray-500">
                  {v.cve || v.id}
                </p>
              )}
            </div>

            <button
              onClick={onClose}
              className="flex-shrink-0 rounded-md p-1.5 text-gray-500 hover:bg-gray-700 hover:text-gray-300 focus:outline-none focus:ring-1 focus:ring-gray-600"
              aria-label="Close"
            >
              <CloseIcon className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* ── Body ───────────────────────────────────────────────────────── */}
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <div className="flex flex-col gap-5">
            {/* Summary */}
            {v.summary && (
              <Section title="Summary">
                <p className="selectable text-sm leading-relaxed text-gray-300">
                  {v.summary}
                </p>
              </Section>
            )}

            {/* Fix advice */}
            <Section title="Fix advice">
              {loadingFix ? (
                <p className="text-sm text-gray-600">Loading…</p>
              ) : fix ? (
                <FixCard fix={fix} />
              ) : (
                <p className="text-sm text-gray-500">{v.fixAdvice}</p>
              )}
            </Section>

            {/* Package metadata */}
            <Section title="Package">
              <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                <MetaRow label="Name"      value={v.package} />
                <MetaRow label="Version"   value={v.version} />
                <MetaRow label="Ecosystem" value={v.ecosystem} />
                {v.fixedIn && <MetaRow label="Fixed in" value={v.fixedIn} highlight />}
              </dl>
            </Section>

            {/* CVE metadata */}
            <Section title="Advisory">
              <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                <MetaRow label="ID" value={v.id} mono />
                {v.cve && <MetaRow label="CVE" value={v.cve} mono />}
                {v.cvss > 0 && (
                  <MetaRow label="CVSS" value={v.cvss.toFixed(1)} />
                )}
              </dl>
            </Section>

            {/* References */}
            {v.references.length > 0 && (
              <Section title="References">
                <ul className="flex flex-col gap-1.5">
                  {v.references.map((url) => (
                    <li key={url}>
                      <button
                        onClick={() => void OpenInBrowser(url)}
                        className="selectable w-full truncate text-left text-xs text-blue-400 hover:text-blue-300 hover:underline focus:outline-none"
                        title={url}
                      >
                        {url}
                      </button>
                    </li>
                  ))}
                </ul>
              </Section>
            )}
          </div>
        </div>

        {/* ── Footer ─────────────────────────────────────────────────────── */}
        {v.cve && (
          <div className="flex-shrink-0 border-t border-gray-700 px-5 py-3">
            <button
              onClick={() =>
                void OpenInBrowser(`https://nvd.nist.gov/vuln/detail/${v.cve}`)
              }
              className="flex w-full items-center justify-center gap-2 rounded-md bg-gray-800 px-4 py-2 text-sm text-gray-300 transition-colors hover:bg-gray-700 hover:text-white"
            >
              <ExternalLinkIcon className="h-3.5 w-3.5" />
              View on NVD
            </button>
          </div>
        )}
      </aside>
    </>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest text-gray-600">
        {title}
      </h3>
      {children}
    </div>
  );
}

function MetaRow({
  label,
  value,
  mono = false,
  highlight = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
  highlight?: boolean;
}) {
  return (
    <>
      <dt className="text-gray-600">{label}</dt>
      <dd
        className={[
          'selectable truncate',
          mono ? 'font-mono text-xs' : '',
          highlight ? 'text-green-400' : 'text-gray-300',
        ].join(' ')}
        title={value}
      >
        {value}
      </dd>
    </>
  );
}

function FixCard({ fix }: { fix: FixSuggestion }) {
  const bump = BUMP_LABEL[fix.changeType] ?? BUMP_LABEL['unknown'];

  return (
    <div className="rounded-md border border-gray-700 bg-gray-800 p-3">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="selectable text-sm font-medium text-gray-200">
            {fix.advice}
          </p>
          {fix.recommended && (
            <div className="mt-1.5 flex items-center gap-2 text-xs text-gray-500">
              <span className="tabular-nums line-through">{fix.current}</span>
              <span>→</span>
              <span className="font-semibold tabular-nums text-green-400">
                {fix.recommended}
              </span>
            </div>
          )}
        </div>
        <span className="flex-shrink-0 text-xs text-gray-500">{bump}</span>
      </div>
    </div>
  );
}

// ── Icons ─────────────────────────────────────────────────────────────────────

function CloseIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function ExternalLinkIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
    </svg>
  );
}
