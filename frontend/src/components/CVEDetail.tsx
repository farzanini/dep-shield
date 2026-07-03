import { useEffect, useState } from 'react';
import type { PackageRow } from './ResultsTable';
import type { ScoredVuln } from '../wailsjs/go/main/App';
import { OpenInBrowser, OpenTerminal, isMethodAvailable } from '../wailsjs/go/main/App';
import EcosystemBadge from './EcosystemBadge';

interface Props {
  pkg: PackageRow;
  onClose: () => void;
}

const SEV_HEADER: Record<string, string> = {
  CRITICAL: 'border-red-800 bg-red-950/60',
  HIGH:     'border-orange-800 bg-orange-950/60',
  MEDIUM:   'border-yellow-800 bg-yellow-950/60',
  LOW:      'border-blue-800 bg-blue-950/60',
  UNKNOWN:  'border-gray-700 bg-gray-800/60',
};

// Dual-mode badge: light bg for OS light mode, dark bg for dark mode
const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  HIGH:     'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  MEDIUM:   'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  LOW:      'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  UNKNOWN:  'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
};

export default function CVEDetail({ pkg, onClose }: Props) {
  // Close on Escape.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  const headerStyle = SEV_HEADER[pkg.worstSeverity] ?? SEV_HEADER['UNKNOWN'];

  return (
    <>
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer */}
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Package CVE detail"
        className={[
          'absolute inset-y-0 right-0 z-20 flex w-[520px] max-w-full flex-col',
          'border-l border-gray-700 bg-gray-900 shadow-2xl',
          'animate-slide-in',
        ].join(' ')}
      >
        {/* ── Header ───────────────────────────────────────────────────────── */}
        <div className={`flex-shrink-0 border-b px-5 py-4 ${headerStyle}`}>
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded px-2 py-0.5 text-xs font-bold ${SEV_BADGE[pkg.worstSeverity] ?? SEV_BADGE['UNKNOWN']}`}>
                  {pkg.worstSeverity}
                </span>
                <EcosystemBadge ecosystem={pkg.ecosystem} />
                <span className="text-xs text-gray-400">
                  {pkg.cveCount} {pkg.cveCount === 1 ? 'CVE' : 'CVEs'}
                </span>
              </div>
              <h2 className="selectable mt-2 text-base font-semibold leading-tight text-gray-100 break-all">
                {pkg.package}
                <span className="ml-2 text-sm font-normal text-gray-400">{pkg.version}</span>
              </h2>
              <p className="mt-0.5 text-xs text-gray-500">{pkg.sourceLabel}</p>
            </div>

            <button
              onClick={onClose}
              className="flex-shrink-0 rounded-md p-1.5 text-gray-500 hover:bg-gray-700 hover:text-gray-300 focus:outline-none focus:ring-1 focus:ring-gray-600"
              aria-label="Close"
            >
              <CloseIcon className="h-4 w-4" />
            </button>
          </div>

          {/* Fix command + where to run it */}
          {pkg.fixCommand && (
            <div className="mt-3 flex flex-col gap-1.5">
              <p className="text-xs text-gray-500">Recommended fix</p>
              <CopyableCommand command={pkg.fixCommand} />
              {pkg.repoPath && (
                <>
                  <p className="mt-1 flex items-center gap-1.5 text-xs text-gray-500">
                    <TerminalIcon className="h-3.5 w-3.5 flex-shrink-0" />
                    Run it in this folder
                  </p>
                  <CopyableCommand command={pkg.repoPath} />
                </>
              )}
              {isMethodAvailable('OpenTerminal') && (
                <OpenTerminalButton dir={pkg.repoPath} command={pkg.fixCommand} />
              )}
            </div>
          )}
        </div>

        {/* ── Body ─────────────────────────────────────────────────────────── */}
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <div className="flex flex-col gap-6">
            {pkg.vulns.map((v) => (
              <VulnEntry key={v.id} vuln={v} />
            ))}
          </div>
        </div>
      </aside>
    </>
  );
}

// ── VulnEntry — one CVE inside the drawer ─────────────────────────────────────

function VulnEntry({ vuln: v }: { vuln: ScoredVuln }) {
  const badgeStyle = SEV_BADGE[v.severity] ?? SEV_BADGE['UNKNOWN'];

  return (
    <div className="rounded-md border border-gray-800 bg-gray-800/40 p-4">
      {/* CVE header row */}
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded px-2 py-0.5 text-xs font-semibold ${badgeStyle}`}>
          {v.severity}
        </span>
        {(v.cve || v.id) && (
          <span className="selectable font-mono text-xs text-gray-400">{v.cve || v.id}</span>
        )}
        {v.cvss > 0 && (
          <span className="ml-auto text-xs tabular-nums text-gray-500">CVSS {v.cvss.toFixed(1)}</span>
        )}
      </div>

      {/* Summary */}
      {v.summary && (
        <p className="selectable mt-2 text-sm leading-relaxed text-gray-300">{v.summary}</p>
      )}

      {/* Affected range + fix */}
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
        <dt className="text-gray-600">Affected</dt>
        <dd className="selectable text-gray-400">&lt; {v.fixedIn || 'unknown'}</dd>
        {v.fixedIn && (
          <>
            <dt className="text-gray-600">Fixed in</dt>
            <dd className="selectable font-semibold text-green-400">{v.fixedIn}</dd>
          </>
        )}
      </dl>

      {/* Suggestion — always present; the scorer fills this for every finding,
          even when no fixed version exists (e.g. Homebrew/NVD advisories). */}
      {v.fixAdvice && (
        <div className="mt-3 rounded bg-gray-900/60 px-3 py-2">
          <p className="text-xs font-medium text-gray-500">Suggestion</p>
          <p className="selectable mt-0.5 text-xs text-gray-300">{v.fixAdvice}</p>
        </div>
      )}

      {/* References */}
      {v.references.length > 0 && (
        <div className="mt-3">
          <p className="mb-1 text-xs font-medium text-gray-600">References</p>
          <ul className="flex flex-col gap-1">
            {v.references.slice(0, 5).map((url) => (
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
            {v.references.length > 5 && (
              <li className="text-xs text-gray-600">+{v.references.length - 5} more</li>
            )}
          </ul>
        </div>
      )}

      {/* NVD link */}
      {v.cve && (
        <button
          onClick={() => void OpenInBrowser(`https://nvd.nist.gov/vuln/detail/${v.cve}`)}
          className="mt-3 flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300"
        >
          <ExternalLinkIcon className="h-3 w-3" />
          View on NVD
        </button>
      )}
    </div>
  );
}

// ── OpenTerminalButton ────────────────────────────────────────────────────────

// OpenTerminalButton opens a terminal at dir and copies the fix command to the
// clipboard, so the user only has to paste and run — no manual cd or retyping.
function OpenTerminalButton({ dir, command }: { dir: string; command: string }) {
  const [status, setStatus] = useState<'idle' | 'ok' | 'error'>('idle');
  const [errMsg, setErrMsg] = useState('');

  const handleOpen = async () => {
    setStatus('idle');
    setErrMsg('');
    // Clipboard copy is the universal fallback: the command is pre-filled at the
    // prompt on macOS/zsh, and pasteable everywhere else.
    await navigator.clipboard.writeText(command).catch(() => undefined);
    try {
      await OpenTerminal(dir, command);
      setStatus('ok');
      setTimeout(() => setStatus('idle'), 4000);
    } catch (e) {
      setStatus('error');
      setErrMsg(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="mt-1.5 flex flex-col gap-1">
      <button
        onClick={() => void handleOpen()}
        className="flex items-center justify-center gap-1.5 rounded-md bg-gray-700 px-3 py-1.5 text-xs font-medium text-gray-200 transition-colors hover:bg-gray-600 focus:outline-none focus:ring-1 focus:ring-gray-500"
      >
        <TerminalIcon className="h-3.5 w-3.5" />
        {dir ? 'Open terminal here' : 'Open terminal'}
      </button>
      {status === 'ok' && (
        <p className="text-xs text-green-400">Terminal opened — command ready, press Enter to run.</p>
      )}
      {status === 'error' && (
        <p className="text-xs text-red-400">Couldn’t open a terminal: {errMsg}</p>
      )}
    </div>
  );
}

// ── CopyableCommand ───────────────────────────────────────────────────────────

function CopyableCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(command).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => undefined);
  };

  return (
    <div className="flex items-center gap-2 rounded-md bg-gray-900 px-3 py-2">
      <code className="selectable min-w-0 flex-1 truncate font-mono text-xs text-green-400" title={command}>
        {command}
      </code>
      <button
        onClick={handleCopy}
        title="Copy to clipboard"
        className="flex-shrink-0 rounded p-1 text-gray-500 transition-colors hover:bg-gray-700 hover:text-gray-200"
      >
        {copied ? (
          <CheckIcon className="h-3.5 w-3.5 text-green-400" />
        ) : (
          <CopyIcon className="h-3.5 w-3.5" />
        )}
      </button>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

// ── Icons ─────────────────────────────────────────────────────────────────────

function CloseIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function TerminalIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
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

function CopyIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 01-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 011.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 00-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.375H9.375a1.125 1.125 0 01-1.125-1.125v-9.25m12 6.625v-1.875a3.375 3.375 0 00-3.375-3.375h-1.5a1.125 1.125 0 01-1.125-1.125v-1.5a3.375 3.375 0 00-3.375-3.375H9.75" />
    </svg>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={2.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
    </svg>
  );
}
