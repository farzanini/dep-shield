/**
 * cve.ts — Query OSV.dev and GitHub Advisory Database for known vulnerabilities.
 *
 * Two sources are queried and their results merged:
 *
 *   1. OSV.dev  — batch REST API, up to 1 000 packages per request.
 *      No authentication required.
 *
 *   2. GitHub Advisory Database — GraphQL API.
 *      Requires GITHUB_TOKEN environment variable.
 *      Gracefully skipped when the token is absent.
 *
 * Merge strategy
 * ──────────────
 * Vulnerabilities are deduplicated by CVE ID.  When the same CVE appears in
 * both sources the entry with the higher CVSS score is kept so the risk
 * picture is never understated.  Non-CVE advisories (GHSA-only entries) are
 * kept from both sources without deduplication.
 *
 * Retry / back-off
 * ────────────────
 * All HTTP requests are wrapped in fetchWithRetry(), which retries up to 3
 * times on HTTP 429 (rate-limited) or 5xx responses using truncated
 * exponential back-off with full jitter:
 *
 *   delay = rand(0, min(cap, base × 2^attempt))   cap = 30 s, base = 1 s
 *
 * Public surface
 * ──────────────
 *   queryVulnerabilities(packages, options?) → Promise<Map<"name@version", Vuln[]>>
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

/** One vulnerability advisory, normalised across both data sources. */
export interface Vuln {
  /** Primary identifier — GHSA-… or CVE-…, whichever is more specific. */
  id: string;
  /** CVE identifier, e.g. "CVE-2021-44228". Null when no CVE is assigned. */
  cveId: string | null;
  severity: Severity;
  /** Numeric CVSS v3 base score (0–10). 0 means unscored. */
  cvss: number;
  title: string;
  description: string;
  /** First version that fixes this vuln, or null when no fix exists yet. */
  fixedIn: string | null;
  /** Canonical URL for this advisory. */
  url: string;
}

/** A package to check. ecosystem follows OSV / models.Ecosystem strings. */
export interface Package {
  name: string;
  version: string;
  /**
   * Ecosystem string. OSV uses: "npm", "Go", "PyPI", "crates.io", etc.
   * GitHub GraphQL uses: "NPM", "GO", "PIP", "RUST", etc.
   */
  ecosystem: string;
}

export interface QueryOptions {
  /**
   * GitHub personal-access token with `read:packages` scope.
   * Falls back to process.env.GITHUB_TOKEN when omitted.
   * Pass an empty string "" to explicitly disable GitHub lookups.
   */
  githubToken?: string;
  /**
   * Maximum packages per OSV batch request. Default 1000 (API maximum).
   * Lower this in tests to exercise chunking with fewer fixtures.
   */
  osvBatchSize?: number;
  /**
   * Maximum packages per GitHub GraphQL request (alias-batching).
   * Default 50. GitHub throttles large queries aggressively.
   */
  githubBatchSize?: number;
  /** Override the OSV batch endpoint (useful for testing). */
  osvEndpoint?: string;
  /** Override the GitHub GraphQL endpoint (useful for testing). */
  githubEndpoint?: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const OSV_ENDPOINT = 'https://api.osv.dev/v1/querybatch';
const GITHUB_ENDPOINT = 'https://api.github.com/graphql';
const OSV_BATCH_SIZE = 1_000;
const GITHUB_BATCH_SIZE = 50;
const MAX_RETRIES = 3;
const RETRY_BASE_MS = 1_000;
const RETRY_CAP_MS = 30_000;

// ── Ecosystem mapping ─────────────────────────────────────────────────────────

/**
 * OSV ecosystem strings → GitHub GraphQL SecurityAdvisoryEcosystem enum value.
 * Returns null for ecosystems the GitHub API does not support.
 */
const OSV_TO_GH_ECOSYSTEM: Readonly<Record<string, string>> = {
  npm: 'NPM',
  'Go': 'GO',
  PyPI: 'PIP',
  'crates.io': 'RUST',
  Maven: 'MAVEN',
  NuGet: 'NUGET',
  RubyGems: 'RUBYGEMS',
  Packagist: 'COMPOSER',
  Hex: 'ERLANG',
  Pub: 'PUB',
};

function toGithubEcosystem(osvEcosystem: string): string | null {
  return OSV_TO_GH_ECOSYSTEM[osvEcosystem] ?? null;
}

// ── CVSS v3 base score calculator ─────────────────────────────────────────────

/**
 * Compute the CVSS v3/v3.1 base score from a vector string.
 *
 * Accepts strings like:
 *   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 *   "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 *
 * Returns 0 when the string is absent or unparseable.
 *
 * Formula: NIST CVSS v3.1 specification §7.1
 */
export function cvssScore(vector: string | null | undefined): number {
  if (!vector) return 0;

  // Strip optional "CVSS:3.x/" prefix.
  const raw = vector.replace(/^CVSS:\d+\.\d+\//, '');
  const parts = raw.split('/');

  const metrics: Record<string, string> = {};
  for (const part of parts) {
    const colon = part.indexOf(':');
    if (colon === -1) continue;
    metrics[part.slice(0, colon)] = part.slice(colon + 1);
  }

  // Attack Vector
  const AV_MAP: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  // Attack Complexity
  const AC_MAP: Record<string, number> = { L: 0.77, H: 0.44 };
  // User Interaction
  const UI_MAP: Record<string, number> = { N: 0.85, R: 0.62 };
  // Confidentiality / Integrity / Availability Impact
  const CIA_MAP: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

  const scope = metrics['S'] ?? '';
  const scopeChanged = scope === 'C';

  // Privileges Required varies by scope (CVSS 3.1 Table 15).
  const PR_MAP_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
  const PR_MAP_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.50 };
  const PR_MAP = scopeChanged ? PR_MAP_C : PR_MAP_U;

  const av = AV_MAP[metrics['AV'] ?? ''];
  const ac = AC_MAP[metrics['AC'] ?? ''];
  const pr = PR_MAP[metrics['PR'] ?? ''];
  const ui = UI_MAP[metrics['UI'] ?? ''];
  const c  = CIA_MAP[metrics['C'] ?? ''];
  const i  = CIA_MAP[metrics['I'] ?? ''];
  const a  = CIA_MAP[metrics['A'] ?? ''];

  if (
    av === undefined || ac === undefined || pr === undefined ||
    ui === undefined || c  === undefined || i  === undefined || a === undefined
  ) {
    return 0;
  }

  const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);
  const isc = scopeChanged
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;

  if (isc <= 0) return 0;

  const exploitability = 8.22 * av * ac * pr * ui;
  const rawScore = scopeChanged
    ? Math.min(1.08 * (isc + exploitability), 10)
    : Math.min(isc + exploitability, 10);

  // Roundup: round to one decimal place, always up.
  return Math.ceil(rawScore * 10) / 10;
}

/**
 * Map a severity string (case-insensitive) to a numeric CVSS midpoint.
 * Used as a fallback when no vector is available.
 */
function severityToScore(s: string): number {
  switch (s.toLowerCase()) {
    case 'critical': return 9.5;
    case 'high':     return 7.5;
    case 'medium':   return 5.0;
    case 'moderate': return 5.0; // GitHub uses "MODERATE"
    case 'low':      return 2.0;
    default:         return 0;
  }
}

/** Map a numeric CVSS score to a Severity label. */
function scoreToSeverity(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0)    return 'low';
  return 'unknown';
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

/**
 * Fetch with truncated exponential back-off + full jitter.
 *
 * Retries on:
 *   - HTTP 429 (Too Many Requests)
 *   - HTTP 5xx (Server Error)
 *   - Network errors (fetch throws)
 *
 * Raises on:
 *   - HTTP 4xx other than 429 (client bug, not retriable)
 *   - Exhausted retries
 */
export async function fetchWithRetry(
  url: string,
  init: RequestInit,
  maxRetries = MAX_RETRIES,
  /** Override the base back-off delay (ms). Defaults to RETRY_BASE_MS (1 s). */
  baseDelayMs = RETRY_BASE_MS,
): Promise<Response> {
  let lastError: unknown;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    if (attempt > 0) {
      // full-jitter exponential back-off
      const cap = RETRY_CAP_MS;
      const base = baseDelayMs;
      const ceiling = Math.min(cap, base * Math.pow(2, attempt));
      const delay = Math.random() * ceiling;
      await sleep(delay);
    }

    try {
      const response = await fetch(url, init);

      if (response.status === 429 || response.status >= 500) {
        // Retriable — read Retry-After if present.
        const retryAfter = response.headers.get('Retry-After');
        if (retryAfter && attempt < maxRetries - 1) {
          const waitMs = parseRetryAfter(retryAfter);
          if (waitMs > 0) await sleep(waitMs);
        }
        lastError = new Error(`HTTP ${response.status} from ${url}`);
        continue;
      }

      return response;
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError ?? new Error(`fetchWithRetry: all ${maxRetries} attempts failed`);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function parseRetryAfter(header: string): number {
  const seconds = Number(header);
  if (!Number.isNaN(seconds)) return seconds * 1_000;
  const date = Date.parse(header);
  if (!Number.isNaN(date)) return Math.max(0, date - Date.now());
  return 0;
}

// ── OSV.dev source ────────────────────────────────────────────────────────────

// OSV JSON schema types (minimal — only fields we actually use)

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version: string;
}

interface OsvBatchRequest {
  queries: OsvQuery[];
}

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVuln[] }>;
}

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: OsvAffected[];
  references?: Array<{ type: string; url: string }>;
  database_specific?: {
    severity?: string;
    cvss?: number;
    [key: string]: unknown;
  };
}

interface OsvAffected {
  package?: { name: string; ecosystem: string };
  ranges?: OsvRange[];
  versions?: string[];
}

interface OsvRange {
  type: string;
  events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
}

/** Extract the best numeric CVSS score from an OSV vuln record. */
function osvCvssScore(vuln: OsvVuln): number {
  // 1. Explicit numeric score in database_specific.
  const dbCvss = vuln.database_specific?.cvss;
  if (typeof dbCvss === 'number' && dbCvss > 0) return dbCvss;

  // 2. CVSS vector in severity array — compute score from vector.
  const vectorEntry = vuln.severity?.find(s => s.type === 'CVSS_V3' || s.type === 'CVSS_V2');
  if (vectorEntry) {
    const computed = cvssScore(vectorEntry.score);
    if (computed > 0) return computed;
  }

  // 3. Severity string in database_specific.
  const dbSev = vuln.database_specific?.severity;
  if (typeof dbSev === 'string') return severityToScore(dbSev);

  return 0;
}

/** Extract the first version that fixes the vuln, for a given package name. */
function osvFixedIn(vuln: OsvVuln, pkgName: string): string | null {
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name !== pkgName) continue;
    for (const range of affected.ranges ?? []) {
      if (range.type !== 'ECOSYSTEM' && range.type !== 'SEMVER') continue;
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

/** Extract a CVE ID from the aliases list. Returns the first CVE found. */
function extractCveId(aliases?: string[]): string | null {
  return aliases?.find(a => a.startsWith('CVE-')) ?? null;
}

/** Convert one OsvVuln record to our normalised Vuln type. */
function osvVulnToVuln(raw: OsvVuln, pkgName: string): Vuln {
  const cveId = extractCveId(raw.aliases);
  const score = osvCvssScore(raw);

  const refUrl =
    raw.references?.find(r => r.type === 'ADVISORY' || r.type === 'WEB')?.url
    ?? `https://osv.dev/vulnerability/${raw.id}`;

  return {
    id:          cveId ?? raw.id,
    cveId,
    severity:    scoreToSeverity(score),
    cvss:        score,
    title:       raw.summary ?? raw.id,
    description: raw.details ?? raw.summary ?? '',
    fixedIn:     osvFixedIn(raw, pkgName),
    url:         refUrl,
  };
}

/**
 * Query OSV.dev for all packages, batching into groups of batchSize.
 * Returns a flat map: `"name@version"` → `Vuln[]`.
 */
async function queryOSV(
  packages: Package[],
  batchSize: number,
  endpoint: string,
): Promise<Map<string, Vuln[]>> {
  const results = new Map<string, Vuln[]>();

  // Process packages in chunks of batchSize.
  for (let start = 0; start < packages.length; start += batchSize) {
    const chunk = packages.slice(start, start + batchSize);

    const body: OsvBatchRequest = {
      queries: chunk.map(pkg => ({
        package: { name: pkg.name, ecosystem: pkg.ecosystem },
        version: pkg.version,
      })),
    };

    const response = await fetchWithRetry(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(`OSV batch query failed: HTTP ${response.status}`);
    }

    const data = (await response.json()) as OsvBatchResponse;

    for (let i = 0; i < chunk.length; i++) {
      const pkg = chunk[i];
      if (!pkg) continue;

      const key = `${pkg.name}@${pkg.version}`;
      const rawVulns = data.results[i]?.vulns ?? [];

      if (rawVulns.length > 0) {
        results.set(key, rawVulns.map(v => osvVulnToVuln(v, pkg.name)));
      }
    }
  }

  return results;
}

// ── GitHub Advisory Database source ──────────────────────────────────────────

// GitHub GraphQL response types.

interface GhResponse {
  data: Record<string, GhVulnerabilityConnection | null>;
  errors?: Array<{ message: string }>;
}

interface GhVulnerabilityConnection {
  nodes: GhVulnerability[];
}

interface GhVulnerability {
  advisory: GhAdvisory;
  vulnerableVersionRange: string | null;
  firstPatchedVersion: { identifier: string } | null;
  package: { name: string };
}

interface GhAdvisory {
  ghsaId: string;
  summary: string;
  description: string;
  severity: string; // "CRITICAL" | "HIGH" | "MODERATE" | "LOW"
  cvss: { score: number } | null;
  identifiers: Array<{ type: string; value: string }>;
  references: Array<{ url: string }>;
}

const GH_VULN_FIELDS = `
  advisory {
    ghsaId
    summary
    description
    severity
    cvss { score }
    identifiers { type value }
    references { url }
  }
  vulnerableVersionRange
  firstPatchedVersion { identifier }
  package { name }
`;

/**
 * Build a batched GraphQL query using field aliases.
 * Each package becomes one aliased field: pkg0, pkg1, ...
 *
 * Example:
 *   query {
 *     pkg0: securityVulnerabilities(ecosystem: NPM, package: "express", first: 5) { nodes { ... } }
 *     pkg1: securityVulnerabilities(ecosystem: NPM, package: "lodash", first: 5) { nodes { ... } }
 *   }
 */
function buildGithubQuery(
  packages: Array<{ pkg: Package; ghEcosystem: string; alias: string }>,
): string {
  const fields = packages
    .map(
      ({ alias, pkg, ghEcosystem }) =>
        `  ${alias}: securityVulnerabilities(` +
        `ecosystem: ${ghEcosystem}, ` +
        `package: ${JSON.stringify(pkg.name)}, ` +
        `first: 5` +
        `) { nodes { ${GH_VULN_FIELDS} } }`,
    )
    .join('\n');

  return `query {\n${fields}\n}`;
}

/** Convert one GitHub vulnerability node to our normalised Vuln type. */
function ghVulnToVuln(node: GhVulnerability): Vuln {
  const adv = node.advisory;
  const cveId = adv.identifiers.find(id => id.type === 'CVE')?.value ?? null;
  const score = adv.cvss?.score ?? severityToScore(adv.severity);

  return {
    id:          cveId ?? adv.ghsaId,
    cveId,
    severity:    scoreToSeverity(score),
    cvss:        score,
    title:       adv.summary,
    description: adv.description,
    fixedIn:     node.firstPatchedVersion?.identifier ?? null,
    url:         `https://github.com/advisories/${adv.ghsaId}`,
  };
}

/**
 * Query GitHub Advisory Database, batching packages via GraphQL aliases.
 * Packages whose ecosystem is not supported by GitHub are silently skipped.
 * Returns a flat map: `"name@version"` → `Vuln[]`.
 */
async function queryGitHub(
  packages: Package[],
  token: string,
  batchSize: number,
  endpoint: string,
): Promise<Map<string, Vuln[]>> {
  const results = new Map<string, Vuln[]>();

  // Filter to packages with a supported GitHub ecosystem.
  const supported = packages.flatMap(pkg => {
    const ghEco = toGithubEcosystem(pkg.ecosystem);
    return ghEco ? [{ pkg, ghEco }] : [];
  });

  for (let start = 0; start < supported.length; start += batchSize) {
    const chunk = supported.slice(start, start + batchSize);

    // Assign stable aliases (pkg0, pkg1, …) for this batch.
    const aliased = chunk.map((item, idx) => ({
      pkg:         item.pkg,
      ghEcosystem: item.ghEco,
      alias:       `pkg${idx}`,
    }));

    const query = buildGithubQuery(aliased);

    const response = await fetchWithRetry(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization:  `Bearer ${token}`,
      },
      body: JSON.stringify({ query }),
    });

    if (!response.ok) {
      throw new Error(`GitHub Advisory query failed: HTTP ${response.status}`);
    }

    const data = (await response.json()) as GhResponse;

    if (data.errors?.length) {
      // GraphQL errors are non-fatal — log and continue.
      console.warn(
        'GitHub Advisory GraphQL errors:',
        data.errors.map(e => e.message).join('; '),
      );
    }

    for (const { alias, pkg } of aliased) {
      const key = `${pkg.name}@${pkg.version}`;
      const connection = data.data[alias];
      if (!connection) continue;

      const vulns = connection.nodes.map(node => ghVulnToVuln(node));
      if (vulns.length > 0) {
        const existing = results.get(key) ?? [];
        results.set(key, [...existing, ...vulns]);
      }
    }
  }

  return results;
}

// ── Merge logic ───────────────────────────────────────────────────────────────

/**
 * Merge two Vuln arrays, deduplicating by CVE ID.
 *
 * Rules:
 * - If a vuln has no CVE ID it is always kept (no deduplication key).
 * - When the same CVE ID appears in both arrays, keep the entry with the
 *   higher CVSS score so we never understate severity.
 */
export function mergeVulns(a: Vuln[], b: Vuln[]): Vuln[] {
  // Map CVE ID → best entry so far.
  const byCve = new Map<string, Vuln>();
  // Non-CVE entries kept verbatim.
  const noCve: Vuln[] = [];

  for (const vuln of [...a, ...b]) {
    if (!vuln.cveId) {
      noCve.push(vuln);
      continue;
    }
    const existing = byCve.get(vuln.cveId);
    if (!existing || vuln.cvss > existing.cvss) {
      byCve.set(vuln.cveId, vuln);
    }
  }

  return [...byCve.values(), ...noCve];
}

/**
 * Merge two `name@version` → `Vuln[]` maps into one.
 * Keys that appear in both maps have their Vuln arrays merged.
 */
function mergeMaps(
  a: Map<string, Vuln[]>,
  b: Map<string, Vuln[]>,
): Map<string, Vuln[]> {
  const merged = new Map<string, Vuln[]>(a);

  for (const [key, vulns] of b) {
    const existing = merged.get(key);
    merged.set(key, existing ? mergeVulns(existing, vulns) : vulns);
  }

  return merged;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Query OSV.dev and (optionally) GitHub Advisory Database for all packages,
 * then merge and return the results.
 *
 * @param packages  List of packages to check.
 * @param options   Tuning options; GITHUB_TOKEN is read from env when absent.
 * @returns         Map from "name@version" to the list of known vulnerabilities.
 *                  Packages with no vulnerabilities are absent from the map.
 *
 * @example
 * ```ts
 * const results = await queryVulnerabilities([
 *   { name: 'express', version: '4.18.2', ecosystem: 'npm' },
 *   { name: 'lodash',  version: '4.17.21', ecosystem: 'npm' },
 * ]);
 *
 * for (const [key, vulns] of results) {
 *   console.log(key, vulns.map(v => v.id));
 * }
 * ```
 */
export async function queryVulnerabilities(
  packages: Package[],
  options: QueryOptions = {},
): Promise<Map<string, Vuln[]>> {
  if (packages.length === 0) return new Map();

  const {
    osvBatchSize    = OSV_BATCH_SIZE,
    githubBatchSize = GITHUB_BATCH_SIZE,
    osvEndpoint     = OSV_ENDPOINT,
    githubEndpoint  = GITHUB_ENDPOINT,
  } = options;

  // Resolve the GitHub token: explicit option > env var > absent.
  const githubToken =
    'githubToken' in options
      ? options.githubToken   // may be "" to disable
      : (process.env['GITHUB_TOKEN'] ?? '');

  // Run both sources concurrently. GitHub is conditional on token presence.
  const osvPromise = queryOSV(packages, osvBatchSize, osvEndpoint);

  const ghPromise: Promise<Map<string, Vuln[]>> = githubToken
    ? queryGitHub(packages, githubToken, githubBatchSize, githubEndpoint)
    : Promise.resolve(new Map());

  const [osvResults, ghResults] = await Promise.all([osvPromise, ghPromise]);

  return mergeMaps(osvResults, ghResults);
}
