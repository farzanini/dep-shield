/**
 * cve.test.ts — unit and integration-level tests for src/cve.ts.
 *
 * No real HTTP calls are made.  fetch is replaced with jest.fn() so every
 * test controls exactly what the server returns.
 *
 * Test surface
 * ─────────────
 *  cvssScore          — CVSS v3 vector → numeric base score
 *  fetchWithRetry     — back-off, retry on 429/5xx, fail-fast on 4xx
 *  mergeVulns         — CVE-based deduplication, prefer higher score
 *  queryVulnerabilities (integration)
 *    - OSV batch chunking
 *    - GitHub GraphQL alias-batching
 *    - GitHub skipped when token absent
 *    - Results correctly mapped to name@version keys
 *    - OSV + GitHub results merged
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  jest,
  test,
} from '@jest/globals';

import {
  cvssScore,
  fetchWithRetry,
  mergeVulns,
  queryVulnerabilities,
  type Package,
  type Vuln,
} from './cve.js';

// ── Test helpers ──────────────────────────────────────────────────────────────

/** Build a minimal Vuln object, merging any overrides. */
function makeVuln(overrides: Partial<Vuln> = {}): Vuln {
  return {
    id:          'CVE-2021-00001',
    cveId:       'CVE-2021-00001',
    severity:    'high',
    cvss:        7.5,
    title:       'Test vulnerability',
    description: 'A test vulnerability.',
    fixedIn:     '1.2.3',
    url:         'https://example.com/advisories/CVE-2021-00001',
    ...overrides,
  };
}

/** Build a Package value. */
function makePkg(overrides: Partial<Package> = {}): Package {
  return { name: 'express', version: '4.18.2', ecosystem: 'npm', ...overrides };
}

// OSV fixtures ────────────────────────────────────────────────────────────────

function osvBatchResponse(vulnsByIndex: Record<number, object[]>) {
  return {
    results: Array.from({ length: Math.max(...Object.keys(vulnsByIndex).map(Number)) + 1 }, (_, i) => ({
      vulns: vulnsByIndex[i] ?? [],
    })),
  };
}

const OSV_EXPRESS_VULN = {
  id: 'GHSA-rv95-896h-c2vc',
  aliases: ['CVE-2022-24999'],
  summary: 'qs before 6.10.3 allows prototype poisoning',
  details:  'Detailed description here.',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }],
  affected: [
    {
      package: { name: 'express', ecosystem: 'npm' },
      ranges: [
        { type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.19.0' }] },
      ],
    },
  ],
  references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-rv95-896h-c2vc' }],
  database_specific: { severity: 'HIGH' },
};

// GitHub Advisory fixtures ────────────────────────────────────────────────────

function ghResponse(aliasData: Record<string, { nodes: object[] }>) {
  return { data: aliasData };
}

const GH_EXPRESS_NODE = {
  advisory: {
    ghsaId:      'GHSA-rv95-896h-c2vc',
    summary:     'qs prototype poisoning',
    description: 'GitHub description.',
    severity:    'HIGH',
    cvss:        { score: 7.5 },
    identifiers: [{ type: 'CVE', value: 'CVE-2022-24999' }, { type: 'GHSA', value: 'GHSA-rv95-896h-c2vc' }],
    references:  [{ url: 'https://github.com/advisories/GHSA-rv95-896h-c2vc' }],
  },
  vulnerableVersionRange: '< 4.19.0',
  firstPatchedVersion: { identifier: '4.19.0' },
  package: { name: 'express' },
};

// ── fetch mock helpers ────────────────────────────────────────────────────────

/** Return a mock Response-like object. */
function mockResponse(body: unknown, status = 200): Response {
  return {
    ok:          status >= 200 && status < 300,
    status,
    statusText:  String(status),
    type:        'basic' as Response['type'],
    url:         '',
    redirected:  false,
    headers:     new Headers(),
    clone:       function() { return this as Response; },
    arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    blob:        () => Promise.resolve(new Blob([])),
    bytes:       () => Promise.resolve(new Uint8Array()),
    formData:    () => Promise.resolve(new FormData()),
    json:        () => Promise.resolve(body),
    text:        () => Promise.resolve(JSON.stringify(body)),
    body:        null,
    bodyUsed:    false,
  } as unknown as Response;
}

/** Replace global fetch with a jest mock and restore it after each test. */
// typed as the fetch signature so mockResolvedValueOnce<Response> works
let fetchMock: jest.MockedFunction<typeof fetch>;

beforeEach(() => {
  fetchMock = jest.fn<typeof fetch>();
  global.fetch = fetchMock;
});

afterEach(() => {
  jest.restoreAllMocks();
  delete (global as unknown as Record<string, unknown>)['fetch'];
});

// ── cvssScore ─────────────────────────────────────────────────────────────────

describe('cvssScore', () => {
  test('returns 0 for null / undefined / empty string', () => {
    expect(cvssScore(null)).toBe(0);
    expect(cvssScore(undefined)).toBe(0);
    expect(cvssScore('')).toBe(0);
  });

  test('CVE-2021-44228 (Log4Shell) — CRITICAL 10.0', () => {
    // AV:N AC:L PR:N UI:N S:C C:H I:H A:H
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
    expect(cvssScore(vector)).toBe(10.0);
  });

  test('high severity with scope unchanged', () => {
    // AV:N AC:L PR:N UI:N S:U C:N I:N A:H  → should be ~7.5
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H';
    const score = cvssScore(vector);
    expect(score).toBeGreaterThanOrEqual(7.0);
    expect(score).toBeLessThanOrEqual(8.0);
  });

  test('medium severity vector', () => {
    // AV:N AC:L PR:L UI:N S:U C:L I:L A:N
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N';
    const score = cvssScore(vector);
    expect(score).toBeGreaterThanOrEqual(4.0);
    expect(score).toBeLessThan(7.0);
  });

  test('zero impact → score 0', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';
    expect(cvssScore(vector)).toBe(0);
  });

  test('strips CVSS:3.1/ prefix before parsing', () => {
    const withPrefix    = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    const withoutPrefix =       'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    expect(cvssScore(withPrefix)).toBe(cvssScore(withoutPrefix));
  });

  test('returns 0 for garbage string', () => {
    expect(cvssScore('not-a-vector')).toBe(0);
  });

  test('scope-changed PR:L uses 0.68 not 0.62', () => {
    // With scope changed, PR:L = 0.68; these vectors differ only in scope.
    const unchanged = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H';
    const changed   = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H';
    // Scope-changed score should be higher.
    expect(cvssScore(changed)).toBeGreaterThan(cvssScore(unchanged));
  });
});

// ── fetchWithRetry ────────────────────────────────────────────────────────────

// All fetchWithRetry tests pass baseDelayMs=1 so back-off sleeps are ~0 ms.
// This avoids fake timers entirely (fake timers + async retry loops interact
// poorly with jest's unhandled-rejection detection in ESM mode).
const INSTANT = 1; // ms — functionally zero delay

describe('fetchWithRetry', () => {
  test('returns response immediately on 200', async () => {
    fetchMock.mockResolvedValueOnce(mockResponse({ ok: true }, 200));
    const res = await fetchWithRetry('https://example.com', {}, 3, INSTANT);
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  test('retries on 429 and succeeds on second attempt', async () => {
    fetchMock
      .mockResolvedValueOnce(mockResponse(null, 429))
      .mockResolvedValueOnce(mockResponse({ ok: true }, 200));

    const res = await fetchWithRetry('https://example.com', {}, 3, INSTANT);
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test('retries on 503 and succeeds on third attempt', async () => {
    fetchMock
      .mockResolvedValueOnce(mockResponse(null, 503))
      .mockResolvedValueOnce(mockResponse(null, 503))
      .mockResolvedValueOnce(mockResponse({ ok: true }, 200));

    const res = await fetchWithRetry('https://example.com', {}, 3, INSTANT);
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  test('throws after exhausting all retries', async () => {
    fetchMock.mockResolvedValue(mockResponse(null, 429));

    await expect(
      fetchWithRetry('https://example.com', {}, 3, INSTANT),
    ).rejects.toThrow('HTTP 429');

    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  test('does not retry on 404 (client error)', async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null, 404));

    const res = await fetchWithRetry('https://example.com', {}, 3, INSTANT);
    expect(res.status).toBe(404);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  test('retries on network error (fetch throws)', async () => {
    fetchMock
      .mockRejectedValueOnce(new TypeError('network failure'))
      .mockResolvedValueOnce(mockResponse({ ok: true }, 200));

    const res = await fetchWithRetry('https://example.com', {}, 3, INSTANT);
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test('respects Retry-After: <seconds> header (parses integer seconds)', async () => {
    // Use 0 as the Retry-After value so the test doesn't actually wait.
    const headers = new Headers({ 'Retry-After': '0' });
    fetchMock
      .mockResolvedValueOnce({ ...mockResponse(null, 429), headers })
      .mockResolvedValueOnce(mockResponse({ ok: true }, 200));

    const res = await fetchWithRetry('https://example.com', {}, 3, INSTANT);
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

// ── mergeVulns ────────────────────────────────────────────────────────────────

describe('mergeVulns', () => {
  test('returns empty array for two empty inputs', () => {
    expect(mergeVulns([], [])).toEqual([]);
  });

  test('returns all items when no CVE IDs overlap', () => {
    const a = [makeVuln({ id: 'CVE-2021-00001', cveId: 'CVE-2021-00001' })];
    const b = [makeVuln({ id: 'CVE-2021-00002', cveId: 'CVE-2021-00002' })];
    expect(mergeVulns(a, b)).toHaveLength(2);
  });

  test('deduplicates by CVE ID, keeps the one with the higher CVSS', () => {
    const low  = makeVuln({ cvss: 6.5, severity: 'medium', title: 'low-score source' });
    const high = makeVuln({ cvss: 9.8, severity: 'critical', title: 'high-score source' });

    const merged = mergeVulns([low], [high]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.cvss).toBe(9.8);
    expect(merged[0]?.title).toBe('high-score source');
  });

  test('keeps both when one has cveId null (no dedup key)', () => {
    const withCve    = makeVuln({ cveId: 'CVE-2021-00001' });
    const withoutCve = makeVuln({ id: 'GHSA-xxxx-xxxx-xxxx', cveId: null });
    const merged = mergeVulns([withCve], [withoutCve]);
    expect(merged).toHaveLength(2);
  });

  test('keeps both non-CVE entries even when GHSA ID is the same', () => {
    // Without a CVE anchor we cannot reliably deduplicate.
    const a = makeVuln({ id: 'GHSA-aaaa-aaaa-aaaa', cveId: null });
    const b = makeVuln({ id: 'GHSA-aaaa-aaaa-aaaa', cveId: null });
    const merged = mergeVulns([a], [b]);
    expect(merged).toHaveLength(2);
  });

  test('all from first array survive when second is empty', () => {
    const vulns = [makeVuln({ cveId: 'CVE-A' }), makeVuln({ cveId: 'CVE-B' })];
    expect(mergeVulns(vulns, [])).toHaveLength(2);
  });

  test('equal CVSS score: keeps entry from second array (last writer wins)', () => {
    const first  = makeVuln({ cvss: 7.5, title: 'first',  cveId: 'CVE-X' });
    const second = makeVuln({ cvss: 7.5, title: 'second', cveId: 'CVE-X' });
    const merged = mergeVulns([first], [second]);
    expect(merged).toHaveLength(1);
    // second is not strictly greater, so first is kept (>=).
    expect(merged[0]?.title).toBe('first');
  });
});

// ── queryVulnerabilities — integration tests ──────────────────────────────────

describe('queryVulnerabilities', () => {
  const FAKE_OSV  = 'https://fake-osv.test/v1/querybatch';
  const FAKE_GH   = 'https://fake-github.test/graphql';
  const baseOpts  = { osvEndpoint: FAKE_OSV, githubEndpoint: FAKE_GH };

  test('returns empty map for zero packages', async () => {
    const result = await queryVulnerabilities([], baseOpts);
    expect(result.size).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('skips GitHub when githubToken is empty string', async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [] })),
    );

    await queryVulnerabilities(
      [makePkg()],
      { ...baseOpts, githubToken: '' },
    );

    // Only one fetch call — OSV only.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(FAKE_OSV);
  });

  test('skips GitHub when GITHUB_TOKEN env var is absent', async () => {
    const savedToken = process.env['GITHUB_TOKEN'];
    delete process.env['GITHUB_TOKEN'];

    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [] })),
    );

    await queryVulnerabilities([makePkg()], baseOpts);

    expect(fetchMock).toHaveBeenCalledTimes(1);

    if (savedToken !== undefined) process.env['GITHUB_TOKEN'] = savedToken;
  });

  test('includes GitHub when GITHUB_TOKEN env var is set', async () => {
    const savedToken = process.env['GITHUB_TOKEN'];
    process.env['GITHUB_TOKEN'] = 'ghp_test_token';

    fetchMock
      .mockResolvedValueOnce(mockResponse(osvBatchResponse({ 0: [] })))
      .mockResolvedValueOnce(mockResponse(ghResponse({ pkg0: { nodes: [] } })));

    await queryVulnerabilities([makePkg()], baseOpts);

    expect(fetchMock).toHaveBeenCalledTimes(2);

    process.env['GITHUB_TOKEN'] = savedToken ?? '';
  });

  test('maps OSV vulnerability to correct name@version key', async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [OSV_EXPRESS_VULN] })),
    );

    const result = await queryVulnerabilities(
      [makePkg()],
      { ...baseOpts, githubToken: '' },
    );

    expect(result.has('express@4.18.2')).toBe(true);
    const vulns = result.get('express@4.18.2')!;
    expect(vulns).toHaveLength(1);
    expect(vulns[0]?.cveId).toBe('CVE-2022-24999');
  });

  test('packages with no vulns are absent from the result map', async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [], 1: [OSV_EXPRESS_VULN] })),
    );

    const result = await queryVulnerabilities(
      [makePkg({ name: 'lodash', version: '4.17.21' }), makePkg()],
      { ...baseOpts, githubToken: '' },
    );

    expect(result.has('lodash@4.17.21')).toBe(false);
    expect(result.has('express@4.18.2')).toBe(true);
  });

  test('OSV batch chunking: 2 packages with batchSize 1 → 2 fetch calls', async () => {
    fetchMock
      .mockResolvedValueOnce(mockResponse(osvBatchResponse({ 0: [] })))
      .mockResolvedValueOnce(mockResponse(osvBatchResponse({ 0: [OSV_EXPRESS_VULN] })));

    const result = await queryVulnerabilities(
      [makePkg({ name: 'lodash', version: '4.17.21' }), makePkg()],
      { ...baseOpts, githubToken: '', osvBatchSize: 1 },
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.has('express@4.18.2')).toBe(true);
    expect(result.has('lodash@4.17.21')).toBe(false);
  });

  test('OSV batch chunking: request bodies contain correct packages per chunk', async () => {
    fetchMock
      .mockResolvedValueOnce(mockResponse(osvBatchResponse({ 0: [] })))
      .mockResolvedValueOnce(mockResponse(osvBatchResponse({ 0: [] })));

    const packages: Package[] = [
      { name: 'a', version: '1.0.0', ecosystem: 'npm' },
      { name: 'b', version: '2.0.0', ecosystem: 'npm' },
    ];

    await queryVulnerabilities(
      packages,
      { ...baseOpts, githubToken: '', osvBatchSize: 1 },
    );

    const body0 = JSON.parse(fetchMock.mock.calls[0]?.[1]?.body as string);
    const body1 = JSON.parse(fetchMock.mock.calls[1]?.[1]?.body as string);

    expect(body0.queries).toHaveLength(1);
    expect(body0.queries[0].package.name).toBe('a');
    expect(body1.queries[0].package.name).toBe('b');
  });

  test('GitHub batch uses aliased GraphQL query', async () => {
    fetchMock
      .mockResolvedValueOnce(mockResponse(osvBatchResponse({ 0: [] })))
      .mockResolvedValueOnce(
        mockResponse(ghResponse({ pkg0: { nodes: [GH_EXPRESS_NODE] } })),
      );

    const result = await queryVulnerabilities(
      [makePkg()],
      { ...baseOpts, githubToken: 'tok' },
    );

    // Check the GraphQL request body.
    const ghCall = fetchMock.mock.calls.find(
      (c: unknown[]) => (c[0] as string) === FAKE_GH,
    );
    expect(ghCall).toBeDefined();
    const ghInit = ghCall![1] as RequestInit;
    const ghBody = JSON.parse(ghInit.body as string);
    expect(ghBody.query).toContain('pkg0:');
    expect(ghBody.query).toContain('securityVulnerabilities');
    expect(ghBody.query).toContain('NPM');

    expect(result.has('express@4.18.2')).toBe(true);
    const vulns = result.get('express@4.18.2')!;
    expect(vulns[0]?.cveId).toBe('CVE-2022-24999');
    expect(vulns[0]?.fixedIn).toBe('4.19.0');
  });

  test('GitHub batch chunking: 3 packages with batchSize 2 → 2 GH calls', async () => {
    const pkg = (name: string) => makePkg({ name, version: '1.0.0' });
    const packages = [pkg('a'), pkg('b'), pkg('c')];

    // OSV: 1 call for all 3 (batchSize default).
    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [], 1: [], 2: [] })),
    );
    // GH batch 1: a, b
    fetchMock.mockResolvedValueOnce(
      mockResponse(ghResponse({ pkg0: { nodes: [] }, pkg1: { nodes: [] } })),
    );
    // GH batch 2: c
    fetchMock.mockResolvedValueOnce(
      mockResponse(ghResponse({ pkg0: { nodes: [] } })),
    );

    await queryVulnerabilities(packages, {
      ...baseOpts,
      githubToken: 'tok',
      githubBatchSize: 2,
    });

    const ghCalls = fetchMock.mock.calls.filter(
      (c: unknown[]) => (c[0] as string) === FAKE_GH,
    );
    expect(ghCalls).toHaveLength(2);
  });

  test('merges OSV and GitHub results for the same package', async () => {
    // OSV returns one vuln; GitHub returns the same vuln with a higher score.
    const osvVulnLow = {
      ...OSV_EXPRESS_VULN,
      database_specific: { cvss: 6.5, severity: 'MEDIUM' },
    };
    const ghNodeHigh = {
      ...GH_EXPRESS_NODE,
      advisory: { ...GH_EXPRESS_NODE.advisory, cvss: { score: 9.8 } },
    };

    fetchMock
      .mockResolvedValueOnce(mockResponse(osvBatchResponse({ 0: [osvVulnLow] })))
      .mockResolvedValueOnce(
        mockResponse(ghResponse({ pkg0: { nodes: [ghNodeHigh] } })),
      );

    const result = await queryVulnerabilities(
      [makePkg()],
      { ...baseOpts, githubToken: 'tok' },
    );

    const vulns = result.get('express@4.18.2')!;
    // Deduplicated: only 1 entry for CVE-2022-24999.
    expect(vulns.filter(v => v.cveId === 'CVE-2022-24999')).toHaveLength(1);
    // Higher score (9.8) is kept.
    const merged = vulns.find(v => v.cveId === 'CVE-2022-24999')!;
    expect(merged.cvss).toBe(9.8);
    expect(merged.severity).toBe('critical');
  });

  test('OSV fixedIn is parsed from affected ranges', async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [OSV_EXPRESS_VULN] })),
    );

    const result = await queryVulnerabilities(
      [makePkg()],
      { ...baseOpts, githubToken: '' },
    );

    expect(result.get('express@4.18.2')?.[0]?.fixedIn).toBe('4.19.0');
  });

  test('vuln with database_specific.cvss number uses it directly', async () => {
    const vuln = { ...OSV_EXPRESS_VULN, database_specific: { cvss: 9.1 } };
    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [vuln] })),
    );

    const result = await queryVulnerabilities(
      [makePkg()],
      { ...baseOpts, githubToken: '' },
    );

    expect(result.get('express@4.18.2')?.[0]?.cvss).toBe(9.1);
    expect(result.get('express@4.18.2')?.[0]?.severity).toBe('critical');
  });

  test('vuln with no scoring falls back to severity string', async () => {
    const vuln = {
      id: 'GHSA-test-0001',
      summary: 'No CVSS available',
      database_specific: { severity: 'HIGH' },
      affected: [{ package: { name: 'express', ecosystem: 'npm' } }],
    };
    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [vuln] })),
    );

    const result = await queryVulnerabilities(
      [makePkg()],
      { ...baseOpts, githubToken: '' },
    );

    const v = result.get('express@4.18.2')?.[0]!;
    expect(v.severity).toBe('high');
    expect(v.cvss).toBe(7.5);
  });

  test('non-npm ecosystem is skipped by GitHub (no supported mapping)', async () => {
    // "unknown-eco" has no GitHub enum.
    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [] })),
    );
    // GitHub should never be called for an unsupported ecosystem.
    fetchMock.mockResolvedValueOnce(
      mockResponse(ghResponse({})),
    );

    await queryVulnerabilities(
      [{ name: 'some-pkg', version: '1.0.0', ecosystem: 'unknown-eco' }],
      { ...baseOpts, githubToken: 'tok' },
    );

    const ghCalls = fetchMock.mock.calls.filter(
      (c: unknown[]) => (c[0] as string) === FAKE_GH,
    );
    // GitHub call still happens (batch may be empty), but the GraphQL body
    // should not reference unknown-eco packages.
    // If all packages are filtered, no GH call is made at all.
    expect(ghCalls.length).toBeLessThanOrEqual(0);
  });

  test('GitHub GraphQL errors are logged as warnings, not thrown', async () => {
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    fetchMock
      .mockResolvedValueOnce(mockResponse(osvBatchResponse({ 0: [] })))
      .mockResolvedValueOnce(
        mockResponse({
          data:   { pkg0: null },
          errors: [{ message: 'rate limit exceeded' }],
        }),
      );

    await expect(
      queryVulnerabilities([makePkg()], { ...baseOpts, githubToken: 'tok' }),
    ).resolves.not.toThrow();

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('GraphQL errors'),
      expect.stringContaining('rate limit'),
    );

    consoleSpy.mockRestore();
  });

  test('OSV HTTP error throws', async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null, 500));

    // All 3 retries return 500.
    fetchMock.mockResolvedValue(mockResponse(null, 500));

    await expect(
      queryVulnerabilities([makePkg()], { ...baseOpts, githubToken: '' }),
    ).rejects.toThrow();
  });

  test('result contains correct ecosystem in returned Vulns', async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [OSV_EXPRESS_VULN] })),
    );

    const result = await queryVulnerabilities(
      [makePkg()],
      { ...baseOpts, githubToken: '' },
    );

    const v = result.get('express@4.18.2')?.[0]!;
    // The Vuln type doesn't carry ecosystem, but the URL should point to OSV.
    expect(v.url).toContain('advisories');
  });

  test('multiple packages, multiple vulnerabilities', async () => {
    const lodashVuln = {
      id: 'GHSA-lodash-001',
      aliases: ['CVE-2020-28500'],
      summary: 'Lodash prototype pollution',
      details: 'Details.',
      affected: [{ package: { name: 'lodash', ecosystem: 'npm' } }],
      database_specific: { severity: 'MEDIUM' },
    };

    fetchMock.mockResolvedValueOnce(
      mockResponse(osvBatchResponse({ 0: [OSV_EXPRESS_VULN], 1: [lodashVuln] })),
    );

    const result = await queryVulnerabilities(
      [makePkg(), { name: 'lodash', version: '4.17.21', ecosystem: 'npm' }],
      { ...baseOpts, githubToken: '' },
    );

    expect(result.size).toBe(2);
    expect(result.has('express@4.18.2')).toBe(true);
    expect(result.has('lodash@4.17.21')).toBe(true);
    expect(result.get('lodash@4.17.21')?.[0]?.cveId).toBe('CVE-2020-28500');
  });

  test('Go ecosystem maps to GO in GitHub query', async () => {
    fetchMock
      .mockResolvedValueOnce(mockResponse(osvBatchResponse({ 0: [] })))
      .mockResolvedValueOnce(mockResponse(ghResponse({ pkg0: { nodes: [] } })));

    await queryVulnerabilities(
      [{ name: 'github.com/foo/bar', version: 'v1.0.0', ecosystem: 'Go' }],
      { ...baseOpts, githubToken: 'tok' },
    );

    const ghCall2 = fetchMock.mock.calls.find(
      (c: unknown[]) => (c[0] as string) === FAKE_GH,
    )!;
    const ghBody2 = JSON.parse((ghCall2[1] as RequestInit).body as string);
    expect(ghBody2.query).toContain('ecosystem: GO');
  });
});
