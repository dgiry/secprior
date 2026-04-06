// tests/morning-brief.test.js
//
// Unit tests for MorningBrief: generate(), _isWLMatch(), _priorityAction().
//
// Coverage goals:
//   • _isWLMatch  — all three signal paths (V1 / V2 / composite)
//   • _priorityAction — priority-order heuristic (P1 → P8)
//   • generate()  — structural output, scope filtering, block presence
//
// Run: npm test
// Run with coverage: npm run test:coverage

'use strict';

// morning-brief.js exports itself via `module.exports = MorningBrief` at the
// bottom of the file (Node-only branch, no-op in browser).
const MB = require('../js/morning-brief.js');

// ── Shared fixture factory ─────────────────────────────────────────────────────

const NOW = new Date();

/**
 * Builds a minimal Article object.  All enrichment fields default to "absent /
 * no-signal" so each test only has to declare the properties it cares about.
 */
function art(overrides = {}) {
  return {
    title:               'Test: critical RCE in Example Product',
    description:         'A researcher disclosed a critical RCE vulnerability.',
    pubDate:             NOW,
    source:              'SecurityWeek',
    sourceName:          'SecurityWeek',
    link:                'https://example.com/a',
    priorityScore:       40,
    score:               40,
    priorityLevel:       'monitor',
    isKEV:               false,
    epssScore:           0,
    iocCount:            0,
    cves:                [],
    watchlistMatches:    [],
    watchlistMatchItems: [],
    prioritySignals:     {},
    attackTags:          [],
    isTrending:          false,
    trendingCount:       1,
    ...overrides,
  };
}

// Shared posture / actionability stubs for _priorityAction unit tests
const NO_POSTURE = { critCount: 0, invCount: 0, kevCount: 0 };
const NO_ACT     = { kev: 0, ioc: 0, cve: 0, zeroDay: 0 };

// ── _isWLMatch ─────────────────────────────────────────────────────────────────

describe('_isWLMatch', () => {
  test('V1 — matches when watchlistMatches has entries', () => {
    expect(MB._isWLMatch(art({ watchlistMatches: ['Microsoft'] }))).toBe(true);
  });

  test('V2 — matches when watchlistMatchItems has entries (watchlistMatches empty)', () => {
    expect(MB._isWLMatch(art({
      watchlistMatches:    [],
      watchlistMatchItems: [{ label: 'Cisco', value: 'cisco' }],
    }))).toBe(true);
  });

  test('composite — matches when prioritySignals.watchlist is true, arrays empty', () => {
    expect(MB._isWLMatch(art({
      watchlistMatches:    [],
      watchlistMatchItems: [],
      prioritySignals:     { watchlist: true },
    }))).toBe(true);
  });

  test('no match when all watchlist signals absent or empty', () => {
    expect(MB._isWLMatch(art())).toBe(false);
    expect(MB._isWLMatch(art({
      watchlistMatches:    [],
      watchlistMatchItems: [],
      prioritySignals:     { watchlist: false },
    }))).toBe(false);
  });
});

// ── _priorityAction ────────────────────────────────────────────────────────────

describe('_priorityAction', () => {
  test('P1 — KEV + IOC: recommends immediate patch with exploitation language', () => {
    const arts = [art({ isKEV: true, iocCount: 2, cves: ['CVE-2024-0001'] })];
    const result = MB._priorityAction(arts, NO_POSTURE, { kev: 1, ioc: 1, cve: 1, zeroDay: 0 }, []);
    expect(result).toMatch(/patch.*kev.*immediately/i);
    expect(result).toMatch(/active exploitation/i);
  });

  test('P2 — KEV without IOC: cites CVE in patch recommendation', () => {
    const arts = [art({ isKEV: true, cves: ['CVE-2025-9999'] })];
    const result = MB._priorityAction(arts, NO_POSTURE, { kev: 1, ioc: 0, cve: 1, zeroDay: 0 }, []);
    expect(result).toMatch(/patch.*actively exploited/i);
    expect(result).toContain('CVE-2025-9999');
  });

  test('P2 — multiple KEV items: pluralises correctly', () => {
    const arts = [art({ isKEV: true }), art({ isKEV: true })];
    const result = MB._priorityAction(arts, NO_POSTURE, { kev: 2, ioc: 0, cve: 0, zeroDay: 0 }, []);
    expect(result).toMatch(/patch 2.*items/i);
  });

  test('P3 — critical-priority articles without KEV', () => {
    const result = MB._priorityAction([], { ...NO_POSTURE, critCount: 3 }, NO_ACT, []);
    expect(result).toMatch(/investigate 3 critical/i);
  });

  test('P4 — 3+ IOC-bearing articles triggers SIEM hunt recommendation', () => {
    const result = MB._priorityAction([], NO_POSTURE, { ...NO_ACT, ioc: 4 }, []);
    expect(result).toMatch(/hunt in siem/i);
  });

  test('P5 — zero-day without higher signal: compensating controls language', () => {
    const result = MB._priorityAction([], NO_POSTURE, { ...NO_ACT, zeroDay: 1 }, []);
    expect(result).toMatch(/monitor.*zero-day/i);
    expect(result).toMatch(/compensating controls/i);
  });

  test('P6 — watchlist hits: names top matched terms', () => {
    const result = MB._priorityAction([], NO_POSTURE, NO_ACT, [['Fortinet', 5], ['Cisco', 2]]);
    expect(result).toMatch(/review.*watchlist/i);
    expect(result).toContain('Fortinet');
  });

  test('P7 — CVE-linked articles, no higher signal: advisory language', () => {
    const result = MB._priorityAction([], NO_POSTURE, { ...NO_ACT, cve: 3 }, []);
    expect(result).toMatch(/apply vendor advisories/i);
  });

  test('P8 — nothing notable: recommends standard monitoring cadence', () => {
    const result = MB._priorityAction([], NO_POSTURE, NO_ACT, []);
    expect(result).toMatch(/standard monitoring cadence/i);
  });
});

// ── generate() — structural and functional tests ──────────────────────────────

describe('generate()', () => {
  test('output contains all mandatory header sections', () => {
    const out = MB.generate([], 7);
    expect(out).toContain('ThreatLens — Morning Brief');
    expect(out).toContain('THREAT POSTURE:');
    expect(out).toContain('⚡  Priority action:');
    expect(out).toContain('ACTIONABILITY');
    expect(out).toContain('#threatintel #security #standup');
  });

  test('scope filter: articles older than window are excluded from count', () => {
    const old    = art({ pubDate: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000) }); // 10 days ago
    const recent = art({ isKEV: true });
    const out = MB.generate([old, recent], 7);  // 7-day window
    expect(out).toContain('1 article');  // only the recent one counts
    expect(out).toContain('KEV ACTIVE');
  });

  test('KEV block appears and shows CVE + EPSS when isKEV articles present', () => {
    const arts = [art({ isKEV: true, cves: ['CVE-2025-0001'], epssScore: 0.88 })];
    const out = MB.generate(arts, 0);  // scope 0 = all
    expect(out).toContain('KEV ACTIVE');
    expect(out).toContain('CVE-2025-0001');
    expect(out).toContain('EPSS 88%');
  });

  test('KEV block absent when no KEV articles in scope', () => {
    const out = MB.generate([art()], 0);
    expect(out).not.toContain('KEV ACTIVE');
  });

  test('watchlist block appears with matched term when article has watchlistMatches', () => {
    const arts = [art({ watchlistMatches: ['Palo Alto'] })];
    const out = MB.generate(arts, 0);
    expect(out).toContain('WATCHLIST HITS');
    expect(out).toContain('Palo Alto');
  });

  test('watchlist block absent when no watchlist signals present', () => {
    const out = MB.generate([art()], 0);
    expect(out).not.toContain('WATCHLIST HITS');
  });

  test('posture is NOMINAL and priority action is "standard monitoring" for empty scope', () => {
    const out = MB.generate([], 7);
    expect(out).toContain('NOMINAL');
    expect(out).toContain('standard monitoring cadence');
  });

  test('posture escalates to CRITICAL when critical_now articles present', () => {
    const arts = [art({ priorityLevel: 'critical_now', priorityScore: 99 })];
    const out = MB.generate(arts, 0);
    expect(out).toContain('CRITICAL');
  });
});
