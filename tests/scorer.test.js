// tests/scorer.test.js
//
// Unit tests for scorer.js: scoreComposite(), classifyScore(), scoreBarClass(),
// computePriority(), digestPriorityScore(), getCriticalityMeta(), getPriorityMeta()
//
// Run: npm test

'use strict';

// ── Mock CONFIG (scorer.js reads CONFIG.SCORER_HIGH / CONFIG.SCORER_MEDIUM) ──
global.CONFIG = {
  SCORER_HIGH: [
    '0day', 'zero-day', 'zero day', 'actively exploited', 'in the wild',
    'emergency patch', 'critical vulnerability', 'rce', 'remote code execution',
    'ransomware', 'exploit kit', 'supply chain attack', 'backdoor',
    'nation-state', 'apt', 'cvss 9', 'cvss 10', 'unauthenticated',
    'authentication bypass', 'mass exploitation', 'worm', 'botnet',
    'cisa kev', 'out-of-band', 'actively being exploited',
  ],
  SCORER_MEDIUM: [
    'vulnerability', 'cve-', 'patch', 'security update', 'breach',
    'malware', 'phishing', 'ddos', 'data leak', 'data breach',
    'privilege escalation', 'sql injection', 'xss', 'csrf',
    'trojan', 'spyware', 'keylogger', 'advisory', 'disclosure',
    'security flaw', 'weak authentication', 'misconfiguration',
    'credential', 'password', 'leak', 'exposed', 'unpatched',
  ],
};

const S = require('../js/scorer.js');

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Minimal article — all signals absent, score should be near 0 */
function art(overrides = {}) {
  return {
    title:          'Generic security news article',
    description:    '',
    cvssScore:      0,
    epssScore:      0,
    isKEV:          false,
    sourceCount:    1,
    iocCount:       0,
    cves:           [],
    attackTags:     [],
    watchlistMatches:    [],
    watchlistMatchItems: [],
    ...overrides,
  };
}

// ── scoreComposite ────────────────────────────────────────────────────────────

describe('scoreComposite()', () => {
  test('all-zero article scores near 0', () => {
    const { score } = S.scoreComposite(art());
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThan(10);
  });

  test('weights sum to exactly 1.0', () => {
    // Verify via: max article should approach 100
    const maxArt = art({
      cvssScore:   10,
      epssScore:   1,
      isKEV:       true,
      sourceCount: 6,
      iocCount:    10,
      title:       'rce zero-day actively exploited',
    });
    const { score } = S.scoreComposite(maxArt);
    expect(score).toBe(100);
  });

  test('CVSS 10 contributes 30 points (weight 0.30)', () => {
    const { breakdown } = S.scoreComposite(art({ cvssScore: 10 }));
    expect(breakdown.cvss).toBeCloseTo(30, 1);
  });

  test('EPSS 1.0 contributes 25 points (weight 0.25)', () => {
    const { breakdown } = S.scoreComposite(art({ epssScore: 1 }));
    expect(breakdown.epss).toBeCloseTo(25, 1);
  });

  test('isKEV=true contributes 25 points (weight 0.25)', () => {
    const { breakdown } = S.scoreComposite(art({ isKEV: true }));
    expect(breakdown.kev).toBeCloseTo(25, 1);
  });

  test('6+ sources contributes full 10 points (weight 0.10)', () => {
    const { breakdown } = S.scoreComposite(art({ sourceCount: 6 }));
    expect(breakdown.sources).toBeCloseTo(10, 1);
  });

  test('1 source contributes 0 source points', () => {
    const { breakdown } = S.scoreComposite(art({ sourceCount: 1 }));
    expect(breakdown.sources).toBe(0);
  });

  test('10+ IOCs contributes full 5 points (weight 0.05)', () => {
    const { breakdown } = S.scoreComposite(art({ iocCount: 10 }));
    expect(breakdown.ioc).toBeCloseTo(5, 1);
  });

  test('HIGH keyword in title contributes 5 points', () => {
    const { breakdown } = S.scoreComposite(art({ title: 'Critical RCE vulnerability' }));
    expect(breakdown.keyword).toBeCloseTo(5, 1);
  });

  test('MEDIUM keyword (2 matches) contributes > 0 and < HIGH (5) points', () => {
    // requires ≥2 MEDIUM keyword matches to trigger medium signal
    const { breakdown } = S.scoreComposite(art({ title: 'patch vulnerability advisory disclosure' }));
    expect(breakdown.keyword).toBeGreaterThan(0);
    expect(breakdown.keyword).toBeLessThan(5);
  });

  test('score is clamped between 0 and 100', () => {
    const { score } = S.scoreComposite(art({
      cvssScore: 10, epssScore: 1, isKEV: true,
      sourceCount: 99, iocCount: 99,
    }));
    expect(score).toBeLessThanOrEqual(100);
    expect(score).toBeGreaterThanOrEqual(0);
  });

  test('missing fields default to 0 without throwing', () => {
    expect(() => S.scoreComposite({})).not.toThrow();
  });
});

// ── classifyScore ─────────────────────────────────────────────────────────────

describe('classifyScore()', () => {
  test('score 65 → high', () => expect(S.classifyScore(65)).toBe('high'));
  test('score 64 → medium', () => expect(S.classifyScore(64)).toBe('medium'));
  test('score 30 → medium', () => expect(S.classifyScore(30)).toBe('medium'));
  test('score 29 → low', () => expect(S.classifyScore(29)).toBe('low'));
  test('score 0 → low', () => expect(S.classifyScore(0)).toBe('low'));
  test('score 100 → high', () => expect(S.classifyScore(100)).toBe('high'));
});

// ── scoreBarClass ─────────────────────────────────────────────────────────────

describe('scoreBarClass()', () => {
  test('65 → score-bar-high', () => expect(S.scoreBarClass(65)).toBe('score-bar-high'));
  test('30 → score-bar-medium', () => expect(S.scoreBarClass(30)).toBe('score-bar-medium'));
  test('0 → score-bar-low', () => expect(S.scoreBarClass(0)).toBe('score-bar-low'));
});

// ── getCriticalityMeta ────────────────────────────────────────────────────────

describe('getCriticalityMeta()', () => {
  test('high → has label and cssClass', () => {
    const m = S.getCriticalityMeta('high');
    expect(m).toHaveProperty('label');
    expect(m).toHaveProperty('cssClass');
  });
  test('unknown level → defaults gracefully (no throw)', () => {
    expect(() => S.getCriticalityMeta('unknown')).not.toThrow();
  });
});

// ── computePriority ───────────────────────────────────────────────────────────

describe('computePriority()', () => {
  test('KEV article → critical_now regardless of score', () => {
    const { priorityLevel } = S.computePriority(art({ isKEV: true }));
    expect(priorityLevel).toBe('critical_now');
  });

  test('CVSS 10 + EPSS 1 + KEV → critical_now with score near 100', () => {
    const { priorityLevel, priorityScore } = S.computePriority(art({
      cvssScore: 10, epssScore: 1, isKEV: true,
    }));
    expect(priorityLevel).toBe('critical_now');
    expect(priorityScore).toBeGreaterThan(40); // composite + bonuses, unbounded
  });

  test('EPSS ≥ 50% with CVE → critical_now', () => {
    const { priorityLevel } = S.computePriority(art({
      epssScore: 0.55,
      cves: ['CVE-2025-1234'],
    }));
    expect(priorityLevel).toBe('critical_now');
  });

  test('EPSS 10% → at least investigate', () => {
    const { priorityLevel } = S.computePriority(art({ epssScore: 0.10 }));
    expect(['critical_now', 'investigate']).toContain(priorityLevel);
  });

  test('zero-day via attackTags → at least investigate', () => {
    const { priorityLevel } = S.computePriority(art({
      attackTags: [{ label: '0-Day' }],
    }));
    expect(['critical_now', 'investigate']).toContain(priorityLevel);
  });

  test('zero-day via title regex → at least investigate', () => {
    const { priorityLevel } = S.computePriority(art({
      title: 'New zero-day exploited in the wild',
    }));
    expect(['critical_now', 'investigate']).toContain(priorityLevel);
  });

  test('bare article with no signals → watch or low', () => {
    const { priorityLevel } = S.computePriority(art());
    expect(['watch', 'low']).toContain(priorityLevel);
  });

  test('article with CVE → at least watch', () => {
    const { priorityLevel } = S.computePriority(art({ cves: ['CVE-2025-9999'] }));
    expect(['critical_now', 'investigate', 'watch']).toContain(priorityLevel);
  });

  test('output has required keys', () => {
    const result = S.computePriority(art({ isKEV: true }));
    expect(result).toHaveProperty('priorityScore');
    expect(result).toHaveProperty('priorityLevel');
    expect(result).toHaveProperty('priorityReasons');
    expect(result).toHaveProperty('prioritySignals');
    expect(Array.isArray(result.priorityReasons)).toBe(true);
  });

  test('watchlist V2 vendor/high + high CVSS → critical_now or investigate', () => {
    // vendor/high = 4×5=20 bonus; combined with cvss:9 this should escalate
    const { priorityLevel } = S.computePriority(art({
      cvssScore: 9,
      epssScore: 0.30,
      watchlistMatchItems: [{ type: 'vendor', priority: 'high', label: 'Microsoft', enabled: true }],
    }));
    expect(['critical_now', 'investigate']).toContain(priorityLevel);
  });

  test('watchlist bonus capped at 25', () => {
    const { prioritySignals } = S.computePriority(art({
      watchlistMatchItems: [
        { type: 'vendor',  priority: 'high', label: 'Microsoft', enabled: true },
        { type: 'vendor',  priority: 'high', label: 'Cisco',     enabled: true },
        { type: 'product', priority: 'high', label: 'Exchange',  enabled: true },
      ],
    }));
    expect(prioritySignals.watchlistBonus).toBeLessThanOrEqual(25);
  });
});

// ── digestPriorityScore ───────────────────────────────────────────────────────

describe('digestPriorityScore()', () => {
  test('KEV bonus = +50', () => {
    const { breakdown } = S.digestPriorityScore(art({ isKEV: true }));
    expect(breakdown.kev).toBe(50);
  });

  test('EPSS ≥ 0.70 → +35 bonus', () => {
    const { breakdown } = S.digestPriorityScore(art({ epssScore: 0.75 }));
    expect(breakdown.epss).toBe(35);
  });

  test('EPSS ≥ 0.40 but < 0.70 → +15 bonus', () => {
    const { breakdown } = S.digestPriorityScore(art({ epssScore: 0.50 }));
    expect(breakdown.epss).toBe(15);
  });

  test('isTrending → +20 bonus', () => {
    const { breakdown } = S.digestPriorityScore(art({ isTrending: true }));
    expect(breakdown.trending).toBe(20);
  });

  test('zero-day via attackTags → +30 bonus', () => {
    const { breakdown } = S.digestPriorityScore(art({
      attackTags: [{ label: '0-Day' }],
    }));
    expect(breakdown.zeroDay).toBe(30);
  });

  test('watchlist bonus capped at 75 (3 × 25)', () => {
    const { breakdown } = S.digestPriorityScore(art({
      watchlistMatches: ['A', 'B', 'C', 'D', 'E'],
    }));
    expect(breakdown.watchlist).toBeLessThanOrEqual(75);
  });

  test('score = base + bonus', () => {
    const result = S.digestPriorityScore(art({ isKEV: true, isTrending: true }));
    expect(result.score).toBe(result.base + result.bonus);
  });
});

// ── getPriorityMeta ───────────────────────────────────────────────────────────

describe('getPriorityMeta()', () => {
  test('critical_now → red icon', () => {
    expect(S.getPriorityMeta('critical_now').icon).toBe('🔴');
  });
  test('investigate → orange icon', () => {
    expect(S.getPriorityMeta('investigate').icon).toBe('🟠');
  });
  test('watch → blue icon', () => {
    expect(S.getPriorityMeta('watch').icon).toBe('🔵');
  });
  test('unknown → default icon (no throw)', () => {
    expect(() => S.getPriorityMeta('anything')).not.toThrow();
  });
});
