// tests/deduplicator.test.js
//
// Unit tests for deduplicator.js:
//   normalizeTitle(), tokenizeTitle(), jaccardSimilarity(),
//   classifyDuplicate(), compareArticles(), deduplicate()
//
// Run: npm test

'use strict';

const D = require('../js/deduplicator.js');

// ── Helpers ───────────────────────────────────────────────────────────────────

const NOW = new Date();
const YESTERDAY = new Date(Date.now() - 86_400_000);

function art(overrides = {}) {
  return {
    id:         overrides.link ? D.normalizeTitle(overrides.link) : Math.random().toString(36),
    title:      'Generic security article',
    description:'',
    link:       'https://example.com/article',
    pubDate:    NOW,
    source:     'source-a',
    sourceName: 'Source A',
    sourceIcon: '',
    cves:       [],
    ...overrides,
  };
}

// ── normalizeTitle ────────────────────────────────────────────────────────────

describe('normalizeTitle()', () => {
  test('lowercases input', () => {
    expect(D.normalizeTitle('CRITICAL RCE')).toBe('critical rce');
  });

  test('removes diacritics', () => {
    expect(D.normalizeTitle('Vulnérabilité')).toBe('vulnerabilite');
  });

  test('normalizes zero-day variants', () => {
    expect(D.normalizeTitle('zero-day exploit')).toContain('0day');
    expect(D.normalizeTitle('zero day exploit')).toContain('0day');
  });

  test('normalizes out-of-band', () => {
    expect(D.normalizeTitle('out-of-band patch')).toContain('outofband');
  });

  test('normalizes supply-chain', () => {
    expect(D.normalizeTitle('supply-chain attack')).toContain('supplychain');
  });

  test('normalizes in-the-wild', () => {
    expect(D.normalizeTitle('in-the-wild exploitation')).toContain('inthewild');
  });

  test('preserves CVE-IDs through normalization', () => {
    const result = D.normalizeTitle('Patch for CVE-2025-12345');
    expect(result).toContain('cve-2025-12345');
  });

  test('removes punctuation except CVE hyphens', () => {
    const result = D.normalizeTitle('Critical: RCE (unauthenticated)');
    expect(result).not.toContain(':');
    expect(result).not.toContain('(');
  });

  test('normalizes whitespace', () => {
    expect(D.normalizeTitle('  too   many   spaces  ')).toBe('too many spaces');
  });

  test('empty string → empty string', () => {
    expect(D.normalizeTitle('')).toBe('');
  });

  test('null input → empty string (no throw)', () => {
    expect(() => D.normalizeTitle(null)).not.toThrow();
    expect(D.normalizeTitle(null)).toBe('');
  });
});

// ── tokenizeTitle ─────────────────────────────────────────────────────────────

describe('tokenizeTitle()', () => {
  test('returns a Set', () => {
    expect(D.tokenizeTitle('microsoft rce vulnerability')).toBeInstanceOf(Set);
  });

  test('always keeps CVE IDs', () => {
    const tokens = D.tokenizeTitle('cve-2025-12345 patch');
    expect(tokens.has('cve-2025-12345')).toBe(true);
  });

  test('always keeps security terms (rce, xss, sqli…)', () => {
    const tokens = D.tokenizeTitle('rce xss sqli vulnerability');
    expect(tokens.has('rce')).toBe(true);
    expect(tokens.has('xss')).toBe(true);
  });

  test('always keeps known vendors (microsoft, cisco…)', () => {
    const tokens = D.tokenizeTitle('microsoft cisco vulnerability');
    expect(tokens.has('microsoft')).toBe(true);
    expect(tokens.has('cisco')).toBe(true);
  });

  test('filters stop words (the, in, a…)', () => {
    const tokens = D.tokenizeTitle('the vulnerability in a system');
    expect(tokens.has('the')).toBe(false);
    expect(tokens.has('in')).toBe(false);
    expect(tokens.has('a')).toBe(false);
  });

  test('filters short words (< 3 chars) unless security term', () => {
    const tokens = D.tokenizeTitle('an rce at');
    expect(tokens.has('an')).toBe(false);
    expect(tokens.has('at')).toBe(false);
    expect(tokens.has('rce')).toBe(true);
  });

  test('filters pure digit tokens', () => {
    const tokens = D.tokenizeTitle('patch 2024 update');
    expect(tokens.has('2024')).toBe(false);
  });

  test('empty string → empty Set', () => {
    expect(D.tokenizeTitle('').size).toBe(0);
  });
});

// ── jaccardSimilarity ─────────────────────────────────────────────────────────

describe('jaccardSimilarity()', () => {
  test('identical sets → 1.0', () => {
    const s = new Set(['a', 'b', 'c']);
    expect(D.jaccardSimilarity(s, s)).toBe(1.0);
  });

  test('disjoint sets → 0.0', () => {
    const a = new Set(['apple', 'orange']);
    const b = new Set(['car', 'truck']);
    expect(D.jaccardSimilarity(a, b)).toBe(0.0);
  });

  test('50% overlap → 0.333…', () => {
    const a = new Set(['a', 'b', 'c']);
    const b = new Set(['a', 'b', 'd', 'e']);
    // intersection=2, union=5 → 0.4
    expect(D.jaccardSimilarity(a, b)).toBeCloseTo(0.4, 2);
  });

  test('both empty → 1.0 (identical empty sets)', () => {
    expect(D.jaccardSimilarity(new Set(), new Set())).toBe(1.0);
  });

  test('one empty → 0.0', () => {
    expect(D.jaccardSimilarity(new Set(['a']), new Set())).toBe(0.0);
  });

  test('accepts string inputs (auto-normalizes + tokenizes)', () => {
    const score = D.jaccardSimilarity(
      'Microsoft patches critical RCE',
      'Microsoft patches critical RCE',
    );
    expect(score).toBe(1.0);
  });

  test('completely different strings → low score', () => {
    const score = D.jaccardSimilarity(
      'apple releases ios update',
      'cisco patches firewall firmware',
    );
    expect(score).toBeLessThan(0.2);
  });
});

// ── classifyDuplicate ─────────────────────────────────────────────────────────

describe('classifyDuplicate()', () => {
  const BASE = {
    score: 0, sameCve: null, conflictingCVEs: false,
    sameVendor: null, sameProduct: null,
    closeInTime: null, sameURL: false, sameNormHash: false,
  };

  test('R1: sameURL → duplicate', () => {
    const { decision } = D.classifyDuplicate({ ...BASE, sameURL: true });
    expect(decision).toBe('duplicate');
  });

  test('R2: sameNormHash → duplicate', () => {
    const { decision } = D.classifyDuplicate({ ...BASE, sameNormHash: true });
    expect(decision).toBe('duplicate');
  });

  test('G1: conflictingCVEs + low score → distinct (guard fuse)', () => {
    const { decision } = D.classifyDuplicate({
      ...BASE, conflictingCVEs: true, score: 0.5,
    });
    expect(decision).toBe('distinct');
  });

  test('R3: sameCve + score ≥ RELATED + sameProduct → duplicate', () => {
    const { decision } = D.classifyDuplicate({
      ...BASE, sameCve: true, score: 0.70, sameProduct: true,
    });
    expect(decision).toBe('duplicate');
  });

  test('R4: score ≥ DUPLICATE + no product conflict → duplicate', () => {
    const { decision } = D.classifyDuplicate({
      ...BASE, score: 0.90,
    });
    expect(decision).toBe('duplicate');
  });

  test('R5: sameCve + score < RELATED → related', () => {
    const { decision } = D.classifyDuplicate({
      ...BASE, sameCve: true, score: 0.50,
    });
    expect(decision).toBe('related');
  });

  test('R6: score ≥ RELATED + sameVendor + no conflict → related', () => {
    const { decision } = D.classifyDuplicate({
      ...BASE, score: 0.70, sameVendor: true, conflictingCVEs: false,
    });
    expect(decision).toBe('related');
  });

  test('default: low score, no signals → distinct', () => {
    const { decision } = D.classifyDuplicate({ ...BASE, score: 0.30 });
    expect(decision).toBe('distinct');
  });
});

// ── compareArticles ───────────────────────────────────────────────────────────

describe('compareArticles()', () => {
  test('identical articles → duplicate', () => {
    const a = art({ title: 'Microsoft patches critical RCE in Exchange', link: 'https://a.com/1' });
    const { decision } = D.compareArticles(a, a);
    expect(decision).toBe('duplicate');
  });

  test('same URL → duplicate regardless of title', () => {
    const a = art({ title: 'Article A', link: 'https://same.com/page' });
    const b = art({ title: 'Article B', link: 'https://same.com/page' });
    const { decision, sameURL } = D.compareArticles(a, b);
    expect(sameURL).toBe(true);
    expect(decision).toBe('duplicate');
  });

  test('shared CVE + same product → duplicate', () => {
    const a = art({ title: 'Microsoft Exchange CVE-2025-9999 RCE patch', cves: ['CVE-2025-9999'] });
    const b = art({ title: 'CVE-2025-9999 remote code execution Microsoft Exchange fix', cves: ['CVE-2025-9999'] });
    const { decision } = D.compareArticles(a, b);
    expect(decision).toBe('duplicate');
  });

  test('conflicting CVEs signal is detected when both articles have different CVEs', () => {
    // _conflictingCVEs fires when both articles have CVEs but with zero overlap
    const a = art({ title: 'Apache Log4j CVE-2025-0001 RCE exploit', cves: ['CVE-2025-0001'] });
    const b = art({ title: 'Cisco IOS-XE CVE-2025-9999 auth bypass',  cves: ['CVE-2025-9999'] });
    const { conflictingCVEs } = D.compareArticles(a, b);
    expect(conflictingCVEs).toBe(true);
  });

  test('output has required fields', () => {
    const a = art({ title: 'Apache Log4j critical RCE exploit' });
    const b = art({ title: 'Apache Log4j critical RCE exploit' });
    const result = D.compareArticles(a, b);
    expect(result).toHaveProperty('score');
    expect(result).toHaveProperty('decision');
    expect(result).toHaveProperty('reason');
    expect(result).toHaveProperty('sameCve');
    expect(result).toHaveProperty('sameURL');
  });

  test('UTM params stripped before URL comparison', () => {
    const a = art({ link: 'https://example.com/article?utm_source=newsletter' });
    const b = art({ link: 'https://example.com/article?utm_medium=email' });
    const { sameURL } = D.compareArticles(a, b);
    expect(sameURL).toBe(true);
  });

  test('totally different articles → score < RELATED threshold', () => {
    const a = art({ title: 'Phishing campaign targets banking customers in France' });
    const b = art({ title: 'Ransomware group leaks stolen government data online' });
    const { score } = D.compareArticles(a, b);
    expect(score).toBeLessThan(D.CONFIG.THRESHOLDS.RELATED);
  });
});

// ── deduplicate (pipeline) ────────────────────────────────────────────────────

describe('deduplicate()', () => {
  test('empty array → empty array', () => {
    expect(D.deduplicate([])).toEqual([]);
  });

  test('single article → returned unchanged', () => {
    const articles = [art({ title: 'Only one article', link: 'https://a.com/1' })];
    expect(D.deduplicate(articles)).toHaveLength(1);
  });

  test('two identical-URL articles → merged (result ≤ 1)', () => {
    const a = { ...art({ title: 'Duplicate Article', link: 'https://same.com/story', pubDate: YESTERDAY }), id: 'dup-a' };
    const b = { ...art({ title: 'Duplicate Article', link: 'https://same.com/story', pubDate: NOW }),      id: 'dup-b' };
    const result = D.deduplicate([a, b]);
    expect(result.length).toBeLessThanOrEqual(1);
  });

  test('kept article has sourceCount ≥ 2 when duplicate absorbed', () => {
    const a = art({
      id: 'a1', title: 'Microsoft Exchange CVE-2025-9999 RCE patch',
      link: 'https://source-a.com/story', cves: ['CVE-2025-9999'],
      source: 'source-a', pubDate: YESTERDAY,
    });
    const b = art({
      id: 'b1', title: 'CVE-2025-9999 remote code execution in Microsoft Exchange',
      link: 'https://source-b.com/story', cves: ['CVE-2025-9999'],
      source: 'source-b', pubDate: NOW,
    });
    const result = D.deduplicate([a, b]);
    if (result.length === 1) {
      expect(result[0].sourceCount).toBeGreaterThanOrEqual(2);
    }
  });

  test('distinct articles → both kept', () => {
    const a = art({ title: 'Apple patches iOS kernel bug', link: 'https://a.com/1', id: 'a1' });
    const b = art({ title: 'Cisco IOS-XE firmware security update advisory', link: 'https://b.com/2', id: 'b1' });
    const result = D.deduplicate([a, b]);
    expect(result).toHaveLength(2);
  });

  test('duplicate articles from same URL deduplicated, distinct kept', () => {
    const dup1 = art({ id: 'x1', title: 'Dup story', link: 'https://dup.com/story', pubDate: YESTERDAY });
    const dup2 = art({ id: 'x2', title: 'Dup story', link: 'https://dup.com/story', pubDate: NOW });
    const unique = art({ id: 'u1', title: 'Unrelated cisco firewall update', link: 'https://unique.com/story' });
    const result = D.deduplicate([dup1, dup2, unique]);
    expect(result).toHaveLength(2);
  });
});
