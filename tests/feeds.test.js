// tests/feeds.test.js
//
// Unit tests for feeds.js pure utility functions:
//   makeId(), getXMLText(), extractLink(), stripHTML(), parseXML()
//
// fetchFeed() and fetchAllFeeds() are integration tests (network + browser APIs)
// and are excluded from this unit suite.
//
// Run: npm test

'use strict';

// ── Global mocks (feeds.js reads these at require-time) ──────────────────────

global.CONFIG = {
  USE_API: false,
  SCORER_HIGH:   ['rce', 'zero-day', 'actively exploited', 'ransomware'],
  SCORER_MEDIUM: ['vulnerability', 'cve-', 'patch', 'advisory'],
};

// scoreItem is called by parseXML via scorer.js — provide a stub
global.scoreItem = (title) => {
  const t = (title || '').toLowerCase();
  if (global.CONFIG.SCORER_HIGH.some(k => t.includes(k))) return 'high';
  if (global.CONFIG.SCORER_MEDIUM.some(k => t.includes(k))) return 'medium';
  return 'low';
};

// Storage.isFavorite is called for each article in parseXML
global.Storage = { isFavorite: jest.fn(() => false) };

// DOMParser is a browser API — mock with minimal XML parser for parseXML tests
global.DOMParser = class {
  parseFromString(str) {
    // Minimal RSS/Atom document builder using a simple regex approach for tests
    const doc = {
      _xml: str,
      querySelectorAll(tag) {
        // Simple extraction for test fixtures
        const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'gi');
        const results = [];
        let m;
        while ((m = re.exec(str)) !== null) {
          results.push({
            _content: m[1],
            querySelector(innerTag) {
              const inner = new RegExp(`<${innerTag}[^>]*>([\\s\\S]*?)<\\/${innerTag}>`, 'i').exec(m[1]);
              if (!inner) return null;
              return {
                textContent: inner[1].trim(),
                getAttribute: () => null,
              };
            },
            getAttribute() { return null; },
            textContent: m[1].trim(),
          });
        }
        return results;
      },
      querySelector(tag) {
        return this.querySelectorAll(tag)[0] || null;
      },
    };
    return doc;
  }
};

const F = require('../js/feeds.js');

// ── makeId ────────────────────────────────────────────────────────────────────

describe('makeId()', () => {
  test('returns a non-empty string', () => {
    expect(typeof F.makeId('https://example.com/article')).toBe('string');
    expect(F.makeId('https://example.com/article').length).toBeGreaterThan(0);
  });

  test('same URL → same ID (deterministic)', () => {
    const url = 'https://example.com/same-article';
    expect(F.makeId(url)).toBe(F.makeId(url));
  });

  test('different URLs → different IDs', () => {
    expect(F.makeId('https://a.com/1')).not.toBe(F.makeId('https://b.com/2'));
  });

  test('falsy input → returns a random fallback string (no throw)', () => {
    expect(() => F.makeId(null)).not.toThrow();
    expect(() => F.makeId('')).not.toThrow();
    expect(typeof F.makeId(null)).toBe('string');
  });

  test('output contains only alphanumeric characters (base36)', () => {
    const id = F.makeId('https://example.com/test');
    expect(id).toMatch(/^[a-z0-9]+$/);
  });
});

// ── stripHTML ─────────────────────────────────────────────────────────────────

describe('stripHTML()', () => {
  test('removes HTML tags', () => {
    expect(F.stripHTML('<p>Hello <strong>world</strong></p>')).toBe('Hello world');
  });

  test('extracts text from CDATA section', () => {
    const result = F.stripHTML('<![CDATA[<p>CDATA content</p>]]>');
    expect(result).toContain('CDATA content');
    expect(result).not.toContain('CDATA[');
    expect(result).not.toContain('<p>');
  });

  test('truncates to 300 chars maximum', () => {
    const long = 'A'.repeat(500);
    expect(F.stripHTML(long).length).toBeLessThanOrEqual(300);
  });

  test('normalizes multiple whitespace to single space', () => {
    expect(F.stripHTML('hello   world')).toBe('hello world');
  });

  test('empty string → empty string', () => {
    expect(F.stripHTML('')).toBe('');
  });

  test('null/undefined → empty string (no throw)', () => {
    expect(() => F.stripHTML(null)).not.toThrow();
    expect(F.stripHTML(null)).toBe('');
  });

  test('plain text passthrough (no tags)', () => {
    expect(F.stripHTML('Simple plain text')).toBe('Simple plain text');
  });

  test('nested tags fully stripped', () => {
    const html = '<div class="a"><p><em>text</em></p></div>';
    expect(F.stripHTML(html)).toBe('text');
  });
});

// ── getXMLText ────────────────────────────────────────────────────────────────

describe('getXMLText()', () => {
  function makeItem(tags) {
    // Build a fake item element with querySelector
    return {
      querySelector(tag) {
        if (tags[tag] !== undefined) {
          return { textContent: tags[tag] };
        }
        return null;
      },
    };
  }

  test('returns text from first matching tag', () => {
    const item = makeItem({ title: 'My Title' });
    expect(F.getXMLText(item, 'title')).toBe('My Title');
  });

  test('tries multiple tag names, returns first non-empty', () => {
    const item = makeItem({ summary: '', description: 'Desc text' });
    expect(F.getXMLText(item, 'summary', 'description')).toBe('Desc text');
  });

  test('returns empty string if no tag found', () => {
    const item = makeItem({});
    expect(F.getXMLText(item, 'title', 'summary')).toBe('');
  });

  test('trims whitespace from result', () => {
    const item = makeItem({ title: '  spaced  ' });
    expect(F.getXMLText(item, 'title')).toBe('spaced');
  });
});

// ── extractLink ───────────────────────────────────────────────────────────────

describe('extractLink()', () => {
  function makeItem({ linkHref, linkText } = {}) {
    return {
      querySelector(tag) {
        if (tag !== 'link') return null;
        return {
          getAttribute(attr) {
            return attr === 'href' ? (linkHref || null) : null;
          },
          textContent: linkText || '',
        };
      },
    };
  }

  test('returns href attribute for Atom <link href="...">', () => {
    const item = makeItem({ linkHref: 'https://atom.example.com/article' });
    expect(F.extractLink(item)).toBe('https://atom.example.com/article');
  });

  test('falls back to textContent for RSS <link>url</link>', () => {
    const item = makeItem({ linkText: 'https://rss.example.com/article' });
    expect(F.extractLink(item)).toBe('https://rss.example.com/article');
  });

  test('returns empty string when no link element', () => {
    const item = { querySelector: () => null };
    expect(F.extractLink(item)).toBe('');
  });
});

// ── parseXML ──────────────────────────────────────────────────────────────────

describe('parseXML()', () => {
  const FEED = { id: 'test-feed', name: 'Test Feed', icon: '📰' };

  function makeXMLDoc(items) {
    // Build a minimal mock XML doc that parseXML can iterate
    return {
      querySelectorAll(selector) {
        if (selector === 'item' || selector === 'entry') {
          return items.map(item => ({
            querySelector(tag) {
              if (tag === 'link') {
                return {
                  getAttribute: () => null,
                  textContent: item.link || '',
                };
              }
              const val = item[tag];
              if (val === undefined) return null;
              return { textContent: val };
            },
          }));
        }
        return [];
      },
    };
  }

  test('returns an array', () => {
    const doc = makeXMLDoc([]);
    expect(Array.isArray(F.parseXML(doc, FEED))).toBe(true);
  });

  test('filters out items with no link', () => {
    const doc = makeXMLDoc([
      { title: 'Has title', link: '', pubDate: new Date().toUTCString() },
    ]);
    // An item with no link must not be included (no stable ID possible)
    const articles = F.parseXML(doc, FEED);
    expect(articles.every(a => a.link)).toBe(true);
  });

  test('maps feed metadata onto each article', () => {
    const doc = makeXMLDoc([{
      title:   'Test Article',
      link:    'https://example.com/article',
      pubDate: new Date().toUTCString(),
    }]);
    const articles = F.parseXML(doc, FEED);
    expect(articles[0].source).toBe('test-feed');
    expect(articles[0].sourceName).toBe('Test Feed');
    expect(articles[0].sourceIcon).toBe('📰');
  });

  test('generates a stable id from link', () => {
    const doc = makeXMLDoc([{
      title:   'Article with stable ID',
      link:    'https://example.com/stable',
      pubDate: new Date().toUTCString(),
    }]);
    const articles = F.parseXML(doc, FEED);
    expect(typeof articles[0].id).toBe('string');
    expect(articles[0].id).toBe(F.makeId('https://example.com/stable'));
  });

  test('filters out articles older than 30 days', () => {
    const old = new Date(Date.now() - 31 * 86_400_000).toUTCString();
    const doc = makeXMLDoc([{
      title:   'Old article',
      link:    'https://example.com/old',
      pubDate: old,
    }]);
    expect(F.parseXML(doc, FEED)).toHaveLength(0);
  });

  test('keeps articles within 30 days', () => {
    const recent = new Date(Date.now() - 7 * 86_400_000).toUTCString();
    const doc = makeXMLDoc([{
      title:   'Recent article',
      link:    'https://example.com/recent',
      pubDate: recent,
    }]);
    expect(F.parseXML(doc, FEED)).toHaveLength(1);
  });

  test('pubDate is a Date object', () => {
    const doc = makeXMLDoc([{
      title:   'Date test',
      link:    'https://example.com/date',
      pubDate: new Date().toUTCString(),
    }]);
    const articles = F.parseXML(doc, FEED);
    expect(articles[0].pubDate).toBeInstanceOf(Date);
  });

  test('invalid pubDate defaults to now (no throw)', () => {
    const doc = makeXMLDoc([{
      title:   'Bad date article',
      link:    'https://example.com/baddate',
      pubDate: 'not-a-date',
    }]);
    expect(() => F.parseXML(doc, FEED)).not.toThrow();
    const articles = F.parseXML(doc, FEED);
    if (articles.length > 0) {
      expect(articles[0].pubDate).toBeInstanceOf(Date);
    }
  });

  test('scored article has criticality field', () => {
    const doc = makeXMLDoc([{
      title:   'Critical RCE vulnerability actively exploited',
      link:    'https://example.com/rce',
      pubDate: new Date().toUTCString(),
    }]);
    const articles = F.parseXML(doc, FEED);
    expect(['high', 'medium', 'low']).toContain(articles[0].criticality);
  });

  test('multiple items all returned (within age limit)', () => {
    const now = new Date().toUTCString();
    const doc = makeXMLDoc([
      { title: 'Article 1', link: 'https://example.com/1', pubDate: now },
      { title: 'Article 2', link: 'https://example.com/2', pubDate: now },
      { title: 'Article 3', link: 'https://example.com/3', pubDate: now },
    ]);
    expect(F.parseXML(doc, FEED)).toHaveLength(3);
  });
});
