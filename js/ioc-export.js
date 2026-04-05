// ioc-export.js — IOC Bulk Export for ThreatLens
//
// Aggregates all IOCs extracted by ioc-extractor.js across the current feed,
// with full article context (source, date, CVEs, EPSS, KEV flag).
//
// Formats:
//   CSV   — type, value, article_count, sources, first_seen, cves, epss, kev
//           Ready to ingest into SIEM (Splunk, Elastic), threat intel platforms
//   JSON  — structured, machine-readable, includes full article list per IOC
//   TXT   — sectioned plain text, human-readable (IPs / Domains / Hashes / URLs)
//   Plain — one value per line, paste directly into EDR/firewall blocklist
//
// API:
//   IOCExport.init(getArticlesFn)   — bind button, store articles getter
//   IOCExport.show()                — open modal

const IOCExport = (() => {
  'use strict';

  let _getArticles = null;
  let _scopeDays   = 7;
  let _types       = new Set(['ip', 'domain', 'hash', 'url']);
  let _format      = 'csv';

  // ── Scope filter ──────────────────────────────────────────────────────────

  function _filterByScope(arts, days) {
    if (!days || days === 0) return arts;
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    return arts.filter(a => a.pubDate && a.pubDate.getTime() >= cutoff);
  }

  // ── Context-aware aggregation ─────────────────────────────────────────────
  // Builds a Map: "category:value" → { category, value, articles[] }
  // Tracks every article that mentions each IOC — preserves source context.

  function _aggregate(articles) {
    const map = new Map();

    const add = (category, value, article) => {
      if (!_types.has(category)) return;
      const key = `${category}:${value}`;
      if (!map.has(key)) {
        map.set(key, {
          category,
          value,
          articles: []
        });
      }
      const entry = map.get(key);
      // Avoid duplicate articles per IOC
      if (!entry.articles.some(a => a.link === article.link)) {
        entry.articles.push({
          title:  article.title  || '',
          date:   article.pubDate instanceof Date
                    ? article.pubDate.toISOString().slice(0, 10)
                    : '',
          link:   article.link   || '',
          cves:   (article.cves  || []).join(' '),
          epss:   article.epssScore != null
                    ? (article.epssScore * 100).toFixed(1)
                    : '',
          kev:    article.isKEV ? 'true' : 'false'
        });
      }
    };

    for (const a of articles) {
      if (!a.iocs) continue;
      if (_types.has('ip'))     (a.iocs.ips     || []).forEach(v => add('ip',     v, a));
      if (_types.has('domain')) (a.iocs.domains || []).forEach(v => add('domain', v, a));
      if (_types.has('url'))    (a.iocs.urls    || []).forEach(v => add('url',    v, a));
      if (_types.has('hash'))   (a.iocs.hashes  || []).forEach(h => {
        if (h && h.value) add('hash', `${h.type || 'hash'}:${h.value}`, a);
      });
    }

    return [...map.values()].sort((a, b) => {
      // Sort: IPs → domains → hashes → URLs, then alphabetically
      const order = { ip: 0, domain: 1, hash: 2, url: 3 };
      const oa = order[a.category] ?? 9;
      const ob = order[b.category] ?? 9;
      if (oa !== ob) return oa - ob;
      return a.value.localeCompare(b.value);
    });
  }

  // ── Format generators ─────────────────────────────────────────────────────

  function _csvEscape(s) {
    const str = String(s || '');
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  }

  function _toCSV(entries) {
    const header = [
      'type', 'value', 'article_count',
      'first_seen', 'sources', 'cves', 'epss', 'kev'
    ].join(',');

    const rows = entries.map(e => {
      const arts        = e.articles;
      const firstSeen   = arts.reduce((min, a) => (a.date < min ? a.date : min), arts[0]?.date || '');
      const sources     = arts.map(a => a.title.slice(0, 60)).join(' | ');
      const allCVEs     = [...new Set(arts.flatMap(a => a.cves ? a.cves.split(' ').filter(Boolean) : []))].join(' ');
      const maxEPSS     = arts.reduce((max, a) => {
        const v = parseFloat(a.epss);
        return (isNaN(v) ? max : Math.max(max, v));
      }, 0);
      const isKEV       = arts.some(a => a.kev === 'true') ? 'true' : 'false';

      return [
        _csvEscape(e.category),
        _csvEscape(e.value),
        arts.length,
        _csvEscape(firstSeen),
        _csvEscape(sources),
        _csvEscape(allCVEs),
        maxEPSS > 0 ? maxEPSS.toFixed(1) + '%' : '',
        isKEV
      ].join(',');
    });

    return [header, ...rows].join('\n');
  }

  function _toJSON(entries, meta) {
    return JSON.stringify({
      meta: {
        tool:       'ThreatLens',
        exportedAt: new Date().toISOString(),
        scope:      meta.scopeLabel,
        articleCount: meta.articleCount,
        iocCount:   entries.length
      },
      iocs: entries.map(e => ({
        type:    e.category,
        value:   e.value,
        sources: e.articles.map(a => ({
          title:   a.title,
          date:    a.date,
          url:     a.link,
          cves:    a.cves || null,
          epss:    a.epss ? parseFloat(a.epss) : null,
          kev:     a.kev === 'true'
        }))
      }))
    }, null, 2);
  }

  function _toTXT(entries, meta) {
    const ts   = new Date().toLocaleString('en-US');
    const head = [
      `# IOC Bulk Export — ThreatLens`,
      `# Scope    : ${meta.scopeLabel} · ${meta.articleCount} articles`,
      `# Total    : ${entries.length} unique indicator${entries.length !== 1 ? 's' : ''}`,
      `# Exported : ${ts}`,
      ''
    ];

    const sections = { ip: [], domain: [], hash: [], url: [] };
    entries.forEach(e => { (sections[e.category] || (sections.other = sections.other || [])).push(e.value); });

    const body = [];
    if (sections.ip.length) {
      body.push(`## IPs (${sections.ip.length})`, ...sections.ip, '');
    }
    if (sections.domain.length) {
      body.push(`## Domains (${sections.domain.length})`, ...sections.domain, '');
    }
    if (sections.hash.length) {
      body.push(`## Hashes (${sections.hash.length})`, ...sections.hash, '');
    }
    if (sections.url.length) {
      body.push(`## URLs (${sections.url.length})`, ...sections.url, '');
    }

    return [...head, ...body].join('\n');
  }

  function _toPlain(entries) {
    // One value per line — paste directly into SIEM, EDR, or firewall blocklist
    return entries.map(e => e.value).join('\n');
  }

  // ── Download helper ───────────────────────────────────────────────────────

  function _download(content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const a    = Object.assign(document.createElement('a'), {
      href:     URL.createObjectURL(blob),
      download: filename
    });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1500);
  }

  // ── Clipboard helper ──────────────────────────────────────────────────────

  function _copyText(text) {
    const btn = document.getElementById('iocexp-copy-btn');
    const flash = msg => {
      if (!btn) return;
      const orig = btn.textContent;
      btn.textContent = msg;
      setTimeout(() => { btn.textContent = orig; }, 1800);
    };
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text)
        .then(() => flash('✅ Copied!'))
        .catch(() => { _legacyCopy(text); flash('✅ Copied!'); });
    } else {
      _legacyCopy(text);
      flash('✅ Copied!');
    }
  }

  function _legacyCopy(text) {
    const ta = Object.assign(document.createElement('textarea'), {
      value: text, style: 'position:fixed;top:-9999px;opacity:0'
    });
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }

  // ── UI helpers ────────────────────────────────────────────────────────────

  function _currentArticles() {
    const all = _getArticles ? _getArticles() : [];
    return _filterByScope(all, _scopeDays);
  }

  function _buildEntries() {
    return _aggregate(_currentArticles());
  }

  function _formatEntries(entries) {
    const arts    = _currentArticles();
    const days    = _scopeDays;
    const meta    = {
      scopeLabel:   days === 1  ? 'Last 24h'
                  : days === 7  ? 'Last 7 days'
                  : days === 30 ? 'Last 30 days'
                  : 'All articles',
      articleCount: arts.length
    };
    switch (_format) {
      case 'json':  return { content: _toJSON(entries, meta),  ext: 'json', mime: 'application/json' };
      case 'txt':   return { content: _toTXT(entries, meta),   ext: 'txt',  mime: 'text/plain' };
      case 'plain': return { content: _toPlain(entries),       ext: 'txt',  mime: 'text/plain' };
      default:      return { content: _toCSV(entries),         ext: 'csv',  mime: 'text/csv'   };
    }
  }

  // ── Modal refresh ─────────────────────────────────────────────────────────

  function _refresh() {
    const arts    = _currentArticles();
    const entries = _aggregate(arts);

    // Counts per type
    const counts = { ip: 0, domain: 0, hash: 0, url: 0 };
    entries.forEach(e => { if (counts[e.category] !== undefined) counts[e.category]++; });
    const total = entries.length;

    // Update summary tiles
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('iocexp-count-ip',     counts.ip);
    set('iocexp-count-domain', counts.domain);
    set('iocexp-count-hash',   counts.hash);
    set('iocexp-count-url',    counts.url);
    set('iocexp-count-total',  total);

    // Update sub-label
    const days = _scopeDays;
    const label = days === 1  ? 'Last 24h'
                : days === 7  ? 'Last 7 days'
                : days === 30 ? 'Last 30 days'
                : 'All articles';
    const sub = document.getElementById('iocexp-sub');
    if (sub) sub.textContent = `${arts.length} article${arts.length !== 1 ? 's' : ''} · ${label} · ${total} unique IOC${total !== 1 ? 's' : ''}`;

    // Disable/enable export if no IOCs
    ['iocexp-copy-btn', 'iocexp-dl-btn'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = total === 0;
    });
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  function show() {
    const modal = document.getElementById('modal-ioc-export');
    if (!modal) return;
    _refresh();
    modal.style.display = 'flex';
  }

  function _close() {
    const modal = document.getElementById('modal-ioc-export');
    if (modal) modal.style.display = 'none';
  }

  function init(getArticlesFn) {
    _getArticles = getArticlesFn;

    document.getElementById('btn-ioc-export')?.addEventListener('click', show);
    document.getElementById('iocexp-close')?.addEventListener('click', _close);

    // Click outside to close
    document.getElementById('modal-ioc-export')?.addEventListener('click', e => {
      if (e.target === e.currentTarget) _close();
    });

    // ESC
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        const modal = document.getElementById('modal-ioc-export');
        if (modal && modal.style.display !== 'none') _close();
      }
    });

    // Scope pills
    document.querySelectorAll('#iocexp-scope-pills .iocexp-scope-pill').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        _scopeDays = parseInt(btn.dataset.days) || 0;
        document.querySelectorAll('#iocexp-scope-pills .iocexp-scope-pill')
          .forEach(b => b.classList.toggle('iocexp-scope-active', b === btn));
        _refresh();
      });
    });

    // Type checkboxes
    document.querySelectorAll('.iocexp-type-cb').forEach(cb => {
      cb.addEventListener('change', () => {
        const type = cb.dataset.type;
        if (cb.checked) _types.add(type); else _types.delete(type);
        _refresh();
      });
    });

    // Format radio buttons
    document.querySelectorAll('.iocexp-fmt-radio').forEach(radio => {
      radio.addEventListener('change', () => {
        _format = radio.value;
      });
    });

    // Download button
    document.getElementById('iocexp-dl-btn')?.addEventListener('click', () => {
      const entries = _buildEntries();
      if (!entries.length) return;
      const { content, ext, mime } = _formatEntries(entries);
      const ts   = new Date().toISOString().slice(0, 10);
      _download(content, `threatlens_iocs_${ts}.${ext}`, mime);
    });

    // Copy button
    document.getElementById('iocexp-copy-btn')?.addEventListener('click', () => {
      const entries = _buildEntries();
      if (!entries.length) return;
      const { content } = _formatEntries(entries);
      _copyText(content);
    });
  }

  return { init, show };
})();
