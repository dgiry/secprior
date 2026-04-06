// trend-search.js — Trend Vision One Search (read-only, user-triggered)
//
// Queries Workbench alerts for CVEs and IOCs extracted from an article.
// Called exclusively on user click — no automatic background search.
//
// Signal priority order per article (max 5 total):
//   CVEs (up to 2) → Hashes (up to 2) → Domains (up to 1) → IPs (up to 1)
//
// Result model per indicator:
//   { query, type, status, alertCount, topSeverity, latestAlert, source, cachedAt }
//   status: "found" | "not_found" | "unknown"
//
// Cache: localStorage cv_trend_search_cache, TTL 1h, max 500 entries (FIFO)
// Throttle: 500ms between requests

const TrendSearch = (() => {
  'use strict';

  const CACHE_KEY  = 'cv_trend_search_cache';
  const CACHE_TTL  = 60 * 60 * 1000; // 1h — workbench alerts change, but not per-minute
  const REQ_DELAY  = 500;             // ms between requests (conservative)
  const MAX_TOTAL  = 5;               // max indicators per click

  // Private / reserved IP ranges — filtered out before sending to Trend
  const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.\d|169\.254\.|224\.|240\.|255\.)/;

  const _delay = ms => new Promise(r => setTimeout(r, ms));

  // ── Cache ───────────────────────────────────────────────────────────────────

  function _getCache() {
    try { return JSON.parse(localStorage.getItem(CACHE_KEY) || '{}'); } catch { return {}; }
  }

  function _saveCache(data) {
    try { localStorage.setItem(CACHE_KEY, JSON.stringify(data)); } catch {}
  }

  function _getCached(key) {
    const cache = _getCache();
    const entry = cache[key];
    if (!entry) return null;
    if (Date.now() - entry.cachedAt > CACHE_TTL) return null;
    return entry.data;
  }

  function _setCached(key, data) {
    const cache = _getCache();
    cache[key] = { data, cachedAt: Date.now() };
    const keys = Object.keys(cache);
    if (keys.length > 500) {
      keys.sort((a, b) => cache[a].cachedAt - cache[b].cachedAt)
          .slice(0, keys.length - 500)
          .forEach(k => delete cache[k]);
    }
    _saveCache(cache);
  }

  // ── Indicator collection ────────────────────────────────────────────────────

  function _collectIndicators(article) {
    const indicators = [];

    // 1. CVEs — highest signal quality (max 2)
    const cves = (article.cves || article.cveIds || []).slice(0, 2);
    for (const cve of cves)
      if (/^CVE-\d{4}-\d{4,}$/i.test(cve))
        indicators.push({ query: cve.toUpperCase(), type: 'cve' });

    // 2. Hashes — high fidelity, low noise (max 2; SHA256/SHA1/MD5 only if ≥32 chars)
    const hashes = (article.iocs?.hashes || [])
      .filter(h => h.value && h.value.length >= 32)
      .slice(0, 2);
    for (const h of hashes)
      indicators.push({ query: h.value.toLowerCase(), type: 'hash' });

    // 3. Domains — medium fidelity (max 1; filter trivially short or gov/mil)
    const domains = (article.iocs?.domains || [])
      .filter(d => d.length > 6 && !/\.(gov|mil|edu)$/.test(d))
      .slice(0, 1);
    for (const d of domains)
      indicators.push({ query: d.toLowerCase(), type: 'domain' });

    // 4. IPs — lower fidelity, filter private ranges (max 1)
    const ips = (article.iocs?.ips || [])
      .filter(ip => !PRIVATE_IP_RE.test(ip))
      .slice(0, 1);
    for (const ip of ips)
      indicators.push({ query: ip, type: 'ip' });

    return indicators.slice(0, MAX_TOTAL);
  }

  // ── Fetch one indicator via /api/tv1-sync?mode=search ──────────────────────

  async function _fetchOne(indicator) {
    const cacheKey = `${indicator.type}:${indicator.query}`;
    const cached   = _getCached(cacheKey);
    if (cached) return cached;

    const region = (typeof TV1Sync !== 'undefined' ? TV1Sync.loadConfig()?.region : null) || 'us';
    const url    = `/api/tv1-sync?mode=search`
      + `&q=${encodeURIComponent(indicator.query)}`
      + `&type=${encodeURIComponent(indicator.type)}`
      + `&region=${encodeURIComponent(region)}`;

    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(12_000) });

      if (res.status === 429) {
        return { ...indicator, status: 'unknown', reason: 'rate_limited',
          alertCount: null, topSeverity: null, latestAlert: null,
          source: 'trend_v1', cachedAt: Date.now() };
      }
      if (!res.ok) {
        return { ...indicator, status: 'unknown', reason: `http_${res.status}`,
          alertCount: null, topSeverity: null, latestAlert: null,
          source: 'trend_v1', cachedAt: Date.now() };
      }

      const data = await res.json();
      _setCached(cacheKey, data);
      return data;

    } catch (err) {
      const reason = err.name === 'AbortError' || err.name === 'TimeoutError'
        ? 'timeout' : 'network_error';
      return { ...indicator, status: 'unknown', reason,
        alertCount: null, topSeverity: null, latestAlert: null,
        source: 'trend_v1', cachedAt: Date.now() };
    }
  }

  // ── Public: search all relevant indicators from an article ─────────────────
  // onResult(indicator, data) is called for each indicator as it resolves.
  // If no indicators are found, onResult(null, null) is called once.

  async function searchArticle(article, onResult) {
    const indicators = _collectIndicators(article);
    if (!indicators.length) { onResult(null, null); return; }

    for (let i = 0; i < indicators.length; i++) {
      const data = await _fetchOne(indicators[i]);
      onResult(indicators[i], data);
      if (i < indicators.length - 1) await _delay(REQ_DELAY);
    }
  }

  // ── Public: indicator count for an article (used to show/hide button) ──────

  function hasIndicators(article) {
    return _collectIndicators(article).length > 0;
  }

  // ── Public: trigger search + render result block in article modal ───────────

  const _SEV_COLOR = { critical: '#f85149', high: '#f0883e', medium: '#d29922', low: '#3fb950' };
  const _TYPE_LABEL = { cve: 'CVE', ip: 'IP', hash: 'Hash', domain: 'Domain' };

  function _rowHTML(indicator, data) {
    const q     = indicator?.query || '—';
    const type  = indicator?.type  || '';
    const label = _TYPE_LABEL[type] || type;

    if (!data || data.status === 'unknown') {
      return `<div class="ts-row ts-unknown">
        <span class="ts-q" title="${label}">${q}</span>
        <span class="ts-badge ts-badge-unknown">? Trend unavailable</span>
      </div>`;
    }
    if (data.status === 'not_found') {
      return `<div class="ts-row ts-notfound">
        <span class="ts-q" title="${label}">${q}</span>
        <span class="ts-badge ts-badge-notfound">○ No Trend match</span>
      </div>`;
    }
    // found
    const sev   = (data.topSeverity || '').toLowerCase();
    const color = _SEV_COLOR[sev] || '#8b949e';
    const cnt   = data.alertCount ?? '?';
    const label2 = sev ? `${cnt} alert${cnt !== 1 ? 's' : ''} · ${sev}` : `${cnt} alert${cnt !== 1 ? 's' : ''}`;
    const name  = data.latestAlert?.name ? `title="${data.latestAlert.name.replace(/"/g, '&quot;')}"` : '';
    return `<div class="ts-row ts-found">
      <span class="ts-q" title="${label}">${q}</span>
      <span class="ts-badge ts-badge-found" style="color:${color}" ${name}>● ${label2}</span>
    </div>`;
  }

  function _triggerUI(article) {
    const block = document.getElementById('art-trend-search-result');
    if (!block) return;

    const indicators = _collectIndicators(article);
    if (!indicators.length) {
      block.style.display = 'none';
      return;
    }

    // Show loading state
    block.style.display = 'block';
    block.innerHTML = `
      <div class="ts-header">
        <span class="ts-title">🔵 Trend Vision One</span>
        <span class="ts-subtitle">Checking ${indicators.length} signal${indicators.length > 1 ? 's' : ''}…</span>
      </div>
      <div class="ts-rows" id="ts-rows-inner">
        ${indicators.map(ind => `
          <div class="ts-row ts-loading" id="ts-row-${ind.type}-${ind.query.replace(/[^a-z0-9]/gi, '')}">
            <span class="ts-q">${ind.query}</span>
            <span class="ts-badge ts-badge-loading">⟳</span>
          </div>`).join('')}
      </div>`;

    // Fire search and update each row as results arrive
    searchArticle(article, (indicator, data) => {
      if (!indicator) return; // no indicators case
      const safeId = `ts-row-${indicator.type}-${indicator.query.replace(/[^a-z0-9]/gi, '')}`;
      const row    = document.getElementById(safeId);
      if (row) row.outerHTML = _rowHTML(indicator, data);
    });
  }

  // ── Public: single-CVE search for use outside the article modal ─────────────
  // Returns the same result shape as _fetchOne. Uses the shared 1h cache.

  async function searchCVE(cveId) {
    return await _fetchOne({ query: cveId.toUpperCase(), type: 'cve' });
  }

  // ── Public: synchronous cache read — no network call ─────────────────────────
  // Returns cached data if a non-expired entry exists for this CVE, else null.
  // Used by the CVE table to restore visible result state on re-render.

  function getCachedCVE(cveId) {
    return _getCached(`cve:${cveId.toUpperCase()}`);
  }

  return { searchArticle, hasIndicators, _triggerUI, searchCVE, getCachedCVE };
})();
