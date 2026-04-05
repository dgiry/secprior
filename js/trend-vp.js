// trend-vp.js — Trend Vision One Virtual Patch Availability (read-only)
//
// Queries the Trend Vision One IPS filter catalog to determine whether
// a virtual patch (IPS rule / Digital Vaccine filter) exists for a given CVE.
//
// Signal semantics:
//   available     — Trend has published a filter for this CVE
//   not_available — CVE known to the API but no filter published yet
//   unknown       — API not configured, error, or CVE not in catalog
//
// This is strictly read-only enrichment. No deployment, no write-back.
//
// Pattern mirrors nvd.js:
//   - 24h localStorage cache (cv_trend_vp_cache)
//   - 300ms inter-request delay (Vision One: ~300 req/min)
//   - Dual endpoint: /api/trend-vp (Vercel, key server-side)
//                    or direct V1 API (local, key from config)
//   - 429 backoff with Retry-After header support
//
// Enable: in the Integrations tab → Trend Vision One section, toggle "Virtual Patch".
// TV1Sync.loadConfig().vpEnabled is the gate; API key lives in Vercel env var TV1_API_KEY.
// Without the toggle the module is completely silent (no badges, no errors).

const TrendVP = (() => {
  'use strict';

  const CACHE_KEY = 'cv_trend_vp_cache';
  const CACHE_TTL = 24 * 60 * 60 * 1000; // 24h — VP catalog changes slowly
  const REQ_DELAY = 300;                  // ms between requests (~300 req/min)

  let backoffUntil = 0;

  const _delay = ms => new Promise(r => setTimeout(r, ms));

  // ── Cache LocalStorage ─────────────────────────────────────────────────────

  function _getCache() {
    try {
      const raw = localStorage.getItem(CACHE_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch { return {}; }
  }

  function _saveCache(data) {
    try { localStorage.setItem(CACHE_KEY, JSON.stringify(data)); }
    catch (e) { console.warn('[TrendVP] Cache write failed:', e.message); }
  }

  function _getCached(cveId) {
    const cache = _getCache();
    const entry = cache[cveId.toUpperCase()];
    if (!entry) return null;
    if (Date.now() - entry.cachedAt > CACHE_TTL) return null; // expired
    return entry.data;
  }

  function _setCached(cveId, data) {
    const cache = _getCache();
    cache[cveId.toUpperCase()] = { data, cachedAt: Date.now() };
    // Prune: keep max 1000 entries (FIFO by cachedAt)
    const keys = Object.keys(cache);
    if (keys.length > 1000) {
      keys.sort((a, b) => cache[a].cachedAt - cache[b].cachedAt)
          .slice(0, keys.length - 1000)
          .forEach(k => delete cache[k]);
    }
    _saveCache(cache);
  }

  // ── Response parser ────────────────────────────────────────────────────────
  // Vision One IPS filter search returns:
  //   { items: [ { id, name, cveIds: [...], publishedAt, severity, ... } ] }

  function _parseResponse(cveId, json) {
    const items = json?.items || [];
    const upper = cveId.toUpperCase();
    const hit   = items.find(f =>
      (f.cveIds || []).some(c => c.toUpperCase() === upper)
    );

    if (!hit) {
      return { cveId, status: 'not_available', source: 'trend_v1', cachedAt: Date.now() };
    }
    return {
      cveId,
      status:      'available',
      filterId:    String(hit.id   || ''),
      filterName:  hit.name        || '',
      publishedAt: hit.publishedAt || null,
      source:      'trend_v1',
      cachedAt:    Date.now()
    };
  }

  // ── Fetch one CVE ──────────────────────────────────────────────────────────

  async function _fetchFilter(cveId) {
    const cached = _getCached(cveId);
    if (cached) return cached;

    // Endpoint routing: always /api/trend-vp (key stays server-side on Vercel).
    // Region comes from the existing TV1Sync config (Integrations tab).
    const region  = (typeof TV1Sync !== 'undefined' ? TV1Sync.loadConfig()?.region : null) || 'us';
    const url     = `/api/trend-vp?cveId=${encodeURIComponent(cveId)}&region=${encodeURIComponent(region)}`;
    const headers = {};

    try {
      const res = await fetch(url, { headers, signal: AbortSignal.timeout(10_000) });

      if (res.status === 429) {
        const ra = parseInt(res.headers.get('Retry-After') || '60', 10);
        backoffUntil = Date.now() + (isNaN(ra) ? 60_000 : ra * 1000);
        return { cveId, status: 'unknown', source: 'trend_v1', cachedAt: Date.now() };
      }

      if (!res.ok) {
        // 403 = insufficient token scope; 404 = CVE unknown to catalog — both → unknown
        return { cveId, status: 'unknown', source: 'trend_v1', cachedAt: Date.now() };
      }

      const json = await res.json();
      return _parseResponse(cveId, json);

    } catch {
      // Timeout, network error, parse error — degrade silently
      return { cveId, status: 'unknown', source: 'trend_v1', cachedAt: Date.now() };
    }
  }

  // ── Public enrichment entry point ─────────────────────────────────────────
  // Called from app.js enrichWithTrendVP(), mirrors NVD.enrichArticles pattern.
  // onEnrich(cveId, vpData) is called for every CVE processed.

  async function enrichCVEs(cveIds, onEnrich) {
    if (typeof TV1Sync === 'undefined' || !TV1Sync.loadConfig()?.vpEnabled) return;
    if (!cveIds || !cveIds.length) return;

    const unique = [...new Set(cveIds.map(c => c.toUpperCase()))];

    for (const cveId of unique) {
      if (backoffUntil > Date.now()) await _delay(backoffUntil - Date.now());

      try {
        const data = await _fetchFilter(cveId);
        _setCached(cveId, data);
        onEnrich(cveId, data);
      } catch {}

      await _delay(REQ_DELAY);
    }
  }

  // ── Cache statistics ──────────────────────────────────────────────────────
  // Returns a snapshot of the current VP cache for display in the Integrations tab.
  // { total, available, notAvailable, unknown, newestAt }
  function getStats() {
    const cache   = _getCache();
    const entries = Object.values(cache);
    const valid   = entries.filter(e => Date.now() - e.cachedAt <= CACHE_TTL);

    let available = 0, notAvailable = 0, unknown = 0, newestAt = null;
    for (const e of valid) {
      if (e.data?.status === 'available')     available++;
      else if (e.data?.status === 'not_available') notAvailable++;
      else                                    unknown++;
      if (!newestAt || e.cachedAt > newestAt) newestAt = e.cachedAt;
    }
    return { total: valid.length, available, notAvailable, unknown, newestAt };
  }

  return { enrichCVEs, getStats };
})();
