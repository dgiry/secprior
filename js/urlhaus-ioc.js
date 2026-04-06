// js/urlhaus-ioc.js — URLhaus IOC lookup layer
//
// URLhaus is NOT injected as feed articles. Instead it is loaded once as a
// background IOC dictionary and used to cross-reference domains and URLs
// extracted from other feed articles by IOCExtractor.enrichArticle().
//
// When a domain or URL found in a regular RSS article matches a URLhaus entry,
// the IOC panel shows: ☣️ URLhaus confirmed — malware_download · exe, trojan
//
// Usage (called automatically):
//   await URLhausIOC.init()       — fetch & build lookup maps (idempotent)
//   URLhausIOC.lookupDomain(d)    — { threat, tags, status, link } | null
//   URLhausIOC.lookupUrl(u)       — { threat, tags, status, link } | null
//   URLhausIOC.isReady()          — true once maps are populated

const URLhausIOC = (() => {
  'use strict';

  // Internal state
  const _domains = new Map(); // hostname (lowercase) → entry
  const _urls    = new Map(); // full url → entry
  let   _ready   = false;
  let   _loading = false;     // prevent concurrent init() calls

  /**
   * Fetch URLhaus IOC map from the backend and populate lookup maps.
   * Idempotent — subsequent calls return immediately if already loaded.
   * Requires URLHAUS_AUTH_KEY configured (UI or Vercel env var).
   */
  async function init() {
    if (_ready || _loading) return;
    if (typeof CONFIG === 'undefined' || !CONFIG.USE_API) return; // static mode: no backend

    const key = localStorage.getItem('cv_urlhaus_auth_key') || '';
    // If no UI key and no env var configured, skip silently.
    // (Backend handles missing env var gracefully with skipped:true)

    _loading = true;
    try {
      const res = await fetch('/api/fetch-feeds?urlhaus=1', {
        headers: key ? { 'X-URLhaus-Key': key } : {},
        signal:  AbortSignal.timeout(25_000)
      });

      if (!res.ok) {
        console.warn('[URLhausIOC] backend error HTTP', res.status);
        return;
      }

      const data = await res.json();

      if (data.skipped) {
        console.log('[URLhausIOC] skipped —', data.reason || 'no key configured');
        return;
      }

      if (data.error) {
        console.warn('[URLhausIOC] error:', data.error);
        return;
      }

      const { domains = {}, urls = {} } = data.iocMap || {};

      Object.entries(domains).forEach(([k, v]) => _domains.set(k.toLowerCase(), v));
      Object.entries(urls).forEach(([k, v])    => _urls.set(k, v));

      _ready = true;
      console.log(`[URLhausIOC] ready — ${_domains.size} domains, ${_urls.size} URLs indexed`);

    } catch (err) {
      console.warn('[URLhausIOC] init failed:', err.message);
    } finally {
      _loading = false;
    }
  }

  /**
   * Look up a domain (exact match or parent domain).
   * e.g. "sub.evil.com" will also match if "evil.com" is in the map.
   * @returns {{ threat, tags, status, link }} | null
   */
  function lookupDomain(domain) {
    if (!domain || !_ready) return null;
    const lower = domain.toLowerCase();
    if (_domains.has(lower)) return _domains.get(lower);
    // Check parent domain (e.g. sub.evil.com → evil.com)
    const parts = lower.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join('.');
      if (_domains.has(parent)) return _domains.get(parent);
    }
    return null;
  }

  /**
   * Look up a full URL (exact match).
   * @returns {{ threat, tags, status, link }} | null
   */
  function lookupUrl(url) {
    if (!url || !_ready) return null;
    return _urls.get(url) || null;
  }

  /** True once the lookup maps have been populated. */
  function isReady() { return _ready; }

  return { init, lookupDomain, lookupUrl, isReady };
})();
