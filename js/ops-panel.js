// ops-panel.js — Panneau léger Ops / Debug (signaux santé/runtime)

const OpsPanel = (() => {
  let _box = null;
  let _visible = false;
  const KEY = 'cv_ops_panel_visible';

  function _ensureBox() {
    if (_box) return _box;
    _box = document.createElement('div');
    _box.id = 'ops-panel';
    _box.className = 'ops-panel';
    // Style inline minimal pour assurer la visibilité sans CSS global
    _box.style.display = 'none';
    _box.style.position = 'fixed';
    _box.style.right = '12px';
    _box.style.bottom = '12px';
    _box.style.zIndex = '9999';
    _box.style.background = '#0d1117';
    _box.style.border = '1px solid #30363d';
    _box.style.borderRadius = '8px';
    _box.style.padding = '8px 10px';
    _box.style.minWidth = '260px';
    _box.style.maxWidth = '360px';
    _box.style.color = '#c9d1d9';
    _box.style.fontSize = '.85rem';
    _box.style.boxShadow = '0 8px 24px rgba(0,0,0,.35)';
    _box.innerHTML = `
      <div class="ops-hd" style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;gap:8px">
        <span class="ops-title" style="font-weight:600">🧩 Ops / Debug</span>
        <button id="ops-close" class="ops-close" title="Fermer" style="background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:2px 8px;font-size:.8rem;cursor:pointer">✕</button>
      </div>
      <div class="ops-body" id="ops-body" style="display:flex;flex-direction:column;gap:6px">
        <!-- Source / Feeds / Articles -->
        <div class="ops-row" style="display:flex;align-items:center;justify-content:space-between;gap:8px"><span class="ops-k" style="opacity:.8">Mode source</span><span class="ops-v" id="ops-source-mode" style="font-variant-numeric:tabular-nums">—</span></div>
        <div class="ops-row" style="display:flex;align-items:center;justify-content:space-between;gap:8px"><span class="ops-k" style="opacity:.8">Flux actifs</span><span class="ops-v" id="ops-feed-count" style="font-variant-numeric:tabular-nums">—</span></div>
        <div class="ops-row" style="display:flex;align-items:center;justify-content:space-between;gap:8px"><span class="ops-k" style="opacity:.8">Articles</span><span class="ops-v" id="ops-article-count" style="font-variant-numeric:tabular-nums">—</span></div>
        <div class="ops-row" style="display:flex;align-items:center;justify-content:space-between;gap:8px"><span class="ops-k" style="opacity:.8">Dernier refresh</span><span class="ops-v" id="ops-last-refresh" style="font-variant-numeric:tabular-nums">—</span></div>

        <!-- Séparateur -->
        <div style="border-top:1px solid #30363d;margin:4px 0"></div>

        <!-- Signal quality — Validating contextual/environment signals -->
        <div style="font-size:.8rem;opacity:.7;font-weight:600;margin-top:2px">Signal quality</div>
        <div class="ops-row" style="display:flex;align-items:center;justify-content:space-between;gap:8px"><span class="ops-k" style="opacity:.8">Matches you</span><span class="ops-v" id="ops-matches-you" style="font-variant-numeric:tabular-nums">—</span></div>
        <div class="ops-row" style="display:flex;align-items:center;justify-content:space-between;gap:8px"><span class="ops-k" style="opacity:.8">Watchlist</span><span class="ops-v" id="ops-watchlist" style="font-variant-numeric:tabular-nums">—</span></div>
        <div class="ops-row" style="display:flex;align-items:center;justify-content:space-between;gap:8px"><span class="ops-k" style="opacity:.8">Exposed vendor</span><span class="ops-v" id="ops-exposed-vendor" style="font-variant-numeric:tabular-nums">—</span></div>
        <div class="ops-row" style="display:flex;align-items:center;justify-content:space-between;gap:8px"><span class="ops-k" style="opacity:.8">KEV reverse match</span><span class="ops-v" id="ops-kev" style="font-variant-numeric:tabular-nums">—</span></div>
        <div class="ops-row" style="display:flex;align-items:center;justify-content:space-between;gap:8px"><span class="ops-k" style="opacity:.8">NVD status</span><span class="ops-v" id="ops-nvd">—</span></div>
      </div>`;
    document.body.appendChild(_box);
    document.getElementById('ops-close')?.addEventListener('click', hide);
    return _box;
  }

  function show() {
    _ensureBox();
    _visible = true;
    try { localStorage.setItem(KEY, '1'); } catch {}
    _box.style.display = 'block';
  }
  function hide() {
    _visible = false;
    try { localStorage.removeItem(KEY); } catch {}
    if (_box) _box.style.display = 'none';
  }
  function toggle() { (_visible ? hide : show)(); }

  function _fmt(dt) {
    try { return new Date(dt).toLocaleString('fr-CA'); } catch { return '—'; }
  }

  // API de mise à jour — App et autres modules envoient des signaux
  function update({ sourceMode, feedCount, articleCount, lastRefreshAt, nvd, kev, environmentContextStats }) {
    _ensureBox();
    const s = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    if (sourceMode)   s('ops-source-mode', sourceMode);
    if (feedCount!=null)    s('ops-feed-count', String(feedCount));
    if (articleCount!=null) s('ops-article-count', String(articleCount));
    if (lastRefreshAt) s('ops-last-refresh', _fmt(lastRefreshAt));
    if (nvd)           s('ops-nvd', nvd);
    if (kev!=null)     s('ops-kev', String(kev));

    // Signal quality indicators (environment context status distribution)
    if (environmentContextStats) {
      const stats = environmentContextStats;
      s('ops-matches-you', String(stats.matches_you || 0));
      s('ops-watchlist', String(stats.watchlist || 0));
      s('ops-exposed-vendor', String(stats.exposed_vendor || 0));
    }
  }

  function init() {
    _ensureBox();
    let was = null; try { was = localStorage.getItem(KEY); } catch {}
    if (was === '1') show();
  }

  return { init, toggle, update };
})();
