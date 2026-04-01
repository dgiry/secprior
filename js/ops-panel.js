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
    _box.style.display = 'none';
    _box.innerHTML = `
      <div class="ops-hd">
        <span class="ops-title">🧩 Ops / Debug</span>
        <button id="ops-close" class="ops-close" title="Fermer">✕</button>
      </div>
      <div class="ops-body" id="ops-body">
        <div class="ops-row"><span class="ops-k">Mode source</span><span class="ops-v" id="ops-source-mode">—</span></div>
        <div class="ops-row"><span class="ops-k">Flux actifs</span><span class="ops-v" id="ops-feed-count">—</span></div>
        <div class="ops-row"><span class="ops-k">Articles</span><span class="ops-v" id="ops-article-count">—</span></div>
        <div class="ops-row"><span class="ops-k">Dernier refresh</span><span class="ops-v" id="ops-last-refresh">—</span></div>
        <div class="ops-row"><span class="ops-k">NVD</span><span class="ops-v" id="ops-nvd">—</span></div>
        <div class="ops-row"><span class="ops-k">KEV reverse match</span><span class="ops-v" id="ops-kev">—</span></div>
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
  function update({ sourceMode, feedCount, articleCount, lastRefreshAt, nvd, kev }) {
    _ensureBox();
    const s = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    if (sourceMode)   s('ops-source-mode', sourceMode);
    if (feedCount!=null)    s('ops-feed-count', String(feedCount));
    if (articleCount!=null) s('ops-article-count', String(articleCount));
    if (lastRefreshAt) s('ops-last-refresh', _fmt(lastRefreshAt));
    if (nvd)           s('ops-nvd', nvd);
    if (kev!=null)     s('ops-kev', String(kev));
  }

  function init() {
    _ensureBox();
    let was = null; try { was = localStorage.getItem(KEY); } catch {}
    if (was === '1') show();
  }

  return { init, toggle, update };
})();
