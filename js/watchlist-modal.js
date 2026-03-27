// watchlist-modal.js — Modal de gestion de la watchlist structurée V2
//
// Supporte le format V2 : { id, type, label, value, enabled, priority }
// Rétrocompatible avec l'ancien format string[] (migration transparente via contextualizer.js)

const WatchlistModal = (() => {

  function open() {
    const modal = document.getElementById("modal-watchlist");
    if (!modal) return;
    _render();
    modal.style.display = "flex";
    document.body.style.overflow = "hidden";
    document.getElementById("watchlist-input")?.focus();
  }

  function close() {
    const modal = document.getElementById("modal-watchlist");
    if (modal) modal.style.display = "none";
    document.body.style.overflow = "";
  }

  // ── Rendu de la liste ──────────────────────────────────────────────────────

  function _render() {
    const list      = Contextualizer.getWatchlist();
    const container = document.getElementById("watchlist-items");
    if (!container) return;

    if (list.length === 0) {
      container.innerHTML = `<span class="wl-empty">Aucun terme surveillé. Ajoutez des éléments ci-dessous.</span>`;
    } else {
      // Grouper par type pour une lecture plus propre
      const byType = {};
      list.forEach(item => {
        if (!byType[item.type]) byType[item.type] = [];
        byType[item.type].push(item);
      });

      const ORDER = ['vendor', 'product', 'technology', 'keyword'];
      const sections = ORDER.filter(t => byType[t]).map(type => {
        const meta  = Contextualizer.WL_TYPES[type];
        const items = byType[type];
        return `
          <div class="wl-group">
            <div class="wl-group-label ${meta.css}">${meta.label}</div>
            ${items.map(_itemHTML).join('')}
          </div>`;
      }).join('');

      container.innerHTML = sections;
    }

    _updateBtn();
  }

  function _itemHTML(item) {
    const pMeta  = Contextualizer.WL_PRIORITIES[item.priority] || Contextualizer.WL_PRIORITIES.medium;
    const tMeta  = Contextualizer.WL_TYPES[item.type]          || Contextualizer.WL_TYPES.keyword;
    const idEsc  = item.id.replace(/'/g, "\\'");
    const lblEsc = (item.label || item.value || '').replace(/</g, '&lt;');
    const cls    = item.enabled ? 'wl-item' : 'wl-item wl-item-disabled';
    return `
      <div class="${cls}" data-id="${item.id}">
        <span class="wl-prio-dot" title="Priorité : ${pMeta.label}">${pMeta.dot}</span>
        <span class="wl-item-label" title="${item.value}">${lblEsc}</span>
        <span class="wl-item-type ${tMeta.css}">${tMeta.label}</span>
        <button class="wl-toggle-btn" onclick="WatchlistModal.toggle('${idEsc}')"
                title="${item.enabled ? 'Désactiver temporairement' : 'Réactiver'}">
          ${item.enabled ? '⏸' : '▶'}
        </button>
        <button class="wl-remove-btn" onclick="WatchlistModal.remove('${idEsc}')"
                title="Supprimer définitivement">✕</button>
      </div>`;
  }

  // ── Actions ────────────────────────────────────────────────────────────────

  function add() {
    const input  = document.getElementById("watchlist-input");
    const typeEl = document.getElementById("watchlist-type");
    const prioEl = document.getElementById("watchlist-priority");
    if (!input) return;

    const term = input.value.trim();
    if (!term) return;

    Contextualizer.addToWatchlist(term, {
      type:     typeEl?.value || 'keyword',
      priority: prioEl?.value || 'medium',
      label:    term
    });

    input.value = "";
    _render();
  }

  function remove(id) {
    Contextualizer.removeFromWatchlist(id);
    _render();
  }

  function toggle(id) {
    const list = Contextualizer.getWatchlist();
    const item = list.find(i => i.id === id);
    if (!item) return;
    Contextualizer.updateItem(id, { enabled: !item.enabled });
    _render();
  }

  // ── Compteur bouton navbar ─────────────────────────────────────────────────

  function _updateBtn() {
    const list  = Contextualizer.getWatchlist();
    const total = list.length;
    const act   = list.filter(i => i.enabled).length;

    const btn = document.getElementById("btn-watchlist");
    if (!btn) return;
    btn.classList.toggle("active", act > 0);
    btn.title = act > 0
      ? `Watchlist : ${act} terme${act > 1 ? 's' : ''} actif${act > 1 ? 's' : ''}` +
        (total > act ? ` (${total - act} désactivé${total - act > 1 ? 's' : ''})` : '')
      : "Gérer la watchlist";

    const badge = document.getElementById("watchlist-count");
    if (badge) badge.textContent = act > 0 ? ` (${act})` : "";
  }

  // ── Init ───────────────────────────────────────────────────────────────────

  function init() {
    document.getElementById("btn-watchlist")?.addEventListener("click", open);
    document.getElementById("watchlist-input")?.addEventListener("keydown", e => {
      if (e.key === "Enter") add();
    });
    document.addEventListener("keydown", e => {
      if (e.key === "Escape") close();
    });
    _updateBtn();
  }

  return { open, close, add, remove, toggle, init };
})();
