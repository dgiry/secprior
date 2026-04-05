// watchlist-modal.js — Modal de gestion de la watchlist structurée V2
//
// Supporte le format V2 : { id, type, label, value, enabled, priority }
// Rétrocompatible avec l'ancien format string[] (migration transparente via contextualizer.js)
//
// Polish TV1 (v3) :
//   • Barre de filtres : Tous / Manuels / TV1 actifs / TV1 obsolètes
//   • Bannière "mode démo" si la dernière sync TV1 était une sync démo
//   • Action "Réactiver tous" sur le filtre TV1 obsolètes
//   • Les items manuels ne sont jamais touchés par reactivateObsolete()

const WatchlistModal = (() => {

  // ── État filtre ─────────────────────────────────────────────────────────────

  let _currentFilter = 'all'; // 'all' | 'manual' | 'tv1_active' | 'tv1_stale'

  // ── Ouvrir / fermer ─────────────────────────────────────────────────────────

  function open() {
    const modal = document.getElementById("modal-watchlist");
    if (!modal) return;
    _currentFilter = 'all'; // réinitialiser à chaque ouverture
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

  // ── Filtrage ────────────────────────────────────────────────────────────────

  function _applyFilter(list, filter) {
    switch (filter) {
      case 'manual':     return list.filter(i => i.source !== 'tv1');
      case 'tv1_active': return list.filter(i => i.source === 'tv1' && i.enabled);
      case 'tv1_stale':  return list.filter(i => i.source === 'tv1' && !i.enabled);
      default:           return list; // 'all'
    }
  }

  // ── Détection des termes sans correspondance dans le feed actuel ────────────

  function _buildMatchedIds() {
    const matched = new Set();
    try {
      const articles = Storage.getArticles();
      for (const a of articles) {
        if (Array.isArray(a.watchlistMatchItems)) {
          for (const m of a.watchlistMatchItems) {
            if (m.id) matched.add(m.id);
          }
        }
      }
    } catch { /* Storage non disponible — pas de marquage */ }
    return matched;
  }

  // ── Rendu principal ─────────────────────────────────────────────────────────

  function _render() {
    const allItems  = Contextualizer.getWatchlist();
    const container = document.getElementById("watchlist-items");
    if (!container) return;

    // ── Compteurs pour les badges de filtre ────────────────────────────────
    const counts = {
      all:        allItems.length,
      manual:     allItems.filter(i => i.source !== 'tv1').length,
      tv1_active: allItems.filter(i => i.source === 'tv1' && i.enabled).length,
      tv1_stale:  allItems.filter(i => i.source === 'tv1' && !i.enabled).length,
    };

    // ── Barre de filtres (injectée dans le container) ──────────────────────
    const FILTERS = [
      { key: 'all',        label: 'Tous'         },
      { key: 'manual',     label: 'Manuels'      },
      { key: 'tv1_active', label: 'TV1 actifs'   },
      { key: 'tv1_stale',  label: 'TV1 obsolètes'},
    ];

    const filterBar = FILTERS.map(f => {
      const active = _currentFilter === f.key ? ' wl-filter-active' : '';
      const n      = counts[f.key];
      const badge  = `<span class="wl-filter-count">${n}</span>`;
      return `<button class="wl-filter-btn${active}" onclick="WatchlistModal.setFilter('${f.key}')">${f.label}${badge}</button>`;
    }).join('');

    let html = `<div class="wl-filter-bar">${filterBar}</div>`;

    // ── Bannière mode démo TV1 ─────────────────────────────────────────────
    if (typeof TV1Sync !== 'undefined' && (counts.tv1_active + counts.tv1_stale) > 0) {
      const cfg = TV1Sync.loadConfig();
      if (cfg.lastSyncSource === 'tv1_demo') {
        html += `<div class="wl-demo-note">🔵 Les items TV1 affichés proviennent du jeu de données de démonstration, pas d'un inventaire réel. Ajoutez <code>TV1_API_KEY</code> dans Vercel pour activer la sync live.</div>`;
      }
    }

    // ── Termes avec au moins un hit dans le feed courant ──────────────────
    const matchedIds = _buildMatchedIds();

    // ── Appliquer le filtre ────────────────────────────────────────────────
    const list = _applyFilter(allItems, _currentFilter);

    // ── Bouton "Réactiver tous" — filtre TV1 obsolètes uniquement ──────────
    if (_currentFilter === 'tv1_stale' && list.length > 0) {
      html += `<div class="wl-reactivate-row">
        <span class="settings-hint" style="flex:1;margin:0">
          ${list.length} item${list.length > 1 ? 's' : ''} obsolète${list.length > 1 ? 's' : ''}
        </span>
        <button class="wl-reactivate-btn" onclick="WatchlistModal.reactivateObsolete()">
          ▶ Réactiver tous
        </button>
      </div>`;
    }

    // ── Contenu filtré ─────────────────────────────────────────────────────
    if (list.length === 0) {
      const EMPTY = {
        all:        'Aucun terme surveillé. Ajoutez des items ci-dessous.',
        manual:     'Aucun item manuel.',
        tv1_active: 'Aucun item TV1 actif.',
        tv1_stale:  '✓ Aucun item TV1 obsolète.',
      };
      html += `<span class="wl-empty">${EMPTY[_currentFilter] || EMPTY.all}</span>`;
      container.innerHTML = html;
      _updateBtn();
      return;
    }

    // Grouper par type
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
          ${items.map(i => _itemHTML(i, matchedIds)).join('')}
        </div>`;
    }).join('');

    html += sections;
    container.innerHTML = html;
    _updateBtn();
  }

  // ── Helpers de formatage des dates ──────────────────────────────────────

  /** Retourne "3 avril 2026" (fr-FR) depuis un ISO string. */
  function _fmtDate(iso) {
    try {
      return new Date(iso).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' });
    } catch { return iso.slice(0, 10); }
  }

  /** Retourne "il y a 3 j" / "il y a 2 h" / "il y a 5 min" depuis un ISO string. */
  function _relativeAge(iso) {
    try {
      const diff = Date.now() - new Date(iso).getTime();
      const days = Math.floor(diff / 86_400_000);
      const hrs  = Math.floor(diff / 3_600_000);
      const mins = Math.floor(diff / 60_000);
      if (days >= 1)  return `il y a ${days} j`;
      if (hrs  >= 1)  return `il y a ${hrs} h`;
      if (mins >= 1)  return `il y a ${mins} min`;
      return "à l'instant";
    } catch { return ''; }
  }

  function _itemHTML(item, matchedIds = new Set()) {
    const pMeta  = Contextualizer.WL_PRIORITIES[item.priority] || Contextualizer.WL_PRIORITIES.medium;
    const tMeta  = Contextualizer.WL_TYPES[item.type]          || Contextualizer.WL_TYPES.keyword;
    const idEsc  = item.id.replace(/'/g, "\\'");
    const lblEsc = (item.label || item.value || '').replace(/</g, '&lt;');
    const noMatch = item.enabled && matchedIds.size > 0 && !matchedIds.has(item.id);
    const cls    = [
      item.enabled ? 'wl-item' : 'wl-item wl-item-disabled',
      noMatch ? 'wl-item-quiet' : ''
    ].join(' ').trim();

    // TV1 badge — tooltip enrichi de la date d'obsolescence si disponible
    const staleDateFull = (item.source === 'tv1' && item.staleAt)
      ? ` — Obsolète depuis le ${_fmtDate(item.staleAt)}`
      : '';
    const tv1Badge = item.source === 'tv1'
      ? `<span class="wl-tv1-badge" title="Synced from Trend Vision One${staleDateFull}">TV1</span>`
      : '';

    // Indicateur d'obsolescence :
    //   • filtre tv1_stale → label complet visible "Obsolète depuis le 3 avril 2026"
    //   • autres filtres   → âge relatif compact "il y a 3 j" (ne surcharge pas la vue)
    let staleHint = '';
    if (item.source === 'tv1' && !item.enabled && item.staleAt) {
      if (_currentFilter === 'tv1_stale') {
        staleHint = `<span class="wl-stale-since">Obsolète depuis le ${_fmtDate(item.staleAt)}</span>`;
      } else {
        const age = _relativeAge(item.staleAt);
        if (age) staleHint = `<span class="wl-stale-age" title="Obsolète depuis le ${_fmtDate(item.staleAt)}">${age}</span>`;
      }
    }

    const noMatchBadge = noMatch
      ? `<span class="wl-no-match" title="No matches in current feed">—</span>`
      : '';

    return `
      <div class="${cls}" data-id="${item.id}">
        <span class="wl-prio-dot" title="Priority: ${pMeta.label}">${pMeta.dot}</span>
        <span class="wl-item-label" title="${item.value}">${lblEsc}</span>
        ${noMatchBadge}
        ${tv1Badge}
        ${staleHint}
        <span class="wl-item-type ${tMeta.css}">${tMeta.label}</span>
        <button class="wl-toggle-btn" onclick="WatchlistModal.toggle('${idEsc}')"
                title="${item.enabled ? 'Temporarily disable' : 'Re-enable'}">
          ${item.enabled ? '⏸' : '▶'}
        </button>
        <button class="wl-remove-btn" onclick="WatchlistModal.remove('${idEsc}')"
                title="Delete permanently">✕</button>
      </div>`;
  }

  // ── Actions ────────────────────────────────────────────────────────────────

  function setFilter(f) {
    _currentFilter = f;
    _render();
  }

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

  // ── Réactiver tous les items TV1 obsolètes ─────────────────────────────────
  //
  // Ne touche jamais aux items manuels (source !== 'tv1').
  // Supprime le marqueur staleAt et repasse enabled à true.

  function reactivateObsolete() {
    const wl = Contextualizer.getWatchlist();
    let count = 0;

    const updated = wl.map(item => {
      if (item.source !== 'tv1') return item; // jamais les manuels
      if (item.enabled) return item;           // déjà actif
      count++;
      const { staleAt, ...rest } = item;       // supprimer le marqueur obsolète
      return { ...rest, enabled: true };
    });

    if (count > 0) Contextualizer.saveWatchlist(updated);
    _render();
    if (count > 0) UI.showToast(
      `▶ ${count} item${count > 1 ? 's' : ''} TV1 réactivé${count > 1 ? 's' : ''}`,
      'success'
    );
    return count;
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
      ? `Watchlist: ${act} terme${act > 1 ? 's' : ''} actif${act > 1 ? 's' : ''}` +
        (total > act ? ` (${total - act} désactivé${total - act > 1 ? 's' : ''})` : '')
      : "Gérer la watchlist";

    const badge = document.getElementById("watchlist-count");
    if (badge) badge.textContent = act > 0 ? ` (${act})` : "";
  }

  // ── Sync depuis TV1 (appelé depuis le footer du modal watchlist) ─────────────

  async function syncFromTV1() {
    if (typeof TV1Sync === 'undefined') {
      UI.showToast('Module TV1 non chargé', 'error');
      return;
    }

    const btn = document.getElementById('btn-tv1-sync-wl');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Sync…'; }

    try {
      const result = await TV1Sync.fetchPreview();
      if (!result.items?.length) {
        UI.showToast('⚠ Aucun item retourné par TV1', 'warning');
        return;
      }

      // Avertissement si fallback démo suite à erreur d'auth
      if (result._authWarning) {
        UI.showToast(`⚠ ${result._authWarning}`, 'warning');
      }

      const stats  = TV1Sync.syncFull(result);
      _render(); // rafraîchir la liste après sync

      let msg = stats.added > 0
        ? `🔵 ${stats.added} item${stats.added !== 1 ? 's' : ''} ajouté${stats.added !== 1 ? 's' : ''} depuis TV1`
        : `ℹ Tous les items TV1 déjà présents`;
      if (stats.skipped)  msg += ` · ${stats.skipped} déjà présent${stats.skipped > 1 ? 's' : ''}`;
      if (stats.disabled) msg += ` · ${stats.disabled} désactivé${stats.disabled > 1 ? 's' : ''} (obsolètes)`;
      UI.showToast(msg, stats.added > 0 ? 'success' : 'info');

    } catch (err) {
      UI.showToast(`⚠ Sync TV1 échouée : ${err.message}`, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '🔵 Sync from TV1'; }
    }
  }

  // ── Refresh public (appelé par TV1Sync après import) ────────────────────────

  function refresh() {
    _render();
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

  return { open, close, add, remove, toggle, setFilter, reactivateObsolete, refresh, syncFromTV1, init };
})();
