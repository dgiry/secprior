// persona-presets.js v7 — Vues métier persona SecPrior
//
// Injecte une barre compacte de vues persona en dessous de la barre Risque Réel.
// Chaque vue active un ensemble cohérent de filtres et ouvre le bon panneau.
// Les saved-filters utilisateur ne sont pas touchés — ce sont deux systèmes distincts.
//
// v7 — Persistance localStorage + restore avant/après refresh + onboarding integration
//   pickAndActivate(id)       — onboarding: seed watchlist + activate + persist
//   silentRestoreFilters()    — avant refresh: applique filtres sans toast ni panel
//   silentRestorePanel()      — après refresh: ouvre le bon panneau
//
// Vues disponibles :
//   🔴 Analyste SOC    — incidents actifs, workflow investigating
//   🔍 Vuln Mgmt       — CVEs KEV/EPSS, focus correctifs
//   📊 RSSI / CISO     — posture globale, vue synthétique
//   🏢 MSSP            — incidents multi-source, watchlist
//   🚨 Top priorités   — Critical Now des dernières 24h

const PersonaPresets = (() => {

  let _activeId = null;

  const PERSONA_KEY = 'cv_active_persona';

  // ── Graines watchlist par persona (seed si watchlist vide au premier lancement) ─
  const WATCHLIST_SEEDS = {
    today: ['ransomware', 'zero-day', 'actively exploited', 'CISA KEV', 'critical vulnerability'],
    soc:   ['phishing', 'exploitation', 'lateral movement', 'backdoor', 'C2', 'incident response'],
    vuln:  ['CVE', 'patch', 'CVSS', 'NVD', 'advisory', 'privilege escalation', 'unpatched'],
    ciso:  ['breach', 'supply chain', 'nation-state', 'APT', 'data leak', 'regulatory'],
    mssp:  ['campaign', 'threat actor', 'IOC', 'multi-source', 'watchlist', 'exposure']
  };

  // ── Filtres par persona (séparés de apply() pour restore pré-refresh) ────
  const PERSONA_FILTERS = {
    today: { priorityLevel: 'critical_now', sortBy: 'priority', date: '24h' },
    soc:   { priorityLevel: 'all',          sortBy: 'priority' },
    vuln:  { priorityLevel: 'all',          sortBy: 'priority' },
    ciso:  { priorityLevel: 'critical_now', sortBy: 'priority' },
    mssp:  { priorityLevel: 'all',          sortBy: 'priority' }
  };

  // ── Panel associé à chaque persona ───────────────────────────────────────
  const PERSONA_PANEL = {
    today: 'main',
    soc:   'incidents',
    vuln:  'cves',
    ciso:  'visibility',
    mssp:  'incidents'
  };

  // ── Définitions des vues persona ─────────────────────────────────────────

  const PERSONAS = [
    {
      id:   'soc',
      icon: '🔴',
      name: 'SOC Analyst',
      desc: 'All incidents sorted by priority · wide analyst view',
      apply() {
        // Vue SOC Analyst : tri par priorité, sans muter la configuration des flux.
        // Applique un masque de vue non persistant côté FeedManager (categories include)
        _setAppFilters({ priorityLevel: 'all', sortBy: 'priority' });
        if (typeof FeedManager !== 'undefined')
          FeedManager.setViewCategoryInclude(['operational', 'cti_campaigns']);
        _openPanel('incidents');
        if (typeof IncidentPanel !== 'undefined')
          IncidentPanel.setFilters({ filterBy: 'all', sortBy: 'priority', statusFilter: 'all' });
      }
    },
    {
      id:   'vuln',
      icon: '🔍',
      name: 'Vuln Mgmt',
      desc: 'Priority KEV and EPSS CVEs · patch focus',
      apply() {
        _setAppFilters({ priorityLevel: 'all', sortBy: 'priority' });
        _openPanel('cves');
        if (typeof CVEPanel !== 'undefined')
          CVEPanel.setFilters({ filterBy: 'kev' });
      }
    },
    {
      id:   'ciso',
      icon: '📊',
      name: 'CISO / Manager',
      desc: 'Global posture · synthetic view · top incidents',
      apply() {
        _setAppFilters({ priorityLevel: 'critical_now', sortBy: 'priority' });
        _openPanel('visibility');
      }
    },
    {
      id:   'mssp',
      icon: '🏢',
      name: 'MSSP',
      desc: 'Multi-source incidents · active watchlist',
      apply() {
        _setAppFilters({ priorityLevel: 'all', sortBy: 'priority' });
        _openPanel('incidents');
        if (typeof IncidentPanel !== 'undefined')
          IncidentPanel.setFilters({ filterBy: 'multi', sortBy: 'priority' });
      }
    },
    {
      id:   'today',
      icon: '🚨',
      name: 'Top priorities',
      desc: 'Critical Now of the last 24h · immediate action',
      apply() {
        _setAppFilters({ priorityLevel: 'critical_now', sortBy: 'priority', date: '24h' });
        // Masque de vue: conserver s'il existe (ne pas écraser), mais n'en impose pas un nouveau ici
        _openPanel('main');
      }
    }
  ];

  // ── Table de navigation des panneaux ─────────────────────────────────────

  const _PANEL_MAP = [
    { id: 'stats-panel',      view: 'stats',      mod: () => typeof StatsPanel      !== 'undefined' ? StatsPanel      : null },
    { id: 'briefing-panel',   view: 'briefing',   mod: () => typeof BriefingPanel   !== 'undefined' ? BriefingPanel   : null },
    { id: 'health-panel',     view: 'health',     mod: () => typeof HealthPanel     !== 'undefined' ? HealthPanel     : null },
    { id: 'vendor-panel',     view: 'vendors',    mod: () => typeof VendorPanel     !== 'undefined' ? VendorPanel     : null },
    { id: 'cve-panel',        view: 'cves',       mod: () => typeof CVEPanel        !== 'undefined' ? CVEPanel        : null },
    { id: 'incident-panel',   view: 'incidents',  mod: () => typeof IncidentPanel   !== 'undefined' ? IncidentPanel   : null },
    { id: 'visibility-panel', view: 'visibility', mod: () => typeof VisibilityPanel !== 'undefined' ? VisibilityPanel : null },
  ];

  // ── Helpers navigation ────────────────────────────────────────────────────

  function _closeAllPanels() {
    _PANEL_MAP.forEach(({ id, mod }) => {
      const el = document.getElementById(id);
      if (el && el.style.display !== 'none') mod()?.toggle?.();
    });
  }

  function _openPanel(view) {
    if (view === 'main') {
      _closeAllPanels();
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }

    const entry = _PANEL_MAP.find(p => p.view === view);
    if (!entry) return;

    // Fermer tous les autres panneaux d'abord
    _PANEL_MAP.forEach(({ id, view: pView, mod }) => {
      if (pView === view) return;
      const el = document.getElementById(id);
      if (el && el.style.display !== 'none') mod()?.toggle?.();
    });

    // Ouvrir le panneau cible s'il est fermé
    const targetEl = document.getElementById(entry.id);
    if (targetEl && targetEl.style.display === 'none') {
      entry.mod()?.toggle?.();
    }

    // Scroll vers le panneau
    requestAnimationFrame(() => {
      document.getElementById(entry.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  // ── Helpers filtres ───────────────────────────────────────────────────────

  // Applique un ensemble de filtres sur le dashboard principal.
  // Remet à zéro les filtres non fournis pour partir d'un état propre.
  function _setAppFilters(overrides) {
    if (typeof App === 'undefined') return;
    const defaults = {
      query:        '',
      criticality:  'all',
      source:       'all',
      date:         'all',
      priorityLevel:'all',
      sortBy:       'default',
      statusFilter: 'all',
      showFavOnly:  false
    };
    App.setFilters({ ...defaults, ...overrides });
  }

  // ── Helpers feed categorization (SOC/CISO views) ──────────────────────────

  /**
   * Retourne les IDs des flux à activer pour une catégorie donnée.
   * Utilisé par les personas pour filtrer les sources par contexte.
   * @param {string|string[]} categories - "operational" | "cti_campaigns" | "strategic" ou tableau
   * @returns {Set<string>} Ensemble des IDs de flux correspondants
   */
  function _getFeedIdsByCategory(categories) {
    if (!Array.isArray(categories)) categories = [categories];
    const feedIds = new Set();
    
    if (typeof FeedManager === 'undefined') return feedIds;
    
    const allFeeds = FeedManager.getAllFeeds();
    allFeeds.forEach(feed => {
      const cat = FeedManager.getCategoryForFeed(feed);
      if (categories.includes(cat)) {
        feedIds.add(feed.id);
      }
    });
    
    return feedIds;
  }

  /**
   * Active/désactive les flux selon les catégories demandées.
   * Utilisé par les personas pour configurer les sources visibles.
   * @param {string|string[]} categoriesToEnable - Catégories à activer
   * @param {boolean} disableOthers - Si true, désactive les autres catégories
   */
  function _applyFeedCategoryFilter(categoriesToEnable, disableOthers = true) {
    if (typeof FeedManager === 'undefined') return;
    
    const enabledIds = _getFeedIdsByCategory(categoriesToEnable);
    const allFeeds = FeedManager.getAllFeeds();
    
    allFeeds.forEach(feed => {
      const shouldEnable = enabledIds.has(feed.id);
      const isCurrentlyEnabled = feed.enabled;
      
      // Changer l'état seulement si nécessaire
      if (disableOthers && shouldEnable !== isCurrentlyEnabled) {
        FeedManager.toggleFeed(feed.id, shouldEnable);
      } else if (!disableOthers && shouldEnable && !isCurrentlyEnabled) {
        FeedManager.toggleFeed(feed.id, true);
      }
    });
  }

  // ── Activation / reset ────────────────────────────────────────────────────

  function _activate(id) {
    const persona = PERSONAS.find(p => p.id === id);
    if (!persona) return;

    _activeId = id;
    try { localStorage.setItem(PERSONA_KEY, id); } catch {}
    try {
      persona.apply();
    } catch (err) {
      console.warn('[PersonaPresets] Erreur activation persona:', err);
    }
    _render();
    // Sync ligne persona dans la barre profil (Sprint 24)
    if (typeof ProfileSwitcher !== 'undefined') ProfileSwitcher.render();

    if (typeof UI !== 'undefined')
      UI.showToast(`${persona.icon} View "${persona.name}" activated`, 'success');
  }

  function _reset() {
    _activeId = null;
    try { localStorage.removeItem(PERSONA_KEY); } catch {}
    _setAppFilters({});     // → tous les filtres à their defaults
    // Retirer tout masque de vue appliqué par une persona
    if (typeof FeedManager !== 'undefined') FeedManager.clearViewCategoryMask();
    _closeAllPanels();
    _render();
    // Sync ligne persona dans la barre profil (Sprint 24)
    if (typeof ProfileSwitcher !== 'undefined') ProfileSwitcher.render();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // ── Onboarding integration ─────────────────────────────────────────────
  // Seed la watchlist du profil actif si elle est vide, puis active le persona.
  // Appelé par l'overlay onboarding au choix de persona.
  function pickAndActivate(id) {
    // Seed watchlist si vide (uniquement au premier choix)
    if (typeof ProfileManager !== 'undefined') {
      const wl = ProfileManager.getActiveWatchlist();
      if (!Array.isArray(wl) || wl.length === 0) {
        const seeds = WATCHLIST_SEEDS[id] || [];
        const items = seeds.map((kw, i) => ({
          id:      `wl_seed_${id}_${i}`,
          type:    'keyword',
          label:   kw,
          value:   kw,
          enabled: true,
          priority:'medium'
        }));
        if (items.length > 0) ProfileManager.saveActiveWatchlist(items);
      }
    }
    _activate(id); // persiste, toast, filtre, rendu
  }

  // ── Restore split (avant / après refresh) ─────────────────────────────
  // silentRestoreFilters() — appelé AVANT refresh() dans app.init()
  //   → applique les filtres du persona stocké sans ouvrir de panneau
  //   → évite le flash "all articles" avant le premier rendu
  function silentRestoreFilters() {
    let id;
    try { id = localStorage.getItem(PERSONA_KEY); } catch {}

    // Premier lancement (aucun persona stocké) → défaut SecOps : Critical Now 24h
    if (!id) {
      _activeId = 'today';
      _setAppFilters(PERSONA_FILTERS['today'] || {});
      _render(); // highlight la pill "Top priorities"
      return;
    }

    const persona = PERSONAS.find(p => p.id === id);
    if (!persona) return;
    _activeId = id;
    _setAppFilters(PERSONA_FILTERS[id] || {});
    // Réappliquer le masque de vue pour SOC uniquement (non destructif)
    if (id === 'soc' && typeof FeedManager !== 'undefined')
      FeedManager.setViewCategoryInclude(['operational', 'cti_campaigns']);
    _render(); // highlight pill dans la barre
    // Sync barre profil
    if (typeof ProfileSwitcher !== 'undefined') ProfileSwitcher.render();
  }

  // silentRestorePanel() — appelé APRÈS refresh() dans app.init()
  //   → ouvre le panneau associé au persona (données disponibles)
  //   → silencieux : pas de toast, pas de re-filtrage
  function silentRestorePanel() {
    let id;
    try { id = localStorage.getItem(PERSONA_KEY); } catch {}
    if (!id || id !== _activeId) return; // sécurité : filtres déjà appliqués
    _openPanel(PERSONA_PANEL[id] || 'main');
  }

  // ── API de synchronisation multi-contexte (Sprint 21) ─────────────────────

  /**
   * clearActive() — Efface la vue persona active sans réinitialiser les filtres.
   * Appelé par profile-switcher.js (changement de profil) et saved-filters.js
   * (application d'un preset) pour éviter que deux indicateurs de contexte
   * coexistent et se contredisent.
   * Silent : pas de toast, juste le re-rendu visuel de la barre.
   */
  function clearActive() {
    if (_activeId === null) return; // déjà inactif — évite un re-render inutile
    _activeId = null;
    _render();
    // Sync ligne persona dans la barre profil (Sprint 24)
    if (typeof ProfileSwitcher !== 'undefined') ProfileSwitcher.render();
  }

  /**
   * getActivePersona() — Retourne l'objet persona actif ou null.
   * Utilisé par profile-panel.js pour afficher le contexte analytique courant.
   */
  function getActivePersona() {
    return _activeId ? (PERSONAS.find(p => p.id === _activeId) || null) : null;
  }

  // ── Rendu de la barre ──────────────────────────────────────────────────────

  function _render() {
    const bar = document.getElementById('persona-bar');
    if (!bar) return;

    const activePersona = _activeId ? PERSONAS.find(p => p.id === _activeId) : null;

    let profileCtx = '';
    if (typeof ProfileManager !== 'undefined') {
      const p = ProfileManager.getActiveProfile();
      if (p) profileCtx = ` — ${p.badge ? p.badge + '\u00a0' : ''}${p.name}`;
    }

    const hintText = activePersona
      ? `Active view: ${activePersona.desc}${profileCtx}`
      : `Select a view${profileCtx}`;

    bar.innerHTML = `
      <span class="pbar-label">Business views</span>
      <div class="pbar-pills">
        ${PERSONAS.map(p => `
          <button class="pbar-pill${_activeId === p.id ? ' pbar-active' : ''}"
                  data-pid="${p.id}"
                  title="${p.desc}">
            ${p.icon}&nbsp;${p.name}
          </button>`).join('')}
      </div>
      <span class="pbar-hint" title="${hintText}">${hintText}</span>
      <button class="pbar-reset" title="Reset all filters to default">↺&nbsp;Reset</button>
      <button class="pbar-tour" title="Review the quick start guide">?</button>`;

    bar.querySelectorAll('.pbar-pill').forEach(btn => {
      btn.addEventListener('click', () => _activate(btn.dataset.pid));
    });
    bar.querySelector('.pbar-reset')?.addEventListener('click', _reset);
    bar.querySelector('.pbar-tour')?.addEventListener('click', () => {
      if (typeof Onboarding !== 'undefined') Onboarding.showTour();
    });
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  function init() {
    // Injecter la barre après #risk-filter-container
    // Fallback : avant #feed-grid si l'ancre est absente
    const anchor = document.getElementById('risk-filter-container')
                || document.querySelector('.main');
    if (!anchor) return;

    if (document.getElementById('persona-bar')) return; // idempotent

    const bar = document.createElement('div');
    bar.id        = 'persona-bar';
    bar.className = 'persona-bar';
    anchor.after(bar);

    _render();
  }

  return {
    init,
    clearActive,
    getActivePersona,
    pickAndActivate,
    silentRestoreFilters,
    silentRestorePanel
  };
})();

// Auto-init : le DOM est prêt (script en fin de body)
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => PersonaPresets.init());
} else {
  PersonaPresets.init();
}
