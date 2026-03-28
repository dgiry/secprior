// persona-presets.js — Vues métier persona CyberVeille Pro
//
// Injecte une barre compacte de vues persona en dessous de la barre Risque Réel.
// Chaque vue active un ensemble cohérent de filtres et ouvre le bon panneau.
// Les saved-filters utilisateur ne sont pas touchés — ce sont deux systèmes distincts.
//
// Vues disponibles :
//   🔴 Analyste SOC    — incidents actifs, workflow investigating
//   🔍 Vuln Mgmt       — CVEs KEV/EPSS, focus correctifs
//   📊 RSSI / CISO     — posture globale, vue synthétique
//   🏢 MSSP            — incidents multi-source, watchlist
//   🚨 Top priorités   — Critical Now des dernières 24h

const PersonaPresets = (() => {

  let _activeId = null;

  // ── Définitions des vues persona ─────────────────────────────────────────

  const PERSONAS = [
    {
      id:   'soc',
      icon: '🔴',
      name: 'SOC Analyst',
      desc: 'All incidents sorted by priority · wide analyst view',
      apply() {
        // Suppression des filtres statusFilter et filterBy imposés :
        // sur données réelles, forcer "investigating" + "critical_now" vide trop souvent la vue.
        // L'analyste retrouve tous les incidents triés par priorité et applique ses filtres manuellement.
        _setAppFilters({ priorityLevel: 'all', sortBy: 'priority' });
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

  // ── Activation / reset ────────────────────────────────────────────────────

  function _activate(id) {
    const persona = PERSONAS.find(p => p.id === id);
    if (!persona) return;

    _activeId = id;
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
    _setAppFilters({});     // → tous les filtres à their defaults
    _closeAllPanels();
    _render();
    // Sync ligne persona dans la barre profil (Sprint 24)
    if (typeof ProfileSwitcher !== 'undefined') ProfileSwitcher.render();
    window.scrollTo({ top: 0, behavior: 'smooth' });
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

  return { init, clearActive, getActivePersona };
})();

// Auto-init : le DOM est prêt (script en fin de body)
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => PersonaPresets.init());
} else {
  PersonaPresets.init();
}
