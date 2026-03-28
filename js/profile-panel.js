// profile-panel.js — Dashboard synthèse du profil actif (Sprint 20–21)
//
// Panneau collapsible affichant le contexte du profil d'exposition courant :
//   • Identité   : badge, nom, description, nb termes watchlist
//   • Vue persona active (Sprint 21) : affichée si PersonaPresets.getActivePersona() non null
//   • KPIs       : hits watchlist, articles prioritaires, KEV actifs, incidents profil
//   • Top termes : barres mini avec compteurs d'articles correspondants
//   • Top menaces: articles triés par score avec watchlist hit — cliquables
//   • Accès rapide : Watchlist · Top priorités · Incidents · Sauvegarder vue (Sprint 21)
//
// Intégration :
//   • app.js             → ProfilePanel.update(articles)  après chaque refresh
//   • profile-switcher.js → ProfilePanel.refreshProfile() sur changement de profil
//
// Dépendances optionnelles : IncidentPanel, WatchlistModal, ArticleModal, App,
//                            PersonaPresets (Sprint 21), SavedFilters (Sprint 21)
// Robuste avec données partielles (profil vide, aucun article, aucun hit).

const ProfilePanel = (() => {

  let _articles = [];
  let _visible  = false;

  // ── Toggle ─────────────────────────────────────────────────────────────────

  function toggle() {
    const panel = document.getElementById('profile-panel');
    const btn   = document.getElementById('btn-profile-panel');
    if (!panel) return;
    _visible = !_visible;
    panel.style.display = _visible ? 'block' : 'none';
    btn?.classList.toggle('active', _visible);
    if (_visible) _render(_articles);
  }

  // ── Mise à jour complète (avec articles) ──────────────────────────────────

  function update(articles) {
    _articles = articles || [];
    if (_visible) _render(_articles);
  }

  // ── Mise à jour sur changement de profil (re-render immédiat) ─────────────
  // Appelée par profile-switcher.js avant que les articles soient re-chargés.
  // Montre immédiatement le nouveau profil, les KPIs seront ré-évalués
  // avec les articles re-contextualisés lors du prochain update().

  function refreshProfile() {
    if (_visible) _render(_articles);
  }

  // ── Rendu principal ────────────────────────────────────────────────────────

  function _render(articles) {
    const panel = document.getElementById('profile-panel');
    if (!panel) return;

    const profile = typeof ProfileManager !== 'undefined'
      ? ProfileManager.getActiveProfile() : null;

    if (!profile) {
      panel.innerHTML = '<div class="pp-empty-panel">No active profile.</div>';
      return;
    }

    // Termes watchlist actifs
    const wlTerms  = (profile.watchlist || []).filter(w => w.enabled !== false);

    // Articles ayant au moins un hit watchlist du profil courant
    const hitArticles = articles.filter(a => (a.watchlistMatches || []).length > 0);

    // ── KPIs ──
    const kpiHits = hitArticles.length;
    const kpiPrio = hitArticles.filter(a =>
      a.priorityLevel === 'critical_now' || a.priorityLevel === 'investigate').length;
    const kpiKEV  = hitArticles.filter(a => a.isKEV).length;

    // Incidents avec watchlist hit (via IncidentPanel si disponible)
    let kpiInc = 0;
    if (typeof IncidentPanel !== 'undefined') {
      try {
        const incs = IncidentPanel.buildIncidentIndex(articles);
        kpiInc = incs.filter(i => i.watchlistHit).length;
      } catch { /* robuste si buildIncidentIndex non disponible */ }
    }

    // ── Top termes watchlist par nombre d'articles correspondants ──
    const termCounts = {};
    hitArticles.forEach(a => {
      (a.watchlistMatches || []).forEach(term => {
        if (term) termCounts[term] = (termCounts[term] || 0) + 1;
      });
    });
    const topTerms     = Object.entries(termCounts)
      .sort((a, b) => b[1] - a[1]).slice(0, 6);
    const maxTermCount = topTerms[0]?.[1] || 1;

    // ── Top articles prioritaires du profil ──
    const topArticles = [...hitArticles]
      .sort((a, b) => (b.priorityScore || b.score || 0) - (a.priorityScore || a.score || 0))
      .slice(0, 5);

    // ── Rendu HTML ──
    panel.innerHTML = _buildHTML({
      profile, wlTerms, kpiHits, kpiPrio, kpiKEV, kpiInc,
      topTerms, maxTermCount, topArticles,
      hasArticles: articles.length > 0
    });

    _bindActions();
  }

  // ── Construction HTML ─────────────────────────────────────────────────────

  function _buildHTML({ profile, wlTerms, kpiHits, kpiPrio, kpiKEV, kpiInc,
                         topTerms, maxTermCount, topArticles, hasArticles }) {

    const wlCount = wlTerms.length;

    // ── Vue persona active (Sprint 21) ──
    let personaHTML = '';
    if (typeof PersonaPresets !== 'undefined') {
      const persona = PersonaPresets.getActivePersona();
      if (persona) {
        personaHTML = `<div class="pp-persona-indicator">
          <span class="pp-persona-icon">${_esc(persona.icon)}</span>
          <span class="pp-persona-name">${_esc(persona.name)}</span>
          <span class="pp-persona-desc">${_esc(persona.desc)}</span>
        </div>`;
      }
    }

    // ── Entête profil ──
    const headerHTML = `
      <div class="pp-header">
        <div class="pp-header-left">
          <span class="pp-badge">${_esc(profile.badge || '◉')}</span>
          <div class="pp-meta">
            <span class="pp-name">${_esc(profile.name)}</span>
            ${profile.description
              ? `<span class="pp-desc">${_esc(profile.description)}</span>` : ''}
          </div>
        </div>
        <div class="pp-header-right">
          <span class="pp-wl-pill"
                title="${wlCount} monitored term${wlCount !== 1 ? 's' : ''}">
            ${wlCount} term${wlCount !== 1 ? 's' : ''}
          </span>
          <button class="pp-close" id="pp-close" title="Close profile dashboard">✕</button>
        </div>
      </div>
      ${personaHTML}`;

    // ── KPIs (seulement si watchlist configurée) ──
    const kpiHTML = wlCount > 0 ? `
      <div class="pp-kpi-row">
        <div class="pp-kpi${kpiHits  > 0 ? ' pp-kpi-accent' : ''}">
          <span class="pp-kpi-val">${kpiHits}</span>
          <span class="pp-kpi-lbl">👁 Hits</span>
        </div>
        <div class="pp-kpi${kpiPrio  > 0 ? ' pp-kpi-warn' : ''}">
          <span class="pp-kpi-val">${kpiPrio}</span>
          <span class="pp-kpi-lbl">🎯 Priority</span>
        </div>
        <div class="pp-kpi${kpiKEV   > 0 ? ' pp-kpi-danger' : ''}">
          <span class="pp-kpi-val">${kpiKEV}</span>
          <span class="pp-kpi-lbl">⚠ KEV</span>
        </div>
        <div class="pp-kpi${kpiInc   > 0 ? ' pp-kpi-warn' : ''}">
          <span class="pp-kpi-val">${kpiInc}</span>
          <span class="pp-kpi-lbl">🚨 Incidents</span>
        </div>
      </div>` : '';

    // ── Empty state : watchlist vide ──
    if (wlCount === 0) {
      return `<div class="pp-inner">
        ${headerHTML}
        <div class="pp-empty-state">
          <div class="pp-empty-icon">👁</div>
          <p>No terms in this profile's watchlist.</p>
          <p class="pp-empty-hint">Add keywords, products or vendors to monitor.</p>
          <button class="btn pp-empty-cta" id="pp-btn-watchlist">Configure watchlist</button>
        </div>
        ${_actionsHTML(kpiInc, wlCount)}
      </div>`;
    }

    // ── Empty state : watchlist configurée mais aucun hit ──
    const noHitsHTML = kpiHits === 0 && hasArticles ? `
      <div class="pp-no-hits">
        No articles match the watchlist terms yet.
      </div>` : (!hasArticles ? `
      <div class="pp-no-hits">Loading articles…</div>` : '');

    // ── Top termes avec mini barres ──
    const topTermsHTML = topTerms.length > 0 ? `
      <div class="pp-section">
        <div class="pp-section-title">Most triggered terms</div>
        <div class="pp-term-list">
          ${topTerms.map(([term, count]) => {
            const pct = Math.round(count / maxTermCount * 100);
            return `<div class="pp-term-row">
              <span class="pp-term-label" title="${_esc(term)}">${_esc(term)}</span>
              <div class="pp-term-bar-wrap">
                <div class="pp-term-bar" style="width:${pct}%"></div>
              </div>
              <span class="pp-term-count">${count}</span>
            </div>`;
          }).join('')}
        </div>
      </div>` : '';

    // ── Top articles du profil ──
    const topArtHTML = topArticles.length > 0 ? `
      <div class="pp-section">
        <div class="pp-section-title">Top profile threats</div>
        <div class="pp-article-list">
          ${topArticles.map(a => _articleRowHTML(a)).join('')}
        </div>
      </div>` : '';

    return `<div class="pp-inner">
      ${headerHTML}
      ${kpiHTML}
      ${noHitsHTML}
      ${topTermsHTML}
      ${topArtHTML}
      ${_actionsHTML(kpiInc, wlCount)}
    </div>`;
  }

  // ── HTML d'une ligne article ───────────────────────────────────────────────

  function _articleRowHTML(a) {
    const critIcon = a.criticality === 'high' ? '🔴'
                   : a.criticality === 'medium' ? '🟠' : '🟢';
    const prioMap  = {
      critical_now: ['CRITICAL', 'pp-prio-critical'],
      investigate:  ['HIGH',     'pp-prio-investigate'],
      watch:        ['MEDIUM',   'pp-prio-watch']
    };
    const [prioLabel, prioCss] = prioMap[a.priorityLevel] || ['', ''];
    const wlSnippet = (a.watchlistMatches || []).slice(0, 2).join(', ');
    const score     = a.priorityScore || a.score || 0;

    return `
      <div class="pp-article-row" data-id="${_esc(a.id)}" role="button" tabindex="0"
           title="Open article: ${_esc(a.title)}">
        <span class="pp-art-crit">${critIcon}</span>
        <div class="pp-art-info">
          <span class="pp-art-title">${_esc(a.title)}</span>
          ${wlSnippet ? `<span class="pp-art-wl">👁 ${_esc(wlSnippet)}</span>` : ''}
        </div>
        <div class="pp-art-right">
          ${prioLabel
            ? `<span class="pp-art-prio ${prioCss}">${prioLabel}</span>` : ''}
          ${score > 0
            ? `<span class="pp-art-score">${score}</span>` : ''}
        </div>
      </div>`;
  }

  // ── HTML des actions rapides ───────────────────────────────────────────────

  function _actionsHTML(kpiInc, wlCount) {
    return `
      <div class="pp-actions">
        <button class="btn pp-action-btn" id="pp-btn-watchlist"
                title="Manage this profile's watchlist">👁 Watchlist</button>
        ${wlCount > 0
          ? `<button class="btn pp-action-btn" id="pp-btn-topprio"
                title="View priority articles for this profile">🎯 Top priorities</button>`
          : ''}
        ${kpiInc > 0
          ? `<button class="btn pp-action-btn" id="pp-btn-incidents"
                title="View active incidents linked to this profile">🚨 Incidents (${kpiInc})</button>`
          : ''}
        <button class="btn pp-action-btn pp-action-btn-save" id="pp-btn-save-view"
                title="Save the current view and filters for this profile">💾 Save view</button>
      </div>`;
  }

  // ── Bind interactions ─────────────────────────────────────────────────────

  function _bindActions() {
    // Fermer le panel
    document.getElementById('pp-close')
      ?.addEventListener('click', toggle);

    // Ouvrir watchlist (plusieurs IDs possibles selon empty state ou pas)
    ['pp-btn-watchlist'].forEach(id => {
      document.getElementById(id)?.addEventListener('click', () => {
        if (typeof WatchlistModal !== 'undefined') WatchlistModal.open();
      });
    });

    // Filtrer sur les articles prioritaires du profil courant
    document.getElementById('pp-btn-topprio')?.addEventListener('click', () => {
      // Applique filtre priorité + watchlist en utilisant l'API App si disponible
      if (typeof App !== 'undefined' && typeof App.getFilters === 'function') {
        App.setFilters({ ...App.getFilters(), priorityLevel: 'critical_now' });
      }
      if (_visible) toggle(); // fermer le panel
    });

    // Ouvrir le panneau incidents
    document.getElementById('pp-btn-incidents')?.addEventListener('click', () => {
      if (typeof IncidentPanel !== 'undefined') {
        const incPanel = document.getElementById('incident-panel');
        if (incPanel && incPanel.style.display === 'none') IncidentPanel.toggle();
      }
      if (_visible) toggle();
    });

    // Sprint 21 — Sauvegarder vue courante via SavedFilters
    document.getElementById('pp-btn-save-view')?.addEventListener('click', () => {
      if (typeof SavedFilters !== 'undefined') SavedFilters.open();
    });

    // Clic sur article → ouvrir la modal de détail
    document.querySelectorAll('.pp-article-row[data-id]').forEach(row => {
      const open = () => {
        const id = row.dataset.id;
        if (id && typeof ArticleModal !== 'undefined') ArticleModal.openById(id);
      };
      row.addEventListener('click', open);
      row.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); }
      });
    });
  }

  // ── Helper HTML-escape ────────────────────────────────────────────────────

  function _esc(s) {
    return String(s || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  function init() {
    document.getElementById('btn-profile-panel')
      ?.addEventListener('click', toggle);
  }

  // ── API publique ──────────────────────────────────────────────────────────

  return { init, toggle, update, refreshProfile };

})();

// Auto-init : script en fin de body
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => ProfilePanel.init());
} else {
  ProfilePanel.init();
}
