// app.js — Point d'entrée et orchestration de CyberVeille Pro

const App = (() => {
  // État global de l'application
  // ─── j/k article navigation ───────────────────────────────────────────────
  let _navIdx = -1; // -1 = nothing focused yet

  function _navCard(delta) {
    const cards = Array.from(document.querySelectorAll('#feed-grid .card[data-id]'));
    if (!cards.length) return;
    document.querySelector('.card-nav-focus')?.classList.remove('card-nav-focus');
    _navIdx = Math.max(0, Math.min(cards.length - 1, _navIdx + delta));
    const card = cards[_navIdx];
    card.classList.add('card-nav-focus');
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  const state = {
    articles: [],         // Tous les articles chargés
    nvdMap: {},           // { articleId: cveData } — données NVD enrichies
    // trendVPMap removed — per-CVE VP signal unsupported by TV1 API (2026-04)
    query: "",
    criticality: "all",
    source: "all",
    date: "all",
    priorityLevel: "all", // all | critical_now | investigate | watch | low
    sortBy: "default",    // default (date) | priority (priorityScore desc)
    statusFilter: "all",  // all | new | acknowledged | investigating | mitigated | ignored
    showFavOnly: false,
    showUnreadOnly: false,
    hideReviewed: false,
    lastSavedQuery: null,  // Track last saved search (avoid duplicates in history)
    timerId: null,
    _cveLinkId:   null,   // CVE unique (clic sur une ligne) — priorité haute
    _cveLinkIds:  null,   // Tableau de CVEs (filtre panneau) — priorité basse
    lastVisitTs:  null,   // Timestamp début session précédente (New since last visit)
    _nsvDismissed: false, // Badge NSV masqué par l'utilisateur pour cette session
    _attackFilter: null,  // ATT&CK tactic drill-down from StatsPanel (label string | null)
    // ─── Freshness tracking ──────────────────────────────────────────────────
    lastFreshFetchAt: null,   // Timestamp of last live (non-cache) fetch
    lastRefreshMode: null,    // 'restore' | 'cache' | 'live' | 'degraded'
    previousArticleCount: 0   // Article count before last refresh (for change detection)
  };

  // ─── Refresh principal via Pipeline ────────────────────────────────────────
  async function refresh(force = false) {
    console.log(`[App] refresh() begin · force=${force}`);
    UI.showSpinner(true);
    try {
      // ── Quand force=true, invalider le cache enrichi pour forcer la recomputation ──
      // Cela garantit que les articles refreshés seront différents des articles cachés.
      if (force) {
        console.log("[App] Force refresh: clearing enriched articles cache to ensure fresh data");
        Storage.clearArticles();
      }
      // ── Pipeline 6 étapes : Collecter → Enrichir → Dédupliquer → Scorer → Contextualiser
      const articles = await Pipeline.run(force);
      console.log(`[App] refresh() pipeline returned ${articles.length} articles`);
      if (articles.length === 0) console.warn("[App] refresh(): pipeline returned 0 articles");
      state.articles = articles;
      console.log(`[App] state.articles set (${state.articles.length})`);

      // Debug: Log priorityLevels et priorityScores après refresh
      const critNowArticles = state.articles
        .filter(a => a.priorityLevel === "critical_now")
        .sort((a, b) => (b.priorityScore || 0) - (a.priorityScore || 0))
        .slice(0, 5);
      const critNowWithScores = critNowArticles.map(a => ({
        title: a.title.slice(0, 40),
        priorityScore: a.priorityScore,
        isKEV: a.isKEV,
        pubDate: a.pubDate.toISOString()
      }));
      console.log(`[App] Top 5 critical_now articles:`, critNowWithScores);

      // Persister les articles enrichis pour restauration au rechargement (TTL 6 h)
      Storage.setArticles(articles);
      console.log(`[App] Storage.setArticles persisted (${articles.length})`);

      // En ligne + refresh OK → état live (retire la bannière dégradée si présente)
      if (typeof PWA !== 'undefined' && navigator.onLine) {
        try { PWA.setAppConnectivityState('live'); } catch {}
      }

      // Notifier les nouvelles alertes critiques (browser)
      UI.notifyCritical(articles);

      // Afficher avec filtres actuels
      render();
      if (!state.articles?.length) console.warn("[App] render() called with empty state.articles");
      UI.updateTimestamp();
      _updateRefreshButtonStatus();  // Update freshness indicator on button

      // Ops panel update (live mode) with signal quality metrics
      try {
        const mode = 'live';
        const feedCount = (typeof FeedManager !== 'undefined') ? FeedManager.getActiveCount() : '—';
        const envStats = (typeof IncidentPanel !== 'undefined') ? IncidentPanel.getEnvironmentContextStats() : null;
        // ── Freshness tracking ────────────────────────────────────────────────
        const now = Date.now();
        state.lastFreshFetchAt = now;  // Track when we last fetched live data
        state.lastRefreshMode = mode;
        const articleChange = state.articles.length - state.previousArticleCount;
        state.previousArticleCount = state.articles.length;
        const feedHealth = _getPriorityFeedHealth();
        OpsPanel.update({
          sourceMode: mode,
          feedCount,
          articleCount: state.articles.length,
          lastRefreshAt: now,
          lastFreshFetchAt: state.lastFreshFetchAt,
          articleChange,
          feedHealth,
          environmentContextStats: envStats
        });
        // Persister le timestamp de la dernière fetch live (pour restauration session)
        try {
          localStorage.setItem('cv_last_fresh_fetch_at', String(state.lastFreshFetchAt));
        } catch {}
      } catch {}

      // Mettre à jour le dashboard stats
      StatsPanel.update(articles);
      VendorPanel.update(articles);
      CVEPanel.update(articles, _buildCveNvdMap());
      IncidentPanel.update(articles);
      VisibilityPanel.update(articles);
      if (typeof ProfilePanel  !== 'undefined') ProfilePanel.update(articles);
      if (typeof ExecView      !== 'undefined') ExecView.update(articles);

      // Mettre à jour la référence articles du modal de détail
      ArticleModal.setArticles(articles, state.nvdMap);

      // Détecter si on est en mode démo (aucun article live)
      const isDemo = articles.every(a => a.id.startsWith("demo"));
      const demoBar = document.getElementById("demo-bar");
      if (demoBar) demoBar.style.display = isDemo ? "flex" : "none";

      if (force && !isDemo) {
        const highCount   = articles.filter(a => a.criticality === "high").length;
        const kevCount    = articles.filter(a => a.isKEV).length;
        const watchCount  = articles.filter(a => a.watchlistMatches?.length > 0).length;
        let msg = `${articles.length} articles · ${highCount} HIGH`;
        if (kevCount)   msg += ` · ${kevCount} KEV`;
        if (watchCount) msg += ` · ${watchCount} watchlist`;
        UI.showToast(msg, "success");
      }

      // ── Enrichissement NVD CVSS en arrière-plan (non-bloquant) ───────────
      if (CONFIG.NVD_ENABLED && !isDemo) {
        enrichWithNVD(articles);
      }

      // Trend VP enrichment removed — per-CVE signal unsupported by TV1 API (2026-04)

      // ── NVD keyword search : trouver les CVE manquants (non-bloquant) ─────
      // Pour les articles avec vendor connu mais 0 CVE dans le texte RSS.
      if (!isDemo && CONFIG.USE_API) {
        Enricher.enrichMissingCVEs(articles, (articleId, newCveIds) => {
          const target = state.articles.find(a => a.id === articleId);
          if (!target) return;
          target.cves = [...new Set([...(target.cves || []), ...newCveIds])];
          // Mettre à jour tous les panneaux avec les nouveaux CVE IDs
          CVEPanel.update(state.articles, _buildCveNvdMap());
          Storage.setArticles(state.articles);
        });
      }

      // ── Auto-IOC enrichment — priority articles only (non-bloquant) ─────
      // Runs Deep IOC scan → OTX for critical_now + KEV/score≥70 articles.
      // VT remains manual. Max 5 articles per run. Anti-duplicate guarded.
      if (!isDemo && CONFIG.USE_API && typeof IOCAutoEnricher !== 'undefined') {
        IOCAutoEnricher.run(articles, (article) => {
          // Article is mutated in-place — persist and refresh modal if open.
          Storage.setArticles(state.articles);
          if (typeof ArticleModal !== 'undefined')
            ArticleModal.refreshIOCSection(article.id);
        });
      }

      // ── Étape 6 : Alertes email/webhook intelligentes (non-bloquant) ─────
      if (!isDemo) {
        AlertManager.processNewArticles(articles);
      }
    } catch (err) {
      console.error("[App] Erreur refresh:", err);
      UI.showToast("Error loading RSS feeds. Check your connection.", "error");
      const cache = Storage.getCache();
      if (cache && cache.items) {
        const _cacheItems = cache.items.map(a => ({ ...a, pubDate: new Date(a.pubDate) }));
        state.articles = typeof Contextualizer !== 'undefined'
          ? Contextualizer.ensureWatchlistConsistency(_cacheItems)
          : _cacheItems;
        // Normalise iocCount from real arrays — prevents stale counts from cache
        if (typeof IOCExtractor !== 'undefined')
          state.articles.forEach(a => { a.iocCount = IOCExtractor.getRealIOCCount(a); });
        console.warn(`[App] Using fallback cache with ${state.articles.length} items after refresh error`);
        render();
        if (!state.articles?.length) console.warn("[App] render() called with empty cache items");
        UI.showToast("Affichage depuis le cache local.", "warning");
        // En ligne mais refresh en échec → état dégradé (distingué du vrai hors-ligne)
        if (typeof PWA !== 'undefined' && navigator.onLine) {
          try { PWA.setAppConnectivityState('degraded'); } catch {}
        }
        try {
          const now = Date.now();
          state.lastRefreshMode = 'degraded';
          const feedHealth = _getPriorityFeedHealth();
          OpsPanel.update({
            sourceMode: 'degraded',
            articleCount: state.articles.length,
            lastRefreshAt: now,
            lastFreshFetchAt: state.lastFreshFetchAt,  // Keep last fresh fetch timestamp
            feedHealth
          });
        } catch {}
      }
    } finally {
      UI.showSpinner(false);
      console.log("[App] refresh() end");
    }
  }

  // ─── Mettre à jour le tooltip du bouton refresh avec infos de fraîcheur ────
  function _updateRefreshButtonStatus() {
    const btn = document.getElementById("btn-refresh");
    if (!btn) return;
    if (!state.lastFreshFetchAt) {
      btn.title = "Force feed update · No live fetch yet";
      return;
    }
    const ago = Math.floor((Date.now() - state.lastFreshFetchAt) / 60000); // en minutes
    const ago_str = ago < 1 ? "Just now" : `${ago}m ago`;
    const status = state.lastRefreshMode === 'live' ? '✓ Live' : (state.lastRefreshMode === 'restore' ? '↻ Cached' : state.lastRefreshMode);
    btn.title = `Force feed update · Last fresh: ${ago_str} (${status})`;
  }

  // ─── Badge actif sur le bouton "Filters ▾" si un filtre secondaire est actif ─
  function _updateSecondaryFiltersBadge() {
    const badge = document.getElementById('secondary-filters-badge');
    if (!badge) return;
    const riskActive = (typeof RiskFilter !== 'undefined') && RiskFilter.getFilters().active.size > 0;
    const active = riskActive
                || state.criticality  !== 'all'
                || state.source       !== 'all'
                || state.sortBy       !== 'default'
                || state.statusFilter !== 'all'
                || !!state._attackFilter;
    badge.style.display = active ? 'block' : 'none';
  }

  // ─── Collecter la santé des flux prioritaires pour l'Ops Panel ──────────────
  function _getPriorityFeedHealth() {
    const priorityIds = ['securityweek', 'cyber-centre', 'certeu', 'cisa-ics'];
    if (typeof FeedManager === 'undefined') return [];

    return priorityIds
      .map(id => FeedManager.getAllFeeds().find(f => f.id === id))
      .filter(f => f) // ignore missing feeds
      .map(f => ({
        name: f.name,
        status: f.lastStatus || 'unknown',
        lastTestAt: f.lastTestAt,
        lastItemCount: f.lastItemCount,
        lastErrorMessage: f.lastErrorMessage
      }));
  }

  // ─── Enrichissement NVD en arrière-plan ───────────────────────────────────
  async function enrichWithNVD(articles) {
    await NVD.enrichArticles(articles, (articleId, cveData) => {
      // Stocker dans la map d'état
      state.nvdMap[articleId] = cveData;
      // Mettre à jour la carte si elle est visible dans le DOM
      UI.updateCardCVSS(articleId, cveData);
      // Synchroniser le modal si c'est l'article actuellement affiché
      ArticleModal.setArticles(state.articles, state.nvdMap);
      // Mettre à jour le panneau CVE avec les données NVD (timeline / âge)
      if (typeof CVEPanel !== 'undefined') CVEPanel.update(state.articles, _buildCveNvdMap());
    });
  }

  // ─── Inversion nvdMap : articleId→cveData  ⟶  cveId→cveData ──────────────
  function _buildCveNvdMap() {
    const m = {};
    Object.values(state.nvdMap).forEach(d => {
      if (d?.cveId) m[d.cveId.toUpperCase()] = d;
    });
    return m;
  }

  // enrichWithTrendVP + _buildCveIdList removed — per-CVE VP signal unsupported by TV1 API (2026-04)

  // ─── Rendu avec filtres ────────────────────────────────────────────────────
  function render() {
    // Pré-filtre CVE (deux niveaux : ligne > panneau)
    let articlesToFilter = state.articles;
    if (state._cveLinkId) {
      // Niveau ligne — CVE unique
      const cve = state._cveLinkId.toUpperCase();
      articlesToFilter = state.articles.filter(a =>
        (a.cveIds || a.cves || []).some(c => c.toUpperCase() === cve)
      );
    } else if (state._cveLinkIds && state._cveLinkIds.length > 0) {
      // Niveau panneau — ensemble de CVEs filtrées
      const cveSet = new Set(state._cveLinkIds);
      articlesToFilter = state.articles.filter(a =>
        (a.cveIds || a.cves || []).some(c => cveSet.has(c.toUpperCase()))
      );
    }

    // Pré-filtre ATT&CK tactic (drill-down depuis StatsPanel)
    if (state._attackFilter) {
      const _atk = state._attackFilter;
      articlesToFilter = articlesToFilter.filter(a =>
        (a.attackTags || []).some(t => t.label === _atk)
      );
    }

    // Marquer les articles "nouveaux depuis la dernière visite"
    const ts = state.lastVisitTs;
    articlesToFilter.forEach(a => {
      a._isNew = ts ? a.pubDate.getTime() > ts : false;
    });

    const filtered = UI.applyFilters(articlesToFilter, {
      query:         state.query,
      criticality:   state.criticality,
      source:        state.source,
      date:          state.date,
      lastVisitTs:   state.lastVisitTs,        // pour le filtre "lastvisit"
      priorityLevel: state.priorityLevel,
      sortBy:        state.sortBy,
      statusFilter:  state.statusFilter,
      showFavOnly:   state.showFavOnly,
      hideReviewed:  state.hideReviewed,
      riskFilters:   RiskFilter.getFilters()   // { active: Set, epssThreshold }
    });
    UI.renderCards(filtered);
    UI.renderKPIBar(filtered);
    _navIdx = -1; // Reset j/k navigation on every render
    RiskFilter.setCount(filtered.length);     // mise à jour compteur dans la barre
    _updateUnreadCount(filtered);             // compteur non-lu dans la navbar
    _updateNewBadge();                        // badge "N nouveaux" dans la statusbar
    _updateContextBar();                      // bandeau contextuel sous la statusbar
    _updateAttackFilterBadge();               // badge tactic ATT&CK actif

    // Sauvegarder la recherche si elle a changé (éviter les doublons)
    if (state.query !== state.lastSavedQuery) {
      Storage.addRecentSearch(state.query);
      state.lastSavedQuery = state.query;
    }
    _updateRecentSearches();                  // mettre à jour l'historique UI
    _updateRefreshButtonStatus();             // mettre à jour l'indicateur de fraîcheur
    _updateSecondaryFiltersBadge();           // point bleu si filtre secondaire actif
  }

  // ─── Badge "New since last visit" ─────────────────────────────────────────
  function _updateNewBadge() {
    if (!state.lastVisitTs) return;
    const count = state.articles.filter(a =>
      a.pubDate instanceof Date && a.pubDate.getTime() > state.lastVisitTs
    ).length;

    // ── Statusbar badge (dismissible) ──────────────────────────────────────
    const badge   = document.getElementById("nsv-badge");
    const countEl = document.getElementById("nsv-count");
    if (badge && countEl) {
      if (count > 0 && !state._nsvDismissed && state.date !== "lastvisit") {
        badge.style.display = "inline-flex";
        countEl.textContent = count;
      } else {
        badge.style.display = "none";
      }
    }

    // ── Navbar button (persistent — not dismissible) ───────────────────────
    const navBtn      = document.getElementById("btn-nsv");
    const navCountEl  = document.getElementById("nsv-nav-count");
    if (navBtn && navCountEl) {
      if (count > 0 && state.date !== "lastvisit") {
        navBtn.style.display = "inline-flex";
        navCountEl.textContent = count;
      } else {
        navBtn.style.display = "none";
      }
    }

    // ── Browser tab title ──────────────────────────────────────────────────
    document.title = count > 0 ? `(${count} new) ThreatLens` : 'ThreatLens';
  }

  // ─── Compteur non-lu (navbar) ──────────────────────────────────────────────
  function _updateUnreadCount(filtered) {
    const countEl = document.getElementById("unread-count");
    if (!countEl) return;
    // Compte les articles non-lus dans l'ensemble actuellement affiché
    const unreadCount = filtered.filter(a => !Storage.isRead(a.id)).length;
    countEl.textContent = unreadCount;
  }

  // ─── Bandeau contextuel NSV (sous la statusbar, au-dessus du feed) ────────
  function _updateContextBar() {
    const bar      = document.getElementById("nsv-context-bar");
    const countEl  = document.getElementById("nsv-ctx-count");
    const pluralEl = document.getElementById("nsv-ctx-plural");
    const timeEl   = document.getElementById("nsv-ctx-time");
    if (!bar) return;
    if (state.date === "lastvisit" && state.lastVisitTs) {
      // Compte les articles réellement affichés (après tous les filtres actifs)
      const filtered = UI.applyFilters(state.articles, {
        query:         state.query,
        criticality:   state.criticality,
        source:        state.source,
        date:          state.date,
        lastVisitTs:   state.lastVisitTs,
        priorityLevel: state.priorityLevel,
        sortBy:        state.sortBy,
        statusFilter:  state.statusFilter,
        showFavOnly:   state.showFavOnly,
        hideReviewed:  state.hideReviewed,
        riskFilters:   RiskFilter.getFilters()
      });
      const n = filtered.length;
      const relTime = UI.timeAgo(state.lastVisitTs);
      bar.style.display  = "flex";
      if (countEl)  countEl.textContent  = n;
      if (pluralEl) pluralEl.textContent = n !== 1 ? "s" : "";
      if (timeEl)   timeEl.textContent   = ` (${relTime} ago)`;
    } else {
      bar.style.display = "none";
    }
  }

  // ─── Historique recherches récentes ──────────────────────────────────────
  function _updateRecentSearches() {
    const panel = document.getElementById("recent-searches-panel");
    if (!panel) return;

    const searches = Storage.getRecentSearches();
    if (searches.length === 0) {
      panel.style.display = "none";
      return;
    }

    panel.style.display = "block";
    const header = `
      <div class="recent-searches-header">
        <span class="recent-searches-label">Recent</span>
        <button class="recent-searches-clear"
                onclick="App.clearRecentSearchHistory()"
                title="Clear search history">✕</button>
      </div>
    `;
    const buttons = searches.map((q) => {
      const display = q.length > 50 ? q.slice(0, 47) + "…" : q;
      return `<div class="recent-search-item">
                <button class="recent-search-btn"
                        onclick="App.applyRecentSearch(${JSON.stringify(q)})"
                        title="${q}">
                  ${display}
                </button>
                <button class="recent-search-remove"
                        onclick="App.removeRecentSearch(${JSON.stringify(q)})"
                        title="Remove from history">✕</button>
              </div>`;
    }).join("");
    panel.innerHTML = header + buttons;
  }

  // ─── Lien CVE → Feed ───────────────────────────────────────────────────────
  function _updateCVELinkBadge() {
    const badge = document.getElementById("cve-link-badge");
    if (!badge) return;
    const labelEl = badge.querySelector(".cve-link-badge-id");
    if (state._cveLinkId) {
      // Niveau ligne — CVE unique
      badge.style.display = "inline-flex";
      if (labelEl) labelEl.textContent = state._cveLinkId;
    } else if (state._cveLinkIds && state._cveLinkIds.length > 0) {
      // Niveau panneau — N CVEs
      badge.style.display = "inline-flex";
      if (labelEl) labelEl.textContent = state._cveLinkIds.length === 1
        ? state._cveLinkIds[0]
        : `${state._cveLinkIds.length} CVEs`;
    } else {
      badge.style.display = "none";
    }
  }

  /** Niveau ligne : clic sur une CVE spécifique */
  function filterByCVE(cveId) {
    state._cveLinkId = cveId ? cveId.toUpperCase() : null;
    _updateCVELinkBadge();
    render();
  }

  /** Niveau ligne : collapse → revient au filtre panneau s'il est actif */
  function clearRowCVEFilter() {
    state._cveLinkId = null;
    _updateCVELinkBadge();
    render();
  }

  /** Niveau panneau : filtre texte/type/date → liste de CVEs visibles */
  function filterByCVEs(cveIds) {
    state._cveLinkIds = (cveIds && cveIds.length > 0)
      ? cveIds.map(c => c.toUpperCase())
      : null;
    // Ne pas écraser un filtre ligne actif dans le rendu
    if (!state._cveLinkId) {
      _updateCVELinkBadge();
      render();
    }
  }

  /** Tout effacer (fermeture panneau, clic ✕ badge) */
  function clearCVEFilter() {
    state._cveLinkId  = null;
    state._cveLinkIds = null;
    _updateCVELinkBadge();
    render();
  }

  // ─── ATT&CK tactic drill-down (StatsPanel → feed pivot) ──────────────────

  function _updateAttackFilterBadge() {
    const badge = document.getElementById('attack-filter-badge');
    if (!badge) return;
    const labelEl = badge.querySelector('.attack-filter-badge-label');
    if (state._attackFilter) {
      badge.style.display = 'inline-flex';
      if (labelEl) labelEl.textContent = state._attackFilter;
    } else {
      badge.style.display = 'none';
    }
  }

  /** Select (or clear) an ATT&CK tactic filter; called by StatsPanel rows */
  function filterByAttack(label) {
    state._attackFilter = label || null;
    _updateAttackFilterBadge();
    // Refresh StatsPanel active-row highlight without waiting for next data load
    if (typeof StatsPanel !== 'undefined' && StatsPanel.refreshAttackList) {
      StatsPanel.refreshAttackList();
    }
    render();
  }

  /** Clear the ATT&CK filter — wired to the badge ✕ button */
  function clearAttackFilter() {
    filterByAttack(null);
  }

  /** Read-only getter used by StatsPanel to mark the active row on re-render */
  function getAttackFilter() {
    return state._attackFilter;
  }

  // ─── Search chip active-state sync ─────────────────────────────────────────
  function _syncSearchChips(query) {
    const chips = document.querySelectorAll(".search-chip");
    chips.forEach(c => c.classList.toggle("active", c.dataset.query === query));
  }

  // ─── Dropdown groups navbar (Analytics, Tools) ────────────────────────────
  function _closeNavDropdowns() {
    document.querySelectorAll(".nav-menu-popover").forEach(p => { p.style.display = "none"; });
    document.querySelectorAll(".nav-menu-trigger").forEach(t => {
      t.classList.remove("active");
      t.setAttribute("aria-expanded", "false");
    });
  }

  function _initNavDropdowns() {
    ["analytics", "tools"].forEach(name => {
      const trigger = document.getElementById(`btn-${name}-menu`);
      const popover = document.getElementById(`nav-${name}-popover`);
      if (!trigger || !popover) return;

      trigger.addEventListener("click", e => {
        e.stopPropagation();
        const isOpen = popover.style.display !== "none";
        _closeNavDropdowns();
        if (!isOpen) {
          popover.style.display = "flex";
          trigger.classList.add("active");
          trigger.setAttribute("aria-expanded", "true");
        }
      });

      // Close dropdown when any item inside is clicked (the panel will open independently)
      popover.addEventListener("click", () => {
        _closeNavDropdowns();
      });
    });

    // Close on any outside click
    document.addEventListener("click", _closeNavDropdowns);

    // Close on Escape key
    document.addEventListener("keydown", e => {
      if (e.key === "Escape") _closeNavDropdowns();
    });
  }

  // ─── Planification auto-refresh ────────────────────────────────────────────
  function scheduleRefresh() {
    if (state.timerId) clearInterval(state.timerId);
    state.timerId = setInterval(() => {
      // Ignorer si onglet masqué (économie proxy)
      if (document.hidden) return;
      refresh(false);
    }, CONFIG.REFRESH_INTERVAL);
  }

  // ─── Chargement des feeds depuis l'API ────────────────────────────────────
  /**
   * Charge la liste des flux depuis GET /api/feeds et met à jour CONFIG.FEEDS
   * en place (splice) pour que FeedManager et tous les modules voient les
   * changements sans rechargement.
   *
   * Fallback silencieux : si USE_API est false (mode statique Hostinger) ou si
   * /api/feeds est indisponible, CONFIG.FEEDS conserve sa valeur statique
   * définie dans config.js — aucun comportement ne change.
   */
  async function _loadFeedsFromAPI() {
    if (!CONFIG.USE_API) return; // mode statique → fallback CONFIG.FEEDS suffisant
    try {
      const res = await fetch("/api/feeds", { signal: AbortSignal.timeout(5_000) });
      if (!res.ok) return;
      const json = await res.json();
      if (Array.isArray(json.feeds) && json.feeds.length > 0) {
        // Mise à jour EN PLACE : toutes les références à CONFIG.FEEDS voient le changement
        CONFIG.FEEDS.splice(0, CONFIG.FEEDS.length, ...json.feeds);
        console.log("[App] Feeds chargés depuis /api/feeds (%d sources)", json.feeds.length);
      }
    } catch (e) {
      console.warn("[App] /api/feeds indisponible — fallback CONFIG.FEEDS statique :", e.message);
    }
  }

  // ─── Global Escape key handler — layered modal management ────────────────
  //
  // Runs in capture phase (before any bubble-phase handler).
  // Finds the topmost visible overlay and closes only that one,
  // preventing the previous bug where ESC closed ALL modals at once.

  function _initGlobalEscape() {
    const OVERLAY_SEL = [
      '.ob-overlay',           // z:9999
      '.modal-overlay',        // z:2000
      '.exec-modal-overlay',   // z:2000
      '.qa-share-modal',       // z:1250
      '.qa-ticket-modal',      // z:1200
      '.cex-overlay',          // z:1100
      '.ai-brief-overlay',     // z:1100
      '.art-modal-overlay',    // z:500
    ].join(',');

    document.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape') return;

      // Don't intercept if user is in an input/textarea — blur instead
      const tag = document.activeElement?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
        document.activeElement.blur();
        e.stopImmediatePropagation();
        return;
      }

      // Find all visible overlays
      const all = document.querySelectorAll(OVERLAY_SEL);
      const visible = [];
      for (const el of all) {
        if (el.style.display === 'none') continue;
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden') continue;
        visible.push(el);
      }

      if (!visible.length) return;  // no modal open — let nav/panel handlers run

      // Sort by z-index descending — close only the topmost
      visible.sort((a, b) =>
        (parseInt(getComputedStyle(b).zIndex) || 0) -
        (parseInt(getComputedStyle(a).zIndex) || 0)
      );

      const top = visible[0];

      // Click the close button (triggers the module's proper close logic)
      const closeBtn = top.querySelector('.modal-close, [class*="-close-btn"], .ob-close');
      if (closeBtn) closeBtn.click();
      else          top.style.display = 'none';  // fallback

      e.stopImmediatePropagation();
      e.preventDefault();
    }, true);  // capture phase — runs before all bubble-phase handlers
  }

  // ─── Initialisation ────────────────────────────────────────────────────────
  async function init() {
    _initGlobalEscape();

    // ── New since last visit — initialisation ─────────────────────────────
    // Pattern sessionStorage : stable sur F5, reset sur fermeture d'onglet.
    // state.lastVisitTs = début de la session PRÉCÉDENTE (référence de comparaison).
    // localStorage cv_last_visit = début de la session ACTUELLE (pour la prochaine fois).
    {
      const prevVisit = Storage.getLastVisit();
      if (!sessionStorage.getItem("cv_sv")) {
        // Nouvelle session — sessionStorage vide = nouvel onglet / retour après fermeture
        sessionStorage.setItem("cv_sv", "1");
        // Sauvegarder le début de cette session pour la prochaine visite
        Storage.setLastVisit(Date.now());
        // Le point de comparaison est l'ancienne valeur (session précédente)
        state.lastVisitTs = prevVisit; // null si première visite
      } else {
        // Même session (F5 / rechargement) — garder la référence stable
        // On lit cv_last_visit qui pointe sur le début de CETTE session
        state.lastVisitTs = prevVisit;
      }
    }

    // ── Maintenance préventive du localStorage ─────────────────────────────
    // Purge les statuts analyste "closed/false_positive" de plus de 90 jours
    // pour éviter la croissance indéfinie du store EntityStatus.
    if (typeof EntityStatus !== "undefined") EntityStatus.pruneStale();

    // ── Charger les feeds depuis l'API (source canonique) ─────────────────
    // await garantit que CONFIG.FEEDS est à jour AVANT tout appel à FeedManager
    await _loadFeedsFromAPI();

    // Initialiser les flux par défaut si le profil est vierge (onboarding)
    if (typeof FeedManager !== 'undefined') {
      FeedManager.initializeDefaultFeedsIfEmpty();
    }

    // Demander permission notifications
    UI.requestNotificationPermission();

    // Peupler le filtre sources (inclut les flux custom via FeedManager)
    UI.initSourceFilter();

    // Mettre à jour le compteur de flux actifs dans la barre de statut
    const feedCountEl = document.getElementById("statusbar-feed-count");
    if (feedCountEl) feedCountEl.textContent = FeedManager.getActiveCount();

    // ── Événements filtres ───────────────────────────────────────────────────
    let searchTimeout;
    document.getElementById("search-input")?.addEventListener("input", e => {
      state.query = e.target.value.trim();
      // Sync chip active state with typed query
      _syncSearchChips(state.query);
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => render(), 150);
    });

    // ── Search quick-filter chips — click toggles search query ────────────
    document.getElementById("search-chips")?.addEventListener("click", e => {
      const chip = e.target.closest(".search-chip");
      if (!chip) return;
      const query   = chip.dataset.query;
      const input   = document.getElementById("search-input");
      const isActive = chip.classList.contains("active");

      // Toggle: clear if already active, set if not
      const newQuery = isActive ? "" : query;
      if (input) input.value = newQuery;
      state.query = newQuery;

      // Update chip active states
      _syncSearchChips(newQuery);
      render();
    });

    // ── Initialiser le panel recherches récentes ────────────────────────────
    _updateRecentSearches();

    document.getElementById("filter-criticality")?.addEventListener("change", e => {
      state.criticality = e.target.value;
      render();
      _updateSecondaryFiltersBadge();
    });

    document.getElementById("filter-source")?.addEventListener("change", e => {
      state.source = e.target.value;
      render();
      _updateSecondaryFiltersBadge();
    });

    document.getElementById("filter-date")?.addEventListener("change", e => {
      state.date = e.target.value;
      render();
    });

    document.getElementById("filter-priority-level")?.addEventListener("change", e => {
      state.priorityLevel = e.target.value;
      render();
    });

    document.getElementById("sort-by")?.addEventListener("change", e => {
      state.sortBy = e.target.value;
      render();
      _updateSecondaryFiltersBadge();
    });

    document.getElementById("filter-status")?.addEventListener("change", e => {
      state.statusFilter = e.target.value;
      render();
      _updateSecondaryFiltersBadge();
    });

    // ── Clear all filters (appelé par raccourci C) ────────────────────────────
    function _clearAllFilters() {
      state.query          = '';
      state.date           = 'all';
      state.priorityLevel  = 'all';
      state.criticality    = 'all';
      state.source         = 'all';
      state.sortBy         = 'default';
      state.statusFilter   = 'all';
      state.showFavOnly    = false;
      state.showUnreadOnly = false;
      state.hideReviewed   = false;
      state._nsvDismissed  = false;

      // Sync DOM inputs
      const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val; };
      set('search-input',        '');
      _syncSearchChips('');
      set('filter-date',         'all');
      set('filter-priority-level','all');
      set('filter-criticality',  'all');
      set('filter-source',       'all');
      set('sort-by',             'default');
      set('filter-status',       'all');

      const favBtn = document.getElementById('btn-favs');
      if (favBtn) { favBtn.classList.remove('active'); favBtn.title = 'My favorites only'; }
      const unreadBtn = document.getElementById('btn-unread');
      if (unreadBtn) { unreadBtn.classList.remove('active'); unreadBtn.title = 'Unread only'; }
      const hideRevBtn = document.getElementById('btn-hide-reviewed');
      if (hideRevBtn) { hideRevBtn.classList.remove('active'); hideRevBtn.title = 'Hide reviewed'; }

      render();
    }

    // ── Raccourcis clavier pour power users ──────────────────────────────────
    document.addEventListener("keydown", e => {
      const target = e.target;
      const isInput = target.tagName === "INPUT" || target.tagName === "TEXTAREA";

      if (e.key === "/") {
        // "/" focus search input (sauf si déjà dedans)
        const searchInput = document.getElementById("search-input");
        if (target !== searchInput) {
          e.preventDefault();
          searchInput?.focus();
        }
      } else if (e.key.toUpperCase() === "R" && !isInput && !e.ctrlKey && !e.metaKey) {
        // "R" force refresh
        e.preventDefault();
        refresh(true);
        scheduleRefresh();
      } else if (e.key.toUpperCase() === "N" && !isInput && !e.ctrlKey && !e.metaKey) {
        // "N" activate "Since last visit" view
        e.preventDefault();
        filterNewSinceVisit();
      } else if (e.key.toUpperCase() === "E" && !isInput && !e.ctrlKey && !e.metaKey) {
        // "E" open Exec / CISO view
        e.preventDefault();
        document.getElementById('btn-exec-view')?.click();
      } else if (e.key.toUpperCase() === "F" && !isInput && !e.ctrlKey && !e.metaKey) {
        // "F" toggle Favorites filter
        e.preventDefault();
        document.getElementById('btn-favs')?.click();
      } else if (e.key.toUpperCase() === "C" && !isInput && !e.ctrlKey && !e.metaKey) {
        // "C" clear all active filters
        e.preventDefault();
        _clearAllFilters();
      } else if (e.key === "?" && !isInput) {
        // "?" show keyboard shortcuts cheatsheet
        e.preventDefault();
        if (typeof KeyboardShortcuts !== 'undefined') KeyboardShortcuts.show();
      } else if (e.key === "j" && !isInput && !e.ctrlKey && !e.metaKey) {
        // "j" navigate to next article card
        e.preventDefault();
        _navCard(+1);
      } else if (e.key === "k" && !isInput && !e.ctrlKey && !e.metaKey) {
        // "k" navigate to previous article card
        e.preventDefault();
        _navCard(-1);
      } else if (e.key === "Enter" && !isInput) {
        // "Enter" open focused card in article modal
        const focused = document.querySelector('.card-nav-focus[data-id]');
        if (focused && typeof ArticleModal !== 'undefined') {
          e.preventDefault();
          ArticleModal.openById(focused.dataset.id);
        }
      } else if (e.key.toUpperCase() === "S" && !isInput && !e.ctrlKey && !e.metaKey) {
        // "S" cycle analyst status of focused card
        const focused = document.querySelector('.card-nav-focus[data-id]');
        if (focused && typeof UI !== 'undefined') {
          e.preventDefault();
          UI.cycleStatus(focused.dataset.id);
        }
      } else if (e.key === "Escape") {
        // "Escape" close nav dropdowns and side panels
        _closeNavDropdowns();
        ["cve-panel", "incident-panel", "vendor-panel", "visibility-panel", "stats-panel", "briefing-panel", "health-panel"].forEach(id => {
          const el = document.getElementById(id);
          if (el) el.style.display = "none";
        });
      }
    });

    // ── Raccourci "Top priorités" — filtre critique + tri priorité ────────────
    document.getElementById("btn-top-priorities")?.addEventListener("click", () => {
      state.priorityLevel = "critical_now";
      state.sortBy = "priority";
      const plEl = document.getElementById("filter-priority-level");
      if (plEl) plEl.value = "critical_now";
      const sbEl = document.getElementById("sort-by");
      if (sbEl) sbEl.value = "priority";
      render();
    });

    // ── Bouton refresh manuel ─────────────────────────────────────────────────
    document.getElementById("btn-refresh")?.addEventListener("click", () => {
      refresh(true);
      scheduleRefresh(); // Réinitialiser le timer
    });

    // ── Export CSV enrichi (CVSS inclus si disponible) ───────────────────────
    document.getElementById("btn-export")?.addEventListener("click", () => {
      const filtered = UI.applyFilters(state.articles, {
        query:         state.query,
        criticality:   state.criticality,
        source:        state.source,
        date:          state.date,
        lastVisitTs:   state.lastVisitTs,
        priorityLevel: state.priorityLevel,
        sortBy:        state.sortBy,
        statusFilter:  state.statusFilter,
        showFavOnly:   state.showFavOnly,
        hideReviewed:  state.hideReviewed,
        riskFilters:   RiskFilter.getFilters()
      });
      UI.exportCSVEnriched(filtered, state.nvdMap);
    });

    // ── Toggle favoris ────────────────────────────────────────────────────────
    document.getElementById("btn-favs")?.addEventListener("click", () => {
      state.showFavOnly = !state.showFavOnly;
      const btn = document.getElementById("btn-favs");
      btn.classList.toggle("active", state.showFavOnly);
      btn.title = state.showFavOnly ? "Afficher tout" : "Mes favoris seulement";
      render();
    });

    // ── Toggle non-lu seulement ────────────────────────────────────────────────
    document.getElementById("btn-unread")?.addEventListener("click", () => {
      state.showUnreadOnly = !state.showUnreadOnly;
      const btn = document.getElementById("btn-unread");
      btn.classList.toggle("active", state.showUnreadOnly);
      btn.title = state.showUnreadOnly ? "Show all articles" : "Unread only";
      render();
    });

    // ── Toggle masquer les articles revus ─────────────────────────────────────
    document.getElementById("btn-hide-reviewed")?.addEventListener("click", () => {
      state.hideReviewed = !state.hideReviewed;
      const btn = document.getElementById("btn-hide-reviewed");
      btn.classList.toggle("active", state.hideReviewed);
      btn.title = state.hideReviewed ? "Show reviewed articles" : "Hide reviewed";
      render();
    });

    // ── Initialiser le modal Paramètres ──────────────────────────────────────
    SettingsModal.init();

    // ── Dropdowns de navigation (Analytics, Tools) ───────────────────────────
    _initNavDropdowns();

    // ── Watchlist modal ───────────────────────────────────────────────────────
    WatchlistModal.init();

    // ── Dashboard statistiques ────────────────────────────────────────────────
    StatsPanel.init();

    // ── Panneau Briefing ──────────────────────────────────────────────────────
    BriefingPanel.init();
    document.getElementById("btn-briefing")?.addEventListener("click", () => BriefingPanel.toggle());

    // ── Panneau Santé / Ops ───────────────────────────────────────────────────
    HealthPanel.init();
    document.getElementById("btn-health")?.addEventListener("click", () => HealthPanel.toggle());

    // ── Ops / Debug léger ─────────────────────────────────────────────────────
    OpsPanel.init();
    document.getElementById('btn-ops')?.addEventListener('click', () => OpsPanel.toggle());
    // Écoute backoff NVD → affichage statut
    window.addEventListener('nvd:backoff', (e) => {
      const until = e.detail?.until;
      const eta = until ? Math.max(0, Math.round((until - Date.now())/1000)) : null;
      OpsPanel.update({ nvd: eta ? `rate-limited (~${eta}s)` : 'rate-limited' });
    });

    // ── Panneau Vendors / Assets exposés ──────────────────────────────────────
    VendorPanel.init();
    document.getElementById("btn-vendors")?.addEventListener("click", () => VendorPanel.toggle());

    // ── Vue Exec / CISO ───────────────────────────────────────────────────────
    if (typeof ExecView !== 'undefined') ExecView.init();

    // ── Morning Brief generator ────────────────────────────────────────────────
    if (typeof MorningBrief  !== 'undefined') MorningBrief.init(() => state.articles);

    // ── IOC Bulk Export ────────────────────────────────────────────────────────
    if (typeof IOCExport !== 'undefined') IOCExport.init(() => state.articles);

    // ── How It Works / Lightweight Product Guide ───────────────────────────────
    if (typeof HowItWorks !== 'undefined') HowItWorks.init();

    // ── Keyboard Shortcuts Cheatsheet ──────────────────────────────────────────
    if (typeof KeyboardShortcuts !== 'undefined') KeyboardShortcuts.init();

    // ── Panneau Corrélation CVE ↔ Articles ────────────────────────────────────
    CVEPanel.init();

    // ── Panneau Incidents Consolidés ──────────────────────────────────────────
    IncidentPanel.init();

    // ── Panneau Visibilité ────────────────────────────────────────────────────
    VisibilityPanel.init();

    // ── Rapport PDF hebdomadaire ──────────────────────────────────────────────
    PDFReport.init();

    // ── Vues / filtres sauvegardés ────────────────────────────────────────────
    SavedFilters.init();

    // ── Filtre Risque Réel ────────────────────────────────────────────────────
    RiskFilter.init(() => render());

    // ── Raccourci navbar "🔗 IOC" — active directement la pill IOC du RiskFilter ─
    document.getElementById("btn-ioc-filter")?.addEventListener("click", () => {
      // Ouvrir la barre Risque si elle est masquée (pour que l'état soit visible)
      const bar = document.getElementById("risk-filter-bar");
      if (bar && bar.style.display === "none") RiskFilter.toggle();
      // Toggle la pill IOC — déclenche render() via _notify()
      RiskFilter.togglePill("ioc");
      // Synchroniser l'état actif du bouton navbar
      const btn = document.getElementById("btn-ioc-filter");
      if (btn) btn.classList.toggle("active", RiskFilter.getFilters().active.has("ioc"));
    });

    // ── Modal détail article ──────────────────────────────────────────────────
    ArticleModal.init();

    // ── PWA (Service Worker, install prompt, offline) ─────────────────────────
    PWA.init();

    // ── Mise à jour compteur favoris ──────────────────────────────────────────
    const favCount = document.getElementById("fav-count");
    if (favCount) favCount.textContent = Storage.getFavoriteCount();

    // ── Restaurer le persona stocké — filtres AVANT le premier rendu ─────────
    // Évite le flash "all articles" : les filtres sont en place quand refresh()
    // appelle render() pour la première fois avec les articles chargés.
    if (typeof PersonaPresets !== 'undefined') PersonaPresets.silentRestoreFilters();

    // ── Restauration depuis le cache persistant (TTL 6 h) ─────────────────────
    // Affiche immédiatement les articles de la session précédente pendant que
    // refresh() revalide en arrière-plan. Aucun rendu visible si cache absent.
    const _restoredArticles = Storage.getArticles();
    if (_restoredArticles && _restoredArticles.length > 0) {
      console.log(`[App] Restored ${_restoredArticles.length} articles from long-lived cache`);
      // Ensure watchlistMatches is always derived from watchlistMatchItems when missing
      // (cache path skips contextualize(), leaving the two arrays potentially out of sync)
      state.articles = typeof Contextualizer !== 'undefined'
        ? Contextualizer.ensureWatchlistConsistency(_restoredArticles)
        : _restoredArticles;
      // Normalise iocCount from real arrays — prevents stale counts after cache restore
      // (iocCount can drift from actual iocs arrays when extraction logic changes between sessions)
      if (typeof IOCExtractor !== 'undefined')
        state.articles.forEach(a => { a.iocCount = IOCExtractor.getRealIOCCount(a); });
      render();
      StatsPanel.update(_restoredArticles);
      VendorPanel.update(_restoredArticles);
      CVEPanel.update(_restoredArticles, _buildCveNvdMap());
      IncidentPanel.update(_restoredArticles);
      VisibilityPanel.update(_restoredArticles);
      if (typeof ProfilePanel  !== 'undefined') ProfilePanel.update(_restoredArticles);
      if (typeof ExecView      !== 'undefined') ExecView.update(_restoredArticles);
      ArticleModal.setArticles(_restoredArticles, state.nvdMap);
      try {
        const envStats = (typeof IncidentPanel !== 'undefined') ? IncidentPanel.getEnvironmentContextStats() : null;
        state.lastRefreshMode = 'restore';
        state.previousArticleCount = _restoredArticles.length;
        // Try to get last fresh fetch timestamp from localStorage if available
        try {
          const freshFetchTs = localStorage.getItem('cv_last_fresh_fetch_at');
          if (freshFetchTs) state.lastFreshFetchAt = parseInt(freshFetchTs, 10);
        } catch {}
        const feedHealth = _getPriorityFeedHealth();
        OpsPanel.update({
          sourceMode: 'restore',
          articleCount: _restoredArticles.length,
          lastFreshFetchAt: state.lastFreshFetchAt,
          feedHealth,
          environmentContextStats: envStats
        });
      } catch {}
      _updateRefreshButtonStatus();  // Update freshness indicator on button
    } else {
      console.log("[App] No articles restored from long-lived cache");
    }

    // ── Lancer le premier fetch (met à jour / remplace le cache restauré) ─────
    await refresh(false);
    console.log(`[App] Initial refresh completed · state.articles=${state.articles?.length || 0}`);

    // ── Ouvrir le panneau du persona restauré (données maintenant disponibles) ─
    if (typeof PersonaPresets !== 'undefined') PersonaPresets.silentRestorePanel();

    scheduleRefresh();
  }

  // ── API publique filtres (pour SavedFilters) ──────────────────────────────
  function getFilters() {
    return {
      query:         state.query,
      criticality:   state.criticality,
      source:        state.source,
      date:          state.date,
      priorityLevel: state.priorityLevel,
      sortBy:        state.sortBy,
      statusFilter:  state.statusFilter,
      showFavOnly:   state.showFavOnly,
      showUnreadOnly: state.showUnreadOnly
    };
  }
  function setFilters(f) {
    if (f.query !== undefined) {
      state.query = f.query;
      const el = document.getElementById("search-input");
      if (el) el.value = f.query;
    }
    if (f.criticality !== undefined) {
      state.criticality = f.criticality;
      const el = document.getElementById("filter-criticality");
      if (el) el.value = f.criticality;
    }
    if (f.source !== undefined) {
      state.source = f.source;
      const el = document.getElementById("filter-source");
      if (el) el.value = f.source;
    }
    if (f.date !== undefined) {
      state.date = f.date;
      const el = document.getElementById("filter-date");
      if (el) el.value = f.date;
    }
    if (f.priorityLevel !== undefined) {
      state.priorityLevel = f.priorityLevel;
      const el = document.getElementById("filter-priority-level");
      if (el) el.value = f.priorityLevel;
    }
    if (f.sortBy !== undefined) {
      state.sortBy = f.sortBy;
      const el = document.getElementById("sort-by");
      if (el) el.value = f.sortBy;
    }
    if (f.statusFilter !== undefined) {
      state.statusFilter = f.statusFilter;
      const el = document.getElementById("filter-status");
      if (el) el.value = f.statusFilter;
    }
    if (f.showFavOnly !== undefined) {
      state.showFavOnly = f.showFavOnly;
      const btn = document.getElementById("btn-favs");
      if (btn) btn.classList.toggle("active", f.showFavOnly);
    }
    if (f.showUnreadOnly !== undefined) {
      state.showUnreadOnly = f.showUnreadOnly;
      const btn = document.getElementById("btn-unread");
      if (btn) btn.classList.toggle("active", f.showUnreadOnly);
    }
    render();
  }
  function getActivePanel() {
    const panels = [
      { id: "cve-panel",         view: "cves" },
      { id: "incident-panel",    view: "incidents" },
      { id: "vendor-panel",      view: "vendors" },
      { id: "visibility-panel",  view: "visibility" },
      { id: "stats-panel",       view: "stats" },
      { id: "briefing-panel",    view: "briefing" },
      { id: "health-panel",      view: "health" }
    ];
    for (const { id, view } of panels) {
      const el = document.getElementById(id);
      if (el && el.style.display !== "none") return view;
    }
    return "main";
  }

  // ─── New since last visit — API publique ──────────────────────────────────

  /** Active le filtre "depuis ma dernière visite" — ouvre la vue dédiée. */
  function filterNewSinceVisit() {
    state.date = "lastvisit";
    state._nsvDismissed = true;
    const el = document.getElementById("filter-date");
    if (el) el.value = "lastvisit";
    render(); // _updateNewBadge + _updateContextBar appelés dans render()
  }

  /** Quitte la vue NSV et revient à "All time". */
  function exitNewSinceVisit() {
    state.date = "all";
    state._nsvDismissed = false; // Restaure le badge pour la session
    const el = document.getElementById("filter-date");
    if (el) el.value = "all";
    render(); // masque la context bar, re-affiche le badge si non dismissed
  }

  /** Masque le badge NSV sans activer le filtre. */
  function dismissNewBadge() {
    state._nsvDismissed = true;
    _updateNewBadge();
  }

  // ─── Recent searches API ──────────────────────────────────────────────────
  /**
   * Applique une recherche récente en mettant à jour l'input et en déclenchant render().
   * Appelée via les boutons du panel recent-searches-panel.
   */
  function applyRecentSearch(query) {
    state.query = query;
    const searchInput = document.getElementById("search-input");
    if (searchInput) searchInput.value = query;
    // Mettre à jour lastSavedQuery pour éviter un doublon immédiat
    state.lastSavedQuery = query;
    render();
  }

  /**
   * Vide l'historique des recherches récentes et ferme le panel.
   * La recherche actuelle et les résultats restent inchangés.
   */
  function clearRecentSearchHistory() {
    Storage.clearRecentSearches();
    _updateRecentSearches();
  }

  /**
   * Supprime une recherche individuelle de l'historique récent.
   * Remet à jour le panel. La recherche actuelle reste inchangée.
   */
  function removeRecentSearch(query) {
    Storage.removeRecentSearch(query);
    _updateRecentSearches();
  }

  return { init, refreshForced: () => refresh(true), getFilters, setFilters, getActivePanel,
           filterByCVE, filterByCVEs, clearRowCVEFilter, clearCVEFilter,
           filterNewSinceVisit, exitNewSinceVisit, dismissNewBadge, applyRecentSearch, clearRecentSearchHistory, removeRecentSearch,
           filterByAttack, clearAttackFilter, getAttackFilter };
})();

// Démarrer quand le DOM est prêt
document.addEventListener("DOMContentLoaded", () => App.init());
