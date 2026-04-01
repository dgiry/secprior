// app.js — Point d'entrée et orchestration de CyberVeille Pro

const App = (() => {
  // État global de l'application
  const state = {
    articles: [],         // Tous les articles chargés
    nvdMap: {},           // { articleId: cveData } — données NVD enrichies
    query: "",
    criticality: "all",
    source: "all",
    date: "all",
    priorityLevel: "all", // all | critical_now | investigate | watch | low
    sortBy: "default",    // default (date) | priority (priorityScore desc)
    statusFilter: "all",  // all | new | acknowledged | investigating | mitigated | ignored
    showFavOnly: false,
    timerId: null,
    _cveLinkId:  null,    // CVE unique (clic sur une ligne) — priorité haute
    _cveLinkIds: null     // Tableau de CVEs (filtre panneau) — priorité basse
  };

  // ─── Refresh principal via Pipeline ────────────────────────────────────────
  async function refresh(force = false) {
    console.log(`[App] refresh() begin · force=${force}`);
    UI.showSpinner(true);
    try {
      // ── Pipeline 6 étapes : Collecter → Enrichir → Dédupliquer → Scorer → Contextualiser
      const articles = await Pipeline.run(force);
      console.log(`[App] refresh() pipeline returned ${articles.length} articles`);
      if (articles.length === 0) console.warn("[App] refresh(): pipeline returned 0 articles");
      state.articles = articles;
      console.log(`[App] state.articles set (${state.articles.length})`);

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

      // Mettre à jour le dashboard stats
      StatsPanel.update(articles);
      VendorPanel.update(articles);
      CVEPanel.update(articles);
      IncidentPanel.update(articles);
      VisibilityPanel.update(articles);
      if (typeof ProfilePanel !== 'undefined') ProfilePanel.update(articles);

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

      // ── NVD keyword search : trouver les CVE manquants (non-bloquant) ─────
      // Pour les articles avec vendor connu mais 0 CVE dans le texte RSS.
      if (!isDemo && CONFIG.USE_API) {
        Enricher.enrichMissingCVEs(articles, (articleId, newCveIds) => {
          const target = state.articles.find(a => a.id === articleId);
          if (!target) return;
          target.cves = [...new Set([...(target.cves || []), ...newCveIds])];
          // Mettre à jour tous les panneaux avec les nouveaux CVE IDs
          CVEPanel.update(state.articles);
          Storage.setArticles(state.articles);
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
        state.articles = cache.items.map(a => ({ ...a, pubDate: new Date(a.pubDate) }));
        console.warn(`[App] Using fallback cache with ${state.articles.length} items after refresh error`);
        render();
        if (!state.articles?.length) console.warn("[App] render() called with empty cache items");
        UI.showToast("Affichage depuis le cache local.", "warning");
        // En ligne mais refresh en échec → état dégradé (distingué du vrai hors-ligne)
        if (typeof PWA !== 'undefined' && navigator.onLine) {
          try { PWA.setAppConnectivityState('degraded'); } catch {}
        }
      }
    } finally {
      UI.showSpinner(false);
      console.log("[App] refresh() end");
    }
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
    });
  }

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

    const filtered = UI.applyFilters(articlesToFilter, {
      query:         state.query,
      criticality:   state.criticality,
      source:        state.source,
      date:          state.date,
      priorityLevel: state.priorityLevel,
      sortBy:        state.sortBy,
      statusFilter:  state.statusFilter,
      showFavOnly:   state.showFavOnly,
      riskFilters:   RiskFilter.getFilters()   // { active: Set, epssThreshold }
    });
    UI.renderCards(filtered);
    RiskFilter.setCount(filtered.length);     // mise à jour compteur dans la barre
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

  // ─── Dropdown groups navbar (Analytics, Tools) ────────────────────────────
  function _closeNavDropdowns() {
    document.querySelectorAll(".nav-menu-popover").forEach(p => { p.style.display = "none"; });
    document.querySelectorAll(".nav-menu-trigger").forEach(t => t.classList.remove("active"));
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

  // ─── Initialisation ────────────────────────────────────────────────────────
  async function init() {
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
    document.getElementById("search-input")?.addEventListener("input", e => {
      state.query = e.target.value.trim();
      render();
    });

    document.getElementById("filter-criticality")?.addEventListener("change", e => {
      state.criticality = e.target.value;
      render();
    });

    document.getElementById("filter-source")?.addEventListener("change", e => {
      state.source = e.target.value;
      render();
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
    });

    document.getElementById("filter-status")?.addEventListener("change", e => {
      state.statusFilter = e.target.value;
      render();
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
      const filtered = UI.applyFilters(state.articles, state);
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

    // ── Panneau Vendors / Assets exposés ──────────────────────────────────────
    VendorPanel.init();
    document.getElementById("btn-vendors")?.addEventListener("click", () => VendorPanel.toggle());

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
      state.articles = _restoredArticles;
      render();
      StatsPanel.update(_restoredArticles);
      VendorPanel.update(_restoredArticles);
      CVEPanel.update(_restoredArticles);
      IncidentPanel.update(_restoredArticles);
      VisibilityPanel.update(_restoredArticles);
      if (typeof ProfilePanel !== 'undefined') ProfilePanel.update(_restoredArticles);
      ArticleModal.setArticles(_restoredArticles, state.nvdMap);
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
      showFavOnly:   state.showFavOnly
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

  return { init, refreshForced: () => refresh(true), getFilters, setFilters, getActivePanel,
           filterByCVE, filterByCVEs, clearRowCVEFilter, clearCVEFilter };
})();

// Démarrer quand le DOM est prêt
document.addEventListener("DOMContentLoaded", () => App.init());
