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
    showFavOnly: false,
    timerId: null
  };

  // ─── Refresh principal via Pipeline ────────────────────────────────────────
  async function refresh(force = false) {
    UI.showSpinner(true);
    try {
      // ── Pipeline 6 étapes : Collecter → Enrichir → Dédupliquer → Scorer → Contextualiser
      const articles = await Pipeline.run(force);
      state.articles = articles;

      // Notifier les nouvelles alertes critiques (browser)
      UI.notifyCritical(articles);

      // Afficher avec filtres actuels
      render();
      UI.updateTimestamp();

      // Mettre à jour le dashboard stats
      StatsPanel.update(articles);

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

      // ── Étape 6 : Alertes email/webhook intelligentes (non-bloquant) ─────
      if (!isDemo) {
        AlertManager.processNewArticles(articles);
      }
    } catch (err) {
      console.error("[App] Erreur refresh:", err);
      UI.showToast("Erreur lors du chargement des flux RSS. Vérifiez la connexion.", "error");
      const cache = Storage.getCache();
      if (cache && cache.items) {
        state.articles = cache.items.map(a => ({ ...a, pubDate: new Date(a.pubDate) }));
        render();
        UI.showToast("Affichage depuis le cache local.", "warning");
      }
    } finally {
      UI.showSpinner(false);
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
    const filtered = UI.applyFilters(state.articles, {
      query:        state.query,
      criticality:  state.criticality,
      source:       state.source,
      date:         state.date,
      showFavOnly:  state.showFavOnly,
      riskFilters:  RiskFilter.getFilters()   // { active: Set, epssThreshold }
    });
    UI.renderCards(filtered);
    RiskFilter.setCount(filtered.length);     // mise à jour compteur dans la barre
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
    // ── Charger les feeds depuis l'API (source canonique) ─────────────────
    // await garantit que CONFIG.FEEDS est à jour AVANT tout appel à FeedManager
    await _loadFeedsFromAPI();

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

    // ── Watchlist modal ───────────────────────────────────────────────────────
    WatchlistModal.init();

    // ── Dashboard statistiques ────────────────────────────────────────────────
    StatsPanel.init();

    // ── Panneau Briefing ──────────────────────────────────────────────────────
    BriefingPanel.init();
    document.getElementById("btn-briefing")?.addEventListener("click", () => BriefingPanel.toggle());

    // ── Rapport PDF hebdomadaire ──────────────────────────────────────────────
    PDFReport.init();

    // ── Filtre Risque Réel ────────────────────────────────────────────────────
    RiskFilter.init(() => render());

    // ── Modal détail article ──────────────────────────────────────────────────
    ArticleModal.init();

    // ── PWA (Service Worker, install prompt, offline) ─────────────────────────
    PWA.init();

    // ── Mise à jour compteur favoris ──────────────────────────────────────────
    const favCount = document.getElementById("fav-count");
    if (favCount) favCount.textContent = Storage.getFavoriteCount();

    // ── Lancer le premier fetch ───────────────────────────────────────────────
    await refresh(false);
    scheduleRefresh();
  }

  return { init, refreshForced: () => refresh(true) };
})();

// Démarrer quand le DOM est prêt
document.addEventListener("DOMContentLoaded", () => App.init());
