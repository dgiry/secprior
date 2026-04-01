// feed-manager.js — Gestionnaire de flux RSS (logique pure, sans DOM)
//
// Responsabilités :
//   - Fusionner flux par défaut (CONFIG.FEEDS) + flux custom (localStorage)
//   - CRUD : ajouter, modifier, supprimer, activer/désactiver
//   - Validation des URLs et noms
//   - Test live d'un flux via la mécanique réseau existante (fetchFeed)
//   - Suivi de la santé (lastStatus, lastTestAt, lastItemCount, …)

const FeedManager = (() => {

  const STORAGE_KEY  = "cv_custom_feeds";   // flux créés par l'utilisateur
  const OVERRIDE_KEY = "cv_feed_overrides"; // enabled/disabled des flux par défaut
  const HEALTH_KEY   = "cv_feed_health";    // santé des flux par défaut (séparé du config)

  // ── Persistence helpers ─────────────────────────────────────────────────────

  function _load(key, fallback) {
    try { return JSON.parse(localStorage.getItem(key)) ?? fallback; }
    catch { return fallback; }
  }
  function _save(key, val) {
    try {
      localStorage.setItem(key, JSON.stringify(val));
      return true;
    } catch (e) {
      console.warn("[FeedManager] localStorage write failed:", e.message);
      return false;
    }
  }

  function loadCustomFeeds()        { return _load(STORAGE_KEY,  []); }
  function saveCustomFeeds(feeds)   { _save(STORAGE_KEY, feeds); }
  function _loadOverrides()         { return _load(OVERRIDE_KEY, {}); }
  function _saveOverrides(ov)       { _save(OVERRIDE_KEY, ov); }
  function _loadHealth()            { return _load(HEALTH_KEY, {}); }
  function _saveHealth(h)           { _save(HEALTH_KEY, h); }

  // ── Catégorie déduite pour les flux par défaut ──────────────────────────────

  function _inferCategory(feed) {
    const id = feed.id.toLowerCase();
    if (["certfr","cisa","ncsc"].includes(id)) return "cert";
    if (["welivesecurity","sans","zdi"].includes(id)) return "exploit";
    if (["talos","unit42","securelist"].includes(id))  return "threat";
    return "news";
  }

  // ── Construction de la liste complète ──────────────────────────────────────

  /**
   * Retourne tous les flux (défaut + custom) avec état enabled + santé injectés.
   * C'est le point d'entrée unique pour l'UI et pour la logique de filtrage.
   */
  function getAllFeeds() {
    const overrides = _loadOverrides();
    const health    = _loadHealth();

    const defaults = (CONFIG.FEEDS || []).map(f => ({
      id:               f.id,
      name:             f.name,
      url:              f.url,
      category:         _inferCategory(f),
      icon:             f.icon || "📡",
      lang:             f.lang || "en",
      enabled:          overrides[f.id] !== undefined ? overrides[f.id] : true,
      isDefault:        true,
      addedAt:          null,
      lastTestAt:       null,
      lastSuccessAt:    null,
      lastErrorAt:      null,
      lastErrorMessage: "",
      lastStatus:       "unknown",
      lastItemCount:    null,
      ...(health[f.id] || {})      // injecter santé persistée
    }));

    const custom = loadCustomFeeds();
    return [...defaults, ...custom];
  }

  /**
   * Retourne uniquement les flux actifs (enabled === true).
   * Utilisé par fetchAllFeeds() dans feeds.js.
   */
  function getActiveFeeds() {
    return getAllFeeds().filter(f => f.enabled);
  }

  /** Nombre de flux actifs (pour la barre de statut). */
  function getActiveCount() { return getActiveFeeds().length; }

  // ── Validation ──────────────────────────────────────────────────────────────

  /**
   * Valide un objet flux avant sauvegarde ou test.
   * @param {object} feed    - { name, url, … }
   * @param {string} skipId  - ID à ignorer pour la détection de doublon (edit)
   * @returns {{ valid: boolean, errors: string[] }}
   */
  function validateFeed(feed, skipId = null) {
    const errors = [];
    const name   = (feed.name || "").trim();
    const url    = (feed.url  || "").trim();

    // Nom
    if (!name)           errors.push("Le nom est requis");
    else if (name.length > 80) errors.push("Name too long (max 80 characters)");

    // URL
    if (!url) {
      errors.push("L'URL est requise");
    } else {
      try {
        const parsed = new URL(url);
        if (!["http:", "https:"].includes(parsed.protocol))
          errors.push("L'URL doit commencer par http:// ou https://");
        if (!parsed.hostname || parsed.hostname.length < 3)
          errors.push("Le domaine de l'URL semble invalide");
      } catch {
        errors.push("L'URL n'est pas valide (ex: https://example.com/feed.xml)");
      }
    }

    // Doublon d'URL
    if (errors.length === 0) {
      const norm = u => u.trim().replace(/\/+$/, "").toLowerCase();
      const all  = getAllFeeds();
      const dup  = all.find(f => f.id !== skipId && norm(f.url) === norm(url));
      if (dup) errors.push(`This URL is already used by «${dup.name}»`);
    }

    return { valid: errors.length === 0, errors };
  }

  // ── CRUD ────────────────────────────────────────────────────────────────────

  /**
   * Ajoute un nouveau flux personnalisé.
   * @returns {{ ok: boolean, feed?: object, errors?: string[] }}
   */
  function addFeed(data) {
    const v = validateFeed(data);
    if (!v.valid) return { ok: false, errors: v.errors };

    const feeds = loadCustomFeeds();
    const feed  = {
      id:               "feed_" + Date.now().toString(36),
      name:             data.name.trim(),
      url:              data.url.trim(),
      category:         data.category  || "news",
      icon:             (data.icon || "").trim() || "📡",
      lang:             data.lang      || "en",
      enabled:          true,
      isDefault:        false,
      addedAt:          new Date().toISOString(),
      lastTestAt:       null,
      lastSuccessAt:    null,
      lastErrorAt:      null,
      lastErrorMessage: "",
      lastStatus:       "unknown",
      lastItemCount:    null
    };

    feeds.push(feed);
    const saved = _save(STORAGE_KEY, feeds);
    if (!saved) return { ok: false, errors: ["Insufficient storage (localStorage full). Delete custom feeds."] };
    console.log("[FeedManager] Flux ajouté :", feed.name, feed.id);
    return { ok: true, feed };
  }

  /**
   * Met à jour un flux personnalisé existant.
   * @param {string} feedId
   * @param {object} patch  - champs à écraser
   * @returns {{ ok: boolean, feed?: object, errors?: string[], error?: string }}
   */
  function updateFeed(feedId, patch) {
    const feeds = loadCustomFeeds();
    const idx   = feeds.findIndex(f => f.id === feedId);
    if (idx === -1) return { ok: false, error: "Feed not found" };

    const merged = { ...feeds[idx], ...patch };
    // Revalider seulement si les champs structurants changent
    if (patch.name !== undefined || patch.url !== undefined) {
      const v = validateFeed(merged, feedId);
      if (!v.valid) return { ok: false, errors: v.errors };
    }

    feeds[idx] = merged;
    saveCustomFeeds(feeds);
    return { ok: true, feed: feeds[idx] };
  }

  /**
   * Supprime un flux personnalisé (les flux par défaut ne peuvent pas être supprimés).
   * @returns {{ ok: boolean, error?: string }}
   */
  function removeFeed(feedId) {
    const feeds = loadCustomFeeds();
    const idx   = feeds.findIndex(f => f.id === feedId);
    if (idx === -1) return { ok: false, error: "Feed not found (or default feed cannot be deleted)" };
    const name = feeds[idx].name;
    feeds.splice(idx, 1);
    saveCustomFeeds(feeds);
    console.log("[FeedManager] Flux supprimé :", name, feedId);
    return { ok: true };
  }

  /**
   * Active ou désactive un flux (fonctionne pour défaut et custom).
   * @param {string}  feedId
   * @param {boolean} enabled
   * @returns {{ ok: boolean, error?: string }}
   */
  function toggleFeed(feedId, enabled) {
    // Flux custom
    const feeds = loadCustomFeeds();
    const idx   = feeds.findIndex(f => f.id === feedId);
    if (idx !== -1) {
      feeds[idx].enabled = enabled;
      saveCustomFeeds(feeds);
      return { ok: true };
    }
    // Flux par défaut → override
    const isDefault = (CONFIG.FEEDS || []).some(f => f.id === feedId);
    if (!isDefault) return { ok: false, error: "Feed not found" };
    const ov = _loadOverrides();
    ov[feedId] = enabled;
    _saveOverrides(ov);
    return { ok: true };
  }

  // ── Suivi de santé ──────────────────────────────────────────────────────────

  function _updateHealth(feedId, result, isDefault) {
    const now = new Date().toISOString();
    if (isDefault) {
      const h = _loadHealth();
      const prev = h[feedId] || {};
      h[feedId] = {
        lastTestAt:       now,
        lastStatus:       result.ok ? "ok" : "error",
        lastSuccessAt:    result.ok  ? now                       : (prev.lastSuccessAt || null),
        lastErrorAt:      result.ok  ? (prev.lastErrorAt || null) : now,
        lastErrorMessage: result.ok  ? ""                        : result.message,
        lastItemCount:    result.ok  ? result.itemCount          : (prev.lastItemCount  ?? null)
      };
      _saveHealth(h);
    } else {
      const feeds = loadCustomFeeds();
      const idx   = feeds.findIndex(f => f.id === feedId);
      if (idx === -1) return;
      feeds[idx].lastTestAt = now;
      feeds[idx].lastStatus = result.ok ? "ok" : "error";
      if (result.ok) {
        feeds[idx].lastSuccessAt    = now;
        feeds[idx].lastItemCount    = result.itemCount;
        feeds[idx].lastErrorMessage = "";
      } else {
        feeds[idx].lastErrorAt      = now;
        feeds[idx].lastErrorMessage = result.message;
      }
      saveCustomFeeds(feeds);
    }
  }

  // ── Test d'un flux ──────────────────────────────────────────────────────────

  /**
   * Teste un flux en tentant de le récupérer via la mécanique réseau de feeds.js.
   * Met à jour l'état de santé du flux après le test.
   *
   * @param   {object} feed - objet flux complet (id, url, name, isDefault, …)
   * @returns {{ ok: boolean, itemCount: number, message: string }}
   */
  async function testFeed(feed) {
    try {
      // fetchFeed() est défini dans feeds.js, chargé après feed-manager.js
      const articles = await fetchFeed(feed);
      const result = {
        ok:        true,
        itemCount: articles.length,
        message:   articles.length > 0
          ? `Valid feed — ${articles.length} articles found`
          : "Feed accessible but empty (0 articles fetched)"
      };
      _updateHealth(feed.id, result, !!feed.isDefault);
      return result;
    } catch (e) {
      const result = {
        ok:        false,
        itemCount: 0,
        message:   e.message || "Network error, CORS issue or invalid XML format"
      };
      _updateHealth(feed.id, result, !!feed.isDefault);
      return result;
    }
  }

  // ── Utilitaires ─────────────────────────────────────────────────────────────

  /** Supprime tous les flux personnalisés. */
  function resetCustomFeeds() {
    _save(STORAGE_KEY, []);
    console.log("[FeedManager] Flux custom réinitialisés");
  }

  /** Réactive tous les flux par défaut (supprime les overrides). */
  function restoreDefaultFeeds() {
    _save(OVERRIDE_KEY, {});
    console.log("[FeedManager] Flux par défaut restaurés");
  }

  // ── Initialisation des flux par défaut pour les nouveaux profils ──────────

  /**
   * Injecte un pack de flux par défaut si le profil actif n'en a aucun configuré.
   * Appelé une seule fois au démarrage si le profil est vierge.
   * Ne modifie jamais les flux existants.
   */
  function initializeDefaultFeedsIfEmpty() {
    // Vérifier si des flux custom existent déjà
    const custom = loadCustomFeeds();
    if (custom.length > 0) return; // profil a déjà des flux → ne rien faire

    // Vérifier si au moins un flux par défaut est activé
    const active = getActiveFeeds();
    if (active.length > 0) return; // au moins un flux actif → ne rien faire

    // Profil vierge : injecter le pack par défaut
    const defaultPack = [
      { id: "certfr-alertes",    name: "CERT-FR Alertes",      enabled: true },
      { id: "certfr-bulletins",  name: "CERT-FR Bulletins",    enabled: true },
      { id: "cisa",              name: "CISA Advisories",      enabled: true },
      { id: "zdi",               name: "Zero Day Initiative",  enabled: true },
      { id: "thehackernews",     name: "The Hacker News",      enabled: true },
      { id: "krebsonsecurity",   name: "Krebs on Security",    enabled: true },
      { id: "securityweek",      name: "SecurityWeek",         enabled: true },
      { id: "bleepingcomputer",  name: "BleepingComputer",     enabled: true },
      { id: "sans",              name: "SANS ISC",             enabled: true },
      { id: "talos",             name: "Cisco Talos",          enabled: true },
      { id: "unit42",            name: "Unit 42",              enabled: true },
      { id: "ncsc",              name: "NCSC UK",              enabled: true }
    ];

    // Activer uniquement les flux par défaut qui existent dans CONFIG.FEEDS
    const ov = _loadOverrides();
    const configIds = new Set((CONFIG.FEEDS || []).map(f => f.id));
    defaultPack.forEach(item => {
      if (configIds.has(item.id)) {
        ov[item.id] = item.enabled;
      }
    });
    _saveOverrides(ov);

    console.log("[FeedManager] Default feeds initialized for new profile");
    if (typeof UI !== 'undefined') {
      UI.showToast("📡 Default feeds enabled", "info");
    }
  }

  /**
   * Met à jour la santé d'un flux après un fetch automatique (appelé par feeds.js).
   * Même logique que _updateHealth, mais exposée publiquement.
   */
  function recordFetchResult(feed, ok, itemCount, errorMessage) {
    _updateHealth(feed.id, {
      ok,
      itemCount: itemCount ?? 0,
      message:   errorMessage || ""
    }, !!feed.isDefault);
  }

  // ── API publique ────────────────────────────────────────────────────────────
  return {
    loadCustomFeeds,
    saveCustomFeeds,
    getAllFeeds,
    getActiveFeeds,
    getActiveCount,
    addFeed,
    updateFeed,
    removeFeed,
    toggleFeed,
    testFeed,
    validateFeed,
    resetCustomFeeds,
    restoreDefaultFeeds,
    recordFetchResult,
    initializeDefaultFeedsIfEmpty
  };

})();
