// storage.js — Couche d'abstraction LocalStorage
// Gère le cache des articles et les favoris

const CACHE_KEY         = "cv_cache";
const FAV_KEY           = "cv_favorites";
const READ_KEY          = "cv_read_articles";
const REVIEWED_KEY      = "cv_reviewed_articles";
const RECENT_SEARCHES_KEY = "cv_recent_searches";
const RECENT_SEARCHES_MAX = 5;

// ── Persistance articles post-pipeline ────────────────────────────────────────
// Clé séparée de cv_cache (articles bruts, 5 min) — ici articles entièrement
// enrichis (score, KEV, EPSS, watchlist, priorité) avec TTL modéré (30 min).
// TTL réduit de 6h → 30min pour que force refresh visibles immédiatement.
// Bump ARTICLES_VER dès que le schéma article du pipeline change
// pour invalider automatiquement les caches clients existants.
const ARTICLES_KEY = "cv_articles";
const ARTICLES_TTL = 30 * 60 * 1000; // 30 minutes (was 6 hours)
const ARTICLES_VER = 1;                   // à incrémenter si format change

const Storage = {
  // ─── Cache articles ────────────────────────────────────────────────────────

  getCache() {
    try {
      const raw = localStorage.getItem(CACHE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  },

  setCache(articles) {
    try {
      // Limiter la taille pour éviter QuotaExceededError
      const trimmed = articles.slice(0, CONFIG.MAX_ITEMS);
      localStorage.setItem(CACHE_KEY, JSON.stringify({
        items: trimmed,
        cachedAt: Date.now()
      }));
    } catch (e) {
      console.warn("[Storage] Cache write failed:", e.message);
    }
  },

  isCacheStale() {
    const cache = this.getCache();
    if (!cache || !cache.cachedAt) return true;
    return (Date.now() - cache.cachedAt) > CONFIG.CACHE_TTL;
  },

  // ─── Favoris ───────────────────────────────────────────────────────────────

  getFavorites() {
    try {
      const raw = localStorage.getItem(FAV_KEY);
      return raw ? new Set(JSON.parse(raw)) : new Set();
    } catch { return new Set(); }
  },

  toggleFavorite(id) {
    const favs = this.getFavorites();
    if (favs.has(id)) {
      favs.delete(id);
    } else {
      favs.add(id);
    }
    try {
      localStorage.setItem(FAV_KEY, JSON.stringify([...favs]));
    } catch (e) {
      console.warn("[Storage] Favorites write failed:", e.message);
    }
    return favs.has(id);
  },

  isFavorite(id) {
    return this.getFavorites().has(id);
  },

  getFavoriteCount() {
    return this.getFavorites().size;
  },

  // ─── Articles revus (triage léger) ────────────────────────────────────────

  getReviewed() {
    try {
      const raw = localStorage.getItem(REVIEWED_KEY);
      return raw ? new Set(JSON.parse(raw)) : new Set();
    } catch { return new Set(); }
  },

  toggleReviewed(id) {
    const reviewed = this.getReviewed();
    if (reviewed.has(id)) {
      reviewed.delete(id);
    } else {
      reviewed.add(id);
    }
    try {
      localStorage.setItem(REVIEWED_KEY, JSON.stringify([...reviewed]));
    } catch (e) {
      console.warn("[Storage] Reviewed write failed:", e.message);
    }
    return reviewed.has(id);
  },

  isReviewed(id) {
    return this.getReviewed().has(id);
  },

  getReviewedCount() {
    return this.getReviewed().size;
  },

  clearCache() {
    try { localStorage.removeItem(CACHE_KEY); } catch (e) {
      console.warn("[Storage] clearCache failed:", e.message);
    }
  },

  // ─── Articles post-pipeline (persistance longue durée, TTL 6 h) ────────────

  /**
   * Persiste les articles entièrement enrichis issus du pipeline.
   * Limite à CONFIG.MAX_ITEMS pour éviter QuotaExceededError.
   */
  setArticles(articles) {
    try {
      const trimmed = articles.slice(0, CONFIG.MAX_ITEMS);
      localStorage.setItem(ARTICLES_KEY, JSON.stringify({
        v:    ARTICLES_VER,
        ts:   Date.now(),
        data: trimmed
      }));
    } catch (e) {
      console.warn("[Storage] setArticles failed:", e.message);
    }
  },

  /**
   * Retourne les articles persistés, ou null si :
   *   - aucun cache présent
   *   - version obsolète (schéma pipeline changé → ARTICLES_VER bumped)
   *   - TTL expiré (> 6 h)
   * pubDate est restauré en objet Date.
   */
  getArticles() {
    try {
      const raw = localStorage.getItem(ARTICLES_KEY);
      if (!raw) return null;
      const { v, ts, data } = JSON.parse(raw);
      if (v !== ARTICLES_VER)             return null; // format obsolète
      if (Date.now() - ts > ARTICLES_TTL) return null; // TTL expiré
      return data.map(a => ({ ...a, pubDate: new Date(a.pubDate) }));
    } catch { return null; }
  },

  /**
   * Vide le cache articles (ex. : reset complet depuis les Paramètres).
   */
  clearArticles() {
    try { localStorage.removeItem(ARTICLES_KEY); } catch {}
  },

  // ─── Dernière visite (New since last visit) ───────────────────────────────

  /**
   * Retourne le timestamp de début de la session précédente,
   * utilisé pour identifier les articles "nouveaux" lors de cette session.
   * Retourne null si aucune session précédente n'est enregistrée.
   */
  getLastVisit() {
    try {
      const v = localStorage.getItem("cv_last_visit");
      return v ? parseInt(v, 10) : null;
    } catch { return null; }
  },

  /**
   * Enregistre le timestamp de début de session actuelle.
   * Appelé une seule fois par session (géré via sessionStorage dans app.js).
   */
  setLastVisit(ts) {
    try { localStorage.setItem("cv_last_visit", String(ts)); } catch {}
  },

  // ─── Suivi lu/non-lu (Read tracking) ──────────────────────────────────────

  /**
   * Retourne l'ensemble des articles marqués comme lus.
   */
  getRead() {
    try {
      const raw = localStorage.getItem(READ_KEY);
      return raw ? new Set(JSON.parse(raw)) : new Set();
    } catch { return new Set(); }
  },

  /**
   * Marque un article comme lu.
   * Idempotent : peut être appelé plusieurs fois sans effet de bord.
   */
  markRead(id) {
    const read = this.getRead();
    if (!read.has(id)) {
      read.add(id);
      try {
        localStorage.setItem(READ_KEY, JSON.stringify([...read]));
      } catch (e) {
        console.warn("[Storage] markRead failed:", e.message);
      }
    }
  },

  /**
   * Toggle l'état lu/non-lu d'un article.
   */
  toggleRead(id) {
    const read = this.getRead();
    if (read.has(id)) {
      read.delete(id);
    } else {
      read.add(id);
    }
    try {
      localStorage.setItem(READ_KEY, JSON.stringify([...read]));
    } catch (e) {
      console.warn("[Storage] toggleRead failed:", e.message);
    }
    return read.has(id);
  },

  /**
   * Vérifie si un article est marqué comme lu.
   */
  isRead(id) {
    return this.getRead().has(id);
  },

  // ─── Historique recherches récentes ──────────────────────────────────────

  /**
   * Retourne l'historique des recherches récentes (array trié par recency).
   */
  getRecentSearches() {
    try {
      const raw = localStorage.getItem(RECENT_SEARCHES_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  },

  /**
   * Ajoute une recherche à l'historique si elle est significative.
   * Évite les doublons consécutifs et les chaînes vides.
   */
  addRecentSearch(query) {
    if (!query || query.trim() === "") return;

    const searches = this.getRecentSearches();
    const trimmed = query.trim();

    // Ne pas sauvegarder si c'est le même que le dernier
    if (searches.length > 0 && searches[0] === trimmed) return;

    // Ajouter au début
    searches.unshift(trimmed);

    // Garder seulement les N derniers
    const bounded = searches.slice(0, RECENT_SEARCHES_MAX);

    try {
      localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(bounded));
    } catch (e) {
      console.warn("[Storage] addRecentSearch failed:", e.message);
    }
  },

  /**
   * Supprime une recherche individuelle de l'historique.
   * Idempotent : ignorer si la recherche n'existe pas.
   */
  removeRecentSearch(query) {
    const searches = this.getRecentSearches();
    const filtered = searches.filter(s => s !== query);

    // Si la liste n'a pas changé, ignorer
    if (filtered.length === searches.length) return;

    try {
      if (filtered.length === 0) {
        localStorage.removeItem(RECENT_SEARCHES_KEY);
      } else {
        localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(filtered));
      }
    } catch (e) {
      console.warn("[Storage] removeRecentSearch failed:", e.message);
    }
  },

  /**
   * Vide l'historique des recherches.
   */
  clearRecentSearches() {
    try { localStorage.removeItem(RECENT_SEARCHES_KEY); } catch {}
  }
};
