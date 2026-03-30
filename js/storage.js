// storage.js — Couche d'abstraction LocalStorage
// Gère le cache des articles et les favoris

const CACHE_KEY    = "cv_cache";
const FAV_KEY      = "cv_favorites";

// ── Persistance articles post-pipeline ────────────────────────────────────────
// Clé séparée de cv_cache (articles bruts, 5 min) — ici articles entièrement
// enrichis (score, KEV, EPSS, watchlist, priorité) avec TTL long (6 h).
// Bump ARTICLES_VER dès que le schéma article du pipeline change
// pour invalider automatiquement les caches clients existants.
const ARTICLES_KEY = "cv_articles";
const ARTICLES_TTL = 6 * 60 * 60 * 1000; // 6 heures
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
  }
};
