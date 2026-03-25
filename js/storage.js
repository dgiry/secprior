// storage.js — Couche d'abstraction LocalStorage
// Gère le cache des articles et les favoris

const CACHE_KEY = "cv_cache";
const FAV_KEY   = "cv_favorites";

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
  }
};
