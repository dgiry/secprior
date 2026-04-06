// tv1-sync.js — Trend Vision One Watchlist Sync (client v2 — hardened)
//
// Calls /api/tv1-sync, normalizes the result, merges into watchlist,
// and handles the full lifecycle of TV1-synced items.
//
// Politique items obsolètes (live sync uniquement) :
//   Les items source:'tv1' absents du dernier retour TV1 live sont désactivés
//   (enabled:false) sans être supprimés. Les items manuels ne sont jamais touchés.
//   En mode démo, aucune désactivation — la démo ne reflète pas l'inventaire réel.
//
// Métadonnées de sync persistées dans cv_tv1_config :
//   lastSyncAt      — ISO timestamp de la dernière sync
//   lastSyncResult  — 'success' | 'demo' | 'error'
//   lastSyncSource  — 'tv1_live' | 'tv1_demo'
//   lastSyncAdded   — nombre d'items ajoutés
//   lastSyncDisabled — nombre d'items TV1 désactivés (obsolètes, live seulement)
//
// API publique :
//   TV1Sync.loadConfig()                 — config persistée (region + lastSync)
//   TV1Sync.saveConfig(cfg)              — persist config
//   TV1Sync.fetchPreview()               — fetch /api/tv1-sync, mappe errorCodes en FR
//   TV1Sync.importItems(items)           — merge sans doublons, retourne { added, skipped }
//   TV1Sync.markObsoleteItems(values)    — désactive les items TV1 absents de values[] (live)
//   TV1Sync.syncFull(result)             — import + obsolète + persist metadata → { added, skipped, disabled }

const TV1Sync = (() => {

  // One-shot cleanup: remove orphaned cache key from removed trend-vp feature
  try { localStorage.removeItem('cv_trend_vp_cache'); } catch {}

  const CONFIG_KEY = "cv_tv1_config";

  // ── Messages d'erreur FR mappés depuis errorCode API ─────────────────────────

  const ERROR_MESSAGES = {
    AUTH_INVALID:  "Clé API TV1 invalide — vérifiez TV1_API_KEY dans les variables Vercel.",
    AUTH_SCOPE:    "Scope insuffisant (HTTP 403) — le token TV1 doit avoir le scope endpoint-security:read.",
    RATE_LIMITED:  "TV1 : limite de débit atteinte — réessayez dans quelques minutes.",
    TIMEOUT:       "Délai TV1 dépassé — vérifiez la région sélectionnée.",
    NETWORK_ERROR: "Impossible de joindre TV1 — vérifiez la connexion.",
    TV1_ERROR:     "Erreur TV1 API — réessayez ou vérifiez la configuration.",
  };

  // ── Persistence ─────────────────────────────────────────────────────────────

  function loadConfig() {
    try { return JSON.parse(localStorage.getItem(CONFIG_KEY) || "{}"); } catch { return {}; }
  }

  function saveConfig(cfg) {
    try { localStorage.setItem(CONFIG_KEY, JSON.stringify(cfg)); } catch {}
  }

  function _saveLastSync(patch) {
    const cfg = loadConfig();
    saveConfig({ ...cfg, ...patch });
  }

  // ── Fetch preview depuis le backend ─────────────────────────────────────────
  //
  // Mappe les errorCodes API en messages lisibles FR.
  // Les erreurs d'auth (401/403) retournent HTTP 200 avec demo data + errorCode +
  // _authWarning pour que l'UI puisse afficher un avertissement explicite.

  async function fetchPreview() {
    const cfg    = loadConfig();
    const region = cfg.region || "us";
    const url    = `/api/tv1-sync?region=${encodeURIComponent(region)}`;

    let res;
    try {
      res = await fetch(url, { signal: AbortSignal.timeout(20_000) });
    } catch (e) {
      if (e.name === "TimeoutError" || e.name === "AbortError") {
        throw new Error(ERROR_MESSAGES.TIMEOUT);
      }
      throw new Error(ERROR_MESSAGES.NETWORK_ERROR);
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      // Map structured errorCode to FR message when available
      if (err.errorCode && ERROR_MESSAGES[err.errorCode]) {
        const msg = err.errorCode === "RATE_LIMITED" && err.retryAfterSeconds
          ? `TV1 : limite de débit atteinte — réessayez dans ${err.retryAfterSeconds}s.`
          : ERROR_MESSAGES[err.errorCode];
        throw new Error(msg);
      }
      throw new Error(err.error || `Erreur HTTP ${res.status}`);
    }

    const result = await res.json();

    // Auth errors return HTTP 200 (with demo data) but carry an errorCode.
    // Surface them as _authWarning so the UI can warn without blocking the preview.
    if (result.errorCode && ERROR_MESSAGES[result.errorCode]) {
      result._authWarning = ERROR_MESSAGES[result.errorCode];
    }

    return result;
  }

  // ── Import items dans la watchlist ──────────────────────────────────────────
  //
  // Merge sans écraser les entrées existantes.
  // Retourne { added, skipped }.

  function importItems(items) {
    if (!Array.isArray(items) || items.length === 0) return { added: 0, skipped: 0 };

    const wl = Contextualizer.getWatchlist();
    const existingValues = new Set(
      wl.map(i => typeof i === "string" ? i.toLowerCase() : (i.value || ""))
    );

    let added   = 0;
    let skipped = 0;
    const syncedAt = new Date().toISOString();
    const merged   = [...wl];

    for (const item of items) {
      const val = String(item.value || item.label || "").toLowerCase().trim();
      if (!val) continue;

      if (existingValues.has(val)) {
        skipped++;
        continue;
      }

      merged.push({
        id:       "tv1_" + Math.random().toString(36).slice(2, 10),
        type:     item.type  || "keyword",
        label:    item.label || item.value,
        value:    val,
        enabled:  true,
        priority: "medium",
        source:   "tv1",
        syncedAt
      });
      existingValues.add(val);
      added++;
    }

    if (added > 0) {
      Contextualizer.saveWatchlist(merged);
    }

    return { added, skipped };
  }

  // ── Désactiver les items TV1 obsolètes (live sync uniquement) ───────────────
  //
  // Politique : les items source:'tv1' absents de currentValues sont désactivés
  // (enabled:false) sans être supprimés. Les items manuels ne sont jamais touchés.
  //
  // Un champ staleAt est ajouté pour traçabilité (date de désactivation).
  // L'utilisateur peut réactiver manuellement depuis le modal watchlist.
  //
  // Retourne le nombre d'items désactivés.

  function markObsoleteItems(currentValues) {
    if (!Array.isArray(currentValues) || currentValues.length === 0) return 0;

    const currentSet = new Set(currentValues.map(v => String(v).toLowerCase().trim()));
    const wl         = Contextualizer.getWatchlist();
    let   disabled   = 0;
    const staleAt    = new Date().toISOString();

    const updated = wl.map(item => {
      // Règle 1 : ne jamais toucher aux items manuels
      if (item.source !== "tv1") return item;
      // Règle 2 : ne pas re-désactiver ce qui l'est déjà
      if (!item.enabled) return item;
      // Règle 3 : si l'item est encore dans TV1 → le garder actif
      if (currentSet.has(item.value)) return item;

      // Item TV1 absent du dernier retour live → désactiver
      disabled++;
      return { ...item, enabled: false, staleAt };
    });

    if (disabled > 0) {
      Contextualizer.saveWatchlist(updated);
    }

    return disabled;
  }

  // ── Sync complète : import + obsolète + métadonnées ─────────────────────────
  //
  // Orchestrateur principal recommandé.
  // • Importe les nouveaux items
  // • Si source live : désactive les items TV1 absents du retour (politique obsolète)
  // • Persiste les métadonnées de sync (lastSyncAt, etc.)
  // • Rafraîchit le modal watchlist si ouvert
  //
  // Retourne { added, skipped, disabled }

  function syncFull(result) {
    if (!result?.items) return { added: 0, skipped: 0, disabled: 0 };

    const isLive = result.source === "tv1_live";

    // 1. Import des nouveaux items
    const { added, skipped } = importItems(result.items);

    // 2. Politique obsolète — live seulement (la démo ne reflète pas l'inventaire réel)
    const disabled = isLive
      ? markObsoleteItems(result.items.map(i => i.value))
      : 0;

    // 3. Persister les métadonnées de la sync
    _saveLastSync({
      lastSyncAt:       new Date().toISOString(),
      lastSyncResult:   result._authWarning ? "demo_auth_error" : (isLive ? "success" : "demo"),
      lastSyncSource:   result.source,
      lastSyncAdded:    added,
      lastSyncDisabled: disabled,
      lastSyncTotal:    result.count || result.items.length
    });

    // 4. Rafraîchir le modal watchlist si visible
    if (typeof WatchlistModal !== "undefined" && typeof WatchlistModal.refresh === "function") {
      WatchlistModal.refresh();
    }

    return { added, skipped, disabled };
  }

  return {
    loadConfig,
    saveConfig,
    fetchPreview,
    importItems,
    markObsoleteItems,
    syncFull
  };

})();
