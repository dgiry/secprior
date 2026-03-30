// tv1-sync.js — Trend Vision One Watchlist Sync (client v1)
//
// Calls /api/tv1-sync, normalizes the result, and merges it into the
// ThreatLens watchlist without overwriting existing manual entries.
//
// Items imported via TV1 are tagged with  source: 'tv1'  for optional
// visual distinction in the watchlist modal.
//
// API publique :
//   TV1Sync.loadConfig()            — load persisted region
//   TV1Sync.saveConfig(cfg)         — persist region
//   TV1Sync.fetchPreview()          — fetch items from /api/tv1-sync (no import yet)
//   TV1Sync.importItems(items)      — merge items into watchlist, returns { added, skipped }

const TV1Sync = (() => {

  const CONFIG_KEY = "cv_tv1_config";

  // ── Persistence ─────────────────────────────────────────────────────────────

  function loadConfig() {
    try { return JSON.parse(localStorage.getItem(CONFIG_KEY) || "{}"); } catch { return {}; }
  }

  function saveConfig(cfg) {
    try { localStorage.setItem(CONFIG_KEY, JSON.stringify(cfg)); } catch {}
  }

  // ── Fetch preview from backend ───────────────────────────────────────────────
  //
  // Returns the raw /api/tv1-sync response:
  //   { items, source: 'tv1_live'|'tv1_demo', count, fetchedAt, note? }

  async function fetchPreview() {
    const cfg    = loadConfig();
    const region = cfg.region || "us";
    const url    = `/api/tv1-sync?region=${encodeURIComponent(region)}`;

    let res;
    try {
      res = await fetch(url, { signal: AbortSignal.timeout(18_000) });
    } catch (e) {
      if (e.name === "TimeoutError" || e.name === "AbortError") {
        throw new Error("Request timed out — TV1 API did not respond in time.");
      }
      throw new Error("Network error — check your connection.");
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    return await res.json();
  }

  // ── Import items into watchlist ──────────────────────────────────────────────
  //
  // Merges the provided items into the existing watchlist.
  // - Deduplicates by normalized value (no overwrite of existing entries)
  // - Adds source: 'tv1' and syncedAt timestamp to each new item
  // - Calls Contextualizer.saveWatchlist() to persist
  //
  // Returns { added: N, skipped: N }

  function importItems(items) {
    if (!Array.isArray(items) || items.length === 0) return { added: 0, skipped: 0 };

    const wl = Contextualizer.getWatchlist();

    // Build a Set of already-present normalized values
    const existingValues = new Set(
      wl.map(i => typeof i === "string" ? i.toLowerCase() : (i.value || ""))
    );

    let added   = 0;
    let skipped = 0;
    const syncedAt = new Date().toISOString();
    const merged   = [...wl]; // start from existing list

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
        source:   "tv1",      // distinguishes TV1-synced from manual entries
        syncedAt               // ISO timestamp for audit / display
      });
      existingValues.add(val);
      added++;
    }

    if (added > 0) {
      Contextualizer.saveWatchlist(merged);
      // Refresh the watchlist modal and navbar counter if visible
      if (typeof WatchlistModal !== "undefined" && typeof WatchlistModal.refresh === "function") {
        WatchlistModal.refresh();
      }
    }

    return { added, skipped };
  }

  return { loadConfig, saveConfig, fetchPreview, importItems };

})();
