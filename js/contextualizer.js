// contextualizer.js — Stage 5 : Contextualisation intelligente
//
// Enrichit chaque article avec :
//   • watchlistMatches     : labels des items watchlist trouvés (string[] — compat)
//   • watchlistMatchItems  : items watchlist complets trouvés (object[] — enrichi)
//   • attackTags           : tactiques MITRE ATT&CK détectées par mots-clés
//   • isTrending           : true si sourceCount ≥ 3 (sujet couvert par 3+ sources)
//   • trendingCount        : nombre de sources (= article.sourceCount)
//
// Format watchlist V2 (rétrocompatible avec ancien string[]) :
//   { id, type, label, value, enabled, priority }
//   Types  : vendor | product | technology | keyword
//   Priorités : high | medium | low

const Contextualizer = (() => {
  const WATCHLIST_KEY = "cv_watchlist";

  // ── Méta types et priorités ───────────────────────────────────────────────

  const WL_TYPES = {
    vendor:     { label: "Vendeur",  css: "wl-type-vendor"     },
    product:    { label: "Produit",  css: "wl-type-product"    },
    technology: { label: "Techno",   css: "wl-type-technology" },
    keyword:    { label: "Mot-clé",  css: "wl-type-keyword"    }
  };

  const WL_PRIORITIES = {
    high:   { label: "High",    dot: "🔴" },
    medium: { label: "Medium",  dot: "🟡" },
    low:    { label: "Low",     dot: "🟢" }
  };

  // ── Table de correspondance MITRE ATT&CK (keyword → tactic) ─────────────

  const ATTACK_MAP = [
    { keywords: ["phishing", "spear phishing", "spearphishing"],         tactic: "T1566", label: "Phishing" },
    { keywords: ["ransomware", "ransom"],                                  tactic: "T1486", label: "Ransomware" },
    { keywords: ["credential", "password", "brute force", "bruteforce"],  tactic: "T1110", label: "Brute Force" },
    { keywords: ["privilege escalation", "privesc"],                       tactic: "T1068", label: "Priv. Escalation" },
    { keywords: ["rce", "remote code execution"],                          tactic: "T1059", label: "Remote Exec." },
    { keywords: ["sql injection", "sqli"],                                 tactic: "T1190", label: "SQLi" },
    { keywords: ["xss", "cross-site scripting"],                           tactic: "T1059", label: "XSS" },
    { keywords: ["supply chain", "supply-chain"],                          tactic: "T1195", label: "Supply Chain" },
    { keywords: ["backdoor", "back door"],                                 tactic: "T1543", label: "Backdoor" },
    { keywords: ["c2", "command and control", "command-and-control"],      tactic: "T1071", label: "C2" },
    { keywords: ["exfiltration", "data theft", "data exfil"],              tactic: "T1041", label: "Exfiltration" },
    { keywords: ["lateral movement", "pass the hash"],                     tactic: "T1021", label: "Lateral Mvmt" },
    { keywords: ["persistence", "autostart"],                              tactic: "T1547", label: "Persistence" },
    { keywords: ["keylogger", "keylogging"],                               tactic: "T1056", label: "Input Capture" },
    { keywords: ["ddos", "denial of service", "dos attack"],               tactic: "T1498", label: "DDoS" },
    { keywords: ["zero-day", "0day", "zero day"],                          tactic: "T1203", label: "0-Day" },
    { keywords: ["watering hole"],                                          tactic: "T1189", label: "Watering Hole" },
    { keywords: ["apt", "nation-state", "nation state"],                   tactic: "TA0001", label: "APT" },
    { keywords: ["botnet", "bot net"],                                      tactic: "T1583", label: "Botnet" },
    { keywords: ["worm", "self-propagat"],                                  tactic: "T1091", label: "Worm" }
  ];

  // ── Watchlist V2 — normalisation rétrocompatible ──────────────────────────

  function _makeId() {
    return Math.random().toString(36).slice(2, 10);
  }

  /**
   * _normalizeItem(raw) — accepte string (ancien format) OU objet (nouveau).
   * Garantit : { id, type, label, value (lowercase), enabled, priority }
   */
  function _normalizeItem(raw) {
    if (typeof raw === 'string') {
      const v = raw.trim().toLowerCase();
      return { id: _makeId(), type: 'keyword', label: raw.trim(), value: v, enabled: true, priority: 'medium' };
    }
    const value = ((raw.value || raw.term || raw.label) || '').trim().toLowerCase();
    return {
      id:       raw.id       || _makeId(),
      type:     WL_TYPES[raw.type] ? raw.type : 'keyword',
      label:    raw.label    || raw.term  || raw.value || value,
      value,
      enabled:  raw.enabled  !== false,
      priority: WL_PRIORITIES[raw.priority] ? raw.priority : 'medium'
    };
  }

  /**
   * getWatchlist() — retourne toujours un tableau d'items normalisés.
   * Si ProfileManager est disponible, délègue au profil actif (multi-profil).
   * Sinon, fallback sur la lecture directe de WATCHLIST_KEY (rétrocompat).
   */
  function getWatchlist() {
    // Multi-profil : déléguer à ProfileManager si disponible
    if (typeof ProfileManager !== 'undefined') {
      const items = ProfileManager.getActiveWatchlist();
      return Array.isArray(items) ? items.map(_normalizeItem) : [];
    }

    // Fallback legacy : lecture directe de cv_watchlist
    try {
      const raw = localStorage.getItem(WATCHLIST_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];

      const items = parsed.map(_normalizeItem);

      // Migration silencieuse : si au moins un item était un string, on resauvegarde
      const hadOldFormat = parsed.some(i => typeof i === 'string');
      if (hadOldFormat) saveWatchlist(items);

      return items;
    } catch { return []; }
  }

  /**
   * saveWatchlist(list) — persiste la watchlist.
   * Si ProfileManager est disponible, sauvegarde dans le profil actif.
   * Sinon, fallback sur l'écriture directe de WATCHLIST_KEY.
   */
  function saveWatchlist(list) {
    // Multi-profil : déléguer à ProfileManager si disponible
    if (typeof ProfileManager !== 'undefined') {
      ProfileManager.saveActiveWatchlist(list);
      return;
    }

    // Fallback legacy
    try {
      localStorage.setItem(WATCHLIST_KEY, JSON.stringify(list));
    } catch (e) { console.warn("[Contextualizer] Watchlist save:", e.message); }
  }

  /**
   * addToWatchlist(term, opts) — ajoute un item.
   * opts = { type, label, priority, enabled }
   * Déduplique par value (lowercase).
   */
  function addToWatchlist(term, opts = {}) {
    const list  = getWatchlist();
    const value = (term || '').trim().toLowerCase();
    if (!value) return;
    if (list.some(i => i.value === value)) return; // déjà présent
    list.push({
      id:       _makeId(),
      type:     WL_TYPES[opts.type] ? opts.type : 'keyword',
      label:    (opts.label || term).trim(),
      value,
      enabled:  opts.enabled !== false,
      priority: WL_PRIORITIES[opts.priority] ? opts.priority : 'medium'
    });
    saveWatchlist(list);
  }

  /**
   * removeFromWatchlist(idOrValue) — supprime par id (nouveau) ou par value (compat).
   */
  function removeFromWatchlist(idOrValue) {
    const normalized = (idOrValue || '').trim().toLowerCase();
    const list = getWatchlist().filter(i => i.id !== idOrValue && i.value !== normalized);
    saveWatchlist(list);
  }

  /**
   * updateItem(id, patch) — met à jour un item existant (type, priority, enabled…)
   */
  function updateItem(id, patch) {
    const list = getWatchlist().map(i => i.id !== id ? i : { ...i, ...patch });
    saveWatchlist(list);
  }

  // ── Détection ATT&CK ──────────────────────────────────────────────────────

  function _detectAttack(text) {
    const t = text.toLowerCase();
    const hits = [];
    for (const entry of ATTACK_MAP) {
      if (entry.keywords.some(kw => t.includes(kw))) {
        hits.push({ tactic: entry.tactic, label: entry.label });
      }
    }
    return hits;
  }

  // ── Stage principal : contextualize(articles) ─────────────────────────────

  function contextualize(articles) {
    // Seuls les items activés participent au matching
    const watchlist = getWatchlist().filter(i => i.enabled);

    // ── Trending CVE-based (signal live) ────────────────────────────────────
    const cveSourcesMap = {};
    articles.forEach(a => {
      (a.cves || []).forEach(cve => {
        if (!cveSourcesMap[cve]) cveSourcesMap[cve] = new Set();
        cveSourcesMap[cve].add(a.source);
      });
    });

    return articles.map(a => {
      const text = (a.title + " " + (a.description || "")).toLowerCase();

      // Watchlist matches enrichis
      const matchedItems = watchlist.filter(item => item.value && text.includes(item.value));
      // string[] pour compat ascendante (article-modal, computePriority, scorer)
      const watchlistMatches     = matchedItems.map(i => i.label);
      // object[] pour usage futur (computePriority prioritySignals, briefing, etc.)
      const watchlistMatchItems  = matchedItems;

      // ATT&CK detection
      const attackTags = _detectAttack(a.title + " " + (a.description || ""));

      // Trending : signal déduplicateur (3+ sources) OU CVE couvert par 2+ sources
      const scDedup = a.sourceCount || 1;
      const scCve   = (a.cves || []).reduce((max, cve) => {
        return Math.max(max, cveSourcesMap[cve]?.size || 1);
      }, 1);
      const sc           = Math.max(scDedup, scCve);
      const isTrending   = scDedup >= 3 || scCve >= 2;
      const trendingCount = sc;

      return { ...a, watchlistMatches, watchlistMatchItems, attackTags, isTrending, trendingCount };
    });
  }

  /**
   * ensureWatchlistConsistency(articles) — normalise watchlistMatches sur des
   * articles restaurés depuis le cache qui n'ont pas repassé par contextualize().
   *
   * Cause racine du bug : contextualize() peuple toujours watchlistMatches ET
   * watchlistMatchItems, mais un article re-scoré (re-scorer sans re-contextualiser,
   * ou restauré tel quel depuis le cache long-lived) peut avoir watchlistMatchItems
   * renseigné et watchlistMatches vide (ou absent). Les consommateurs (Morning Brief,
   * Exec View, badges ui.js) doivent pouvoir se fier à watchlistMatches.
   *
   * Idempotent : sans effet si watchlistMatches est déjà renseigné.
   * Coût : O(n) sur le tableau, aucun accès DOM ni réseau.
   */
  function ensureWatchlistConsistency(articles) {
    if (!Array.isArray(articles)) return articles;
    return articles.map(a => {
      if ((a.watchlistMatchItems?.length > 0) && !(a.watchlistMatches?.length > 0)) {
        return {
          ...a,
          watchlistMatches: a.watchlistMatchItems
            .map(i => i.label || i.value)
            .filter(Boolean)
        };
      }
      return a;
    });
  }

  return {
    contextualize,
    ensureWatchlistConsistency,
    getWatchlist,
    saveWatchlist,
    addToWatchlist,
    removeFromWatchlist,
    updateItem,
    WL_TYPES,
    WL_PRIORITIES
  };
})();
