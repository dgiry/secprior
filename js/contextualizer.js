// contextualizer.js — Stage 5 : Contextualisation intelligente
//
// Enrichit chaque article avec :
//   • watchlistMatches  : mots-clés de la watchlist utilisateur trouvés dans le texte
//   • attackTags        : tactiques MITRE ATT&CK détectées par mots-clés
//   • isTrending        : true si sourceCount ≥ 3 (sujet couvert par 3+ sources)
//   • trendingCount     : nombre de sources (= article.sourceCount)

const Contextualizer = (() => {
  const WATCHLIST_KEY = "cv_watchlist";

  // ── Table de correspondance MITRE ATT&CK (keyword → tactic) ────────────────

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

  // ── Watchlist (persistée en LocalStorage) ─────────────────────────────────

  function getWatchlist() {
    try {
      const raw = localStorage.getItem(WATCHLIST_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  }

  function saveWatchlist(list) {
    try {
      localStorage.setItem(WATCHLIST_KEY, JSON.stringify(list));
    } catch (e) { console.warn("[Contextualizer] Watchlist save:", e.message); }
  }

  function addToWatchlist(term) {
    const list = getWatchlist();
    const t = term.trim().toLowerCase();
    if (t && !list.includes(t)) {
      list.push(t);
      saveWatchlist(list);
    }
  }

  function removeFromWatchlist(term) {
    const list = getWatchlist().filter(t => t !== term.trim().toLowerCase());
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

  // ── Stage principal : contextualize(articles) ────────────────────────────

  function contextualize(articles) {
    const watchlist = getWatchlist();

    // ── Trending CVE-based (signal live) ──────────────────────────────────────
    // Pour chaque CVE, compter les sources distinctes qui le couvrent.
    // Si 2+ sources couvrent le même CVE → trending (signal fiable en mode live).
    const cveSourcesMap = {}; // { "CVE-2024-1234": Set(sourceId) }
    articles.forEach(a => {
      (a.cves || []).forEach(cve => {
        if (!cveSourcesMap[cve]) cveSourcesMap[cve] = new Set();
        cveSourcesMap[cve].add(a.source);
      });
    });

    return articles.map(a => {
      const text = (a.title + " " + (a.description || "")).toLowerCase();

      // Watchlist matches
      const watchlistMatches = watchlist.filter(term => text.includes(term));

      // ATT&CK detection
      const attackTags = _detectAttack(a.title + " " + (a.description || ""));

      // Trending : signal déduplicateur (3+ sources) OU CVE couvert par 2+ sources
      const scDedup = a.sourceCount || 1;
      const scCve   = (a.cves || []).reduce((max, cve) => {
        return Math.max(max, cveSourcesMap[cve]?.size || 1);
      }, 1);
      const sc = Math.max(scDedup, scCve);
      const isTrending   = scDedup >= 3 || scCve >= 2;
      const trendingCount = sc;

      return {
        ...a,
        watchlistMatches,
        attackTags,
        isTrending,
        trendingCount
      };
    });
  }

  return { contextualize, getWatchlist, saveWatchlist, addToWatchlist, removeFromWatchlist };
})();
