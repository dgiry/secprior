// config.js — Configuration centrale de CyberVeille Pro
// Modifiez REFRESH_INTERVAL et FEEDS selon vos besoins

const CONFIG = {
  // ── Détection environnement ────────────────────────────────────────────────
  // true  → déployé sur Vercel : toutes les APIs passent par /api/...
  //          (clés sécurisées côté serveur dans les Variables d'Environnement Vercel)
  // false → développement local OU hébergement statique (Hostinger, GitHub Pages…)
  //          → les proxies CORS (allorigins.win) sont utilisés à la place
  //
  // ── Si vous utilisez un domaine custom Vercel, ajoutez-le ici ─────────────
  // Ex : ["cyberveille.monentreprise.fr", "soc-dashboard.com"]
  VERCEL_CUSTOM_DOMAINS: [
    // "mondomaine.com"
  ],

  // USE_API est calculé dynamiquement — ne pas modifier directement.
  // Pour forcer le mode production sur un domaine non listé : ajoutez-le à VERCEL_CUSTOM_DOMAINS.
  get USE_API() {
    if (typeof location === "undefined") return false;
    const host = location.hostname;
    // Domaines Vercel natifs (.vercel.app)
    if (host.endsWith(".vercel.app")) return true;
    // Domaines custom explicitement déclarés dans VERCEL_CUSTOM_DOMAINS
    if (this.VERCEL_CUSTOM_DOMAINS.includes(host)) return true;
    // Tout autre domaine (local, Hostinger, GitHub Pages…) → mode statique
    return false;
  },

  // Proxy CORS de fallback (local uniquement, jamais en production)
  PROXY_URL: "https://api.allorigins.win/get?url=",

  REFRESH_INTERVAL: 600_000, // 10 minutes
  CACHE_TTL: 300_000,        // 5 minutes avant de considérer le cache périmé
  MAX_ITEMS: 300,            // Limite stockage LocalStorage

  // ── NVD API (NIST National Vulnerability Database) ─────────────────────
  // En local : appel direct NVD (clé optionnelle dans le champ ci-dessous)
  // Sur Vercel : appel via /api/nvd (clé NVD_API_KEY dans les env vars Vercel)
  NVD_API_URL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
  NVD_API_KEY:    "",          // Local seulement — sur Vercel, utiliser env var
  NVD_ENABLED:    true,        // Mettre false pour désactiver l'enrichissement

  // ── Alertes (paramètres modifiables via le modal ⚙️ Paramètres) ──────────
  // Les valeurs ci-dessous sont les DÉFAUTS ; l'utilisateur les remplace via
  // le modal et ils sont persistés en LocalStorage (clé "cv_alert_settings").
  ALERT_COOLDOWN_MIN: 30,      // Minutes entre deux alertes (évite le spam)
  ALERT_BATCH_SIZE:   5,       // Max articles par alerte envoyée

  // ── Feeds — FALLBACK STATIQUE ─────────────────────────────────────────────
  // Sur Vercel (USE_API=true), cette liste est remplacée au démarrage par
  // les données de GET /api/feeds (api/lib/feeds.js — source canonique unique).
  // Sur Hostinger / mode statique (USE_API=false), cette liste est utilisée
  // directement.  NE MODIFIER QUE api/lib/feeds.js pour changer les feeds.
  FEEDS: [
    {
      id: "thehackernews",
      name: "The Hacker News",
      url: "https://feeds.feedburner.com/TheHackersNews",
      lang: "en",
      icon: "🔴"
    },
    {
      id: "krebsonsecurity",
      name: "Krebs on Security",
      url: "https://krebsonsecurity.com/feed/",
      lang: "en",
      icon: "🔵"
    },
    {
      id: "bleepingcomputer",
      name: "Bleeping Computer",
      url: "https://www.bleepingcomputer.com/feed/",
      lang: "en",
      icon: "🟣"
    },
    {
      id: "zataz",
      name: "Zataz",
      url: "https://www.zataz.com/feed/",
      lang: "fr",
      icon: "🟠"
    },
    {
      id: "certfr",
      name: "CERT-FR",
      url: "https://www.cert.ssi.gouv.fr/feed/",
      lang: "fr",
      icon: "🇫🇷"
    },
    {
      id: "cisa",
      name: "CISA Advisories",
      url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
      lang: "en",
      icon: "🦅"
    },
    {
      id: "zdi",
      name: "Zero Day Initiative",
      url: "https://www.zerodayinitiative.com/rss/published/",
      lang: "en",
      icon: "💀"
    },
    {
      id: "welivesecurity",
      name: "WeLiveSecurity (ESET)",
      url: "https://www.welivesecurity.com/feed/",
      lang: "en",
      icon: "🧨"
    },
    {
      id: "sans",
      name: "SANS ISC",
      url: "https://isc.sans.edu/rssfeed_full.xml",
      lang: "en",
      icon: "⚡"
    },
    {
      id: "talos",
      name: "Cisco Talos",
      url: "https://blog.talosintelligence.com/rss/",
      lang: "en",
      icon: "🔬"
    },
    {
      id: "securelist",
      name: "Securelist (Kaspersky)",
      url: "https://securelist.com/feed/",
      lang: "en",
      icon: "🕵️"
    },
    {
      id: "unit42",
      name: "Unit 42 (Palo Alto)",
      url: "https://unit42.paloaltonetworks.com/feed/",
      lang: "en",
      icon: "🔭"
    },
    {
      id: "ncsc",
      name: "NCSC UK",
      url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
      lang: "en",
      icon: "🇬🇧"
    }
  ],

  // Mots-clés pour le scoring de criticité
  SCORER_HIGH: [
    "0day", "zero-day", "zero day", "actively exploited", "in the wild",
    "emergency patch", "critical vulnerability", "rce", "remote code execution",
    "ransomware", "exploit kit", "supply chain attack", "backdoor",
    "nation-state", "apt", "cvss 9", "cvss 10", "cvss:9", "cvss:10",
    "unauthenticated", "authentication bypass", "mass exploitation",
    "worm", "botnet", "firmware vulnerability", "cisa kev",
    "patch tuesday emergency", "out-of-band", "actively being exploited"
  ],

  SCORER_MEDIUM: [
    "vulnerability", "cve-", "patch", "security update", "breach",
    "malware", "phishing", "ddos", "data leak", "data breach",
    "privilege escalation", "sql injection", "xss", "csrf",
    "trojan", "spyware", "keylogger", "advisory", "disclosure",
    "security flaw", "weak authentication", "misconfiguration",
    "credential", "password", "leak", "exposed", "unpatched"
  ]
};
