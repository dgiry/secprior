// enricher.js — Stage 2 : Enrichissement des articles
//
// Sources d'enrichissement :
//   • EPSS (Exploit Prediction Scoring System) via api.first.org
//     → Probabilité d'exploitation d'un CVE dans les 30 prochains jours (0-1)
//   • CISA KEV (Known Exploited Vulnerabilities)
//     → Liste officielle des CVE exploités activement en production
//   • Extraction d'entités : vendeurs, produits, versions (regex)

const Enricher = (() => {
  const KEV_CACHE_KEY  = "cv_kev_cache";
  const EPSS_CACHE_KEY = "cv_epss_cache";
  const KEV_TTL        = 86_400_000; // 24h
  const EPSS_TTL       = 86_400_000; // 24h
  const CVE_REGEX      = /CVE-\d{4}-\d{4,}/gi;

  // ── Vendeurs & produits connus (extraction NER légère) ────────────────────
  const KNOWN_VENDORS = [
    "Microsoft","Cisco","Fortinet","Palo Alto","VMware","Apache","Linux","Windows",
    "Apple","macOS","iOS","iPadOS","tvOS","watchOS","visionOS","Xcode","iCloud",
    "Android","Chrome","Firefox","Safari","Edge","OpenSSL","Log4j","Spring",
    "nginx","Apache Tomcat","GitLab","GitHub","Atlassian","Confluence","Jira",
    "Exchange","SharePoint","Active Directory","Azure","AWS","GCP","Docker",
    "Kubernetes","Jenkins","Terraform","Okta","Citrix","Ivanti","Juniper",
    "SolarWinds","MOVEit","GoAnywhere","Progress","Barracuda","F5","BIG-IP",
    "Ivanti","Pulse Secure","GlobalProtect","Zimbra","WordPress","Drupal","Magento"
  ];

  const VENDOR_RE = new RegExp(
    `\\b(${KNOWN_VENDORS.map(v => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})\\b`,
    "gi"
  );

  // ── Produits → vendor parent (normalisation NER) ──────────────────────────
  // Quand un article mentionne "FortiGate" sans dire "Fortinet", on remonte
  // au vendor parent pour que les recherches "fortinet" fonctionnent.
  const PRODUCT_ALIASES = {
    // Fortinet
    "FortiGate":    "Fortinet", "FortiOS":       "Fortinet",
    "FortiManager": "Fortinet", "FortiClient":   "Fortinet",
    "FortiAnalyzer":"Fortinet", "FortiWeb":      "Fortinet",
    "FortiProxy":   "Fortinet", "FortiSwitch":   "Fortinet",
    "FortiSIEM":    "Fortinet", "FortiEDR":      "Fortinet",
    "FortiNAC":     "Fortinet", "FortiSOAR":     "Fortinet",
    "FortiMail":    "Fortinet",
    // Apple
    "macOS":        "Apple",    "iOS":           "Apple",
    "iPadOS":       "Apple",    "tvOS":          "Apple",
    "watchOS":      "Apple",    "visionOS":      "Apple",
    "Xcode":        "Apple",    "iCloud":        "Apple",
    "Safari":       "Apple",
    // Palo Alto Networks
    "PAN-OS":       "Palo Alto",
    // VMware / Broadcom
    "vCenter":      "VMware",   "ESXi":          "VMware",
    "vSphere":      "VMware",   "Workstation":   "VMware",
    // Cisco
    "IOS XE":       "Cisco",    "NX-OS":         "Cisco",
    "Meraki":       "Cisco",    "Webex":         "Cisco",
    // Ivanti
    "EPMM":         "Ivanti",   "MobileIron":    "Ivanti",
  };

  const PRODUCT_RE = new RegExp(
    `\\b(${Object.keys(PRODUCT_ALIASES)
      .map(p => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join("|")})\\b`,
    "gi"
  );

  // ── CISA KEV ──────────────────────────────────────────────────────────────

  async function _fetchKEV() {
    const cached = _loadCache(KEV_CACHE_KEY, KEV_TTL);
    // Ne pas réutiliser un cache vide — forcer un nouveau fetch
    if (cached && Object.keys(cached).length > 0) return cached;

    // Sur Vercel : /api/kev (JSON direct, cache CDN 24h côté serveur)
    // En local   : allorigins.win (JSON wrappé dans .contents)
    const url = CONFIG.USE_API
      ? "/api/kev"
      : CONFIG.PROXY_URL +
        encodeURIComponent(
          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        );

    try {
      const res  = await fetch(url, { signal: AbortSignal.timeout(15_000) });
      const json = await res.json();
      // allorigins enveloppe dans { contents: "..." }, /api/kev renvoie le JSON direct
      const data = typeof json.contents === "string" ? JSON.parse(json.contents) : json;
      const kevMap = {};
      (data.vulnerabilities || []).forEach(v => {
        kevMap[v.cveID] = {
          dateAdded:        v.dateAdded,
          vendorProject:    v.vendorProject,
          product:          v.product,
          vulnerabilityName:v.vulnerabilityName || "",
          requiredAction:   v.requiredAction,
          dueDate:          v.dueDate
        };
      });
      // Ne cacher que si on a récupéré des données réelles
      if (Object.keys(kevMap).length > 0) _saveCache(KEV_CACHE_KEY, kevMap);
      console.log(`[Enricher] KEV chargé — ${Object.keys(kevMap).length} CVE`);
      return kevMap;
    } catch (e) {
      console.warn("[Enricher] KEV fetch échoué:", e.message);
      return _loadCache(KEV_CACHE_KEY, Infinity) || {}; // fallback cache périmé
    }
  }

  // ── EPSS (batch) ──────────────────────────────────────────────────────────

  async function _fetchEPSS(cveIds) {
    if (!cveIds.length) return {};

    const epssCache = _loadCache(EPSS_CACHE_KEY, EPSS_TTL) || {};
    const missing   = cveIds.filter(id => !(id in epssCache));

    if (missing.length === 0) return epssCache;

    // Sur Vercel : /api/epss?cves=... (batch jusqu'à 1000, cache CDN 24h)
    // En local   : appel direct api.first.org (batch 100, pas de cache serveur)
    const BATCH = CONFIG.USE_API ? 500 : 100;

    for (let i = 0; i < missing.length; i += BATCH) {
      const chunk = missing.slice(i, i + BATCH);
      const query = chunk.join(",");
      const url   = CONFIG.USE_API
        ? `/api/epss?cves=${encodeURIComponent(query)}`
        : `https://api.first.org/data/v1/epss?cve=${query}`;

      try {
        const res  = await fetch(url, { signal: AbortSignal.timeout(10_000) });
        const json = await res.json();
        (json.data || []).forEach(entry => {
          epssCache[entry.cve] = {
            score:      parseFloat(entry.epss),
            percentile: parseFloat(entry.percentile),
            date:       entry.date
          };
        });
      } catch (e) {
        console.warn(`[Enricher] EPSS batch ${i}-${i+BATCH} échoué:`, e.message);
      }
    }

    _saveCache(EPSS_CACHE_KEY, epssCache);
    return epssCache;
  }

  // ── KEV reverse lookup ────────────────────────────────────────────────────
  // Quand un article a un vendor connu mais 0 CVE extrait du texte RSS,
  // cherche dans le KEV si un produit matche le titre de l'article.
  // Ex : "FortiClientEMS" (KEV product) ⊆ "forticlientems" (titre normalisé)
  function _kevReverseLookup(text, vendors, kevMap) {
    if (!kevMap || Object.keys(kevMap).length === 0) return [];

    // Normalise : minuscule, supprime espaces/tirets/points
    const norm    = s => s.toLowerCase().replace(/[\s\-_.\/]/g, "");
    const textN   = norm(text);
    const vendorSet = new Set(vendors.map(v => v.toLowerCase()));

    const matches = [];
    for (const [cveId, entry] of Object.entries(kevMap)) {
      // Le vendor doit correspondre — matching souple pour gérer les variantes
      // ex. KEV dit "Palo Alto Networks", notre enricher extrait "Palo Alto"
      const entryVendor = (entry.vendorProject || "").toLowerCase();
      const vendorMatch = [...vendorSet].some(v =>
        entryVendor === v ||           // exact
        entryVendor.startsWith(v) ||   // "palo alto networks".startsWith("palo alto") ✓
        v.startsWith(entryVendor)      // cas inverse
      );
      if (!vendorMatch) continue;

      // Le nom du produit doit apparaître dans le texte (normalisé)
      const productN = norm(entry.product || "");
      if (productN.length >= 5 && textN.includes(productN)) {
        matches.push(cveId);
        continue;
      }

      // Fallback : mots-clés du vulnerabilityName (sans le prefix vendor)
      if (entry.vulnerabilityName) {
        const vulnN = norm(entry.vulnerabilityName)
          .replace(norm(entry.vendorProject || ""), "")
          .slice(0, 25);
        if (vulnN.length >= 5 && textN.includes(vulnN)) {
          matches.push(cveId);
        }
      }
    }

    return [...new Set(matches)].slice(0, 3);
  }

  // ── NVD keyword search (async, background) ────────────────────────────────
  // Appelé après le pipeline principal pour enrichir les articles sans CVE.
  // Utilise /api/nvd-search (Vercel) ou NVD direct si USE_API est false.
  async function _nvdKeywordSearch(query) {
    try {
      const url = CONFIG.USE_API
        ? `/api/nvd-search?q=${encodeURIComponent(query)}`
        : `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=5`;

      const res  = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      if (!res.ok) return [];
      const json = await res.json();

      // /api/nvd-search renvoie { cves: [{id, ...}] }
      // NVD direct renvoie { vulnerabilities: [{cve: {id, ...}}] }
      if (json.cves) return json.cves.map(c => c.id);
      return (json.vulnerabilities || []).map(v => v.cve.id);
    } catch { return []; }
  }

  // Enrichit en arrière-plan les articles sans CVE ID via NVD keyword search.
  // Non-bloquant : appelle onUpdate(article, newCves) pour chaque match.
  async function enrichMissingCVEs(articles, onUpdate) {
    if (!CONFIG.USE_API) return; // NVD direct hors Vercel → trop lent

    const candidates = articles.filter(a =>
      (a.cves || []).length === 0 &&
      (a.vendors || []).length > 0 &&
      a.title
    ).slice(0, 8); // max 8 requêtes par refresh

    for (const article of candidates) {
      // Construire la requête : vendor + mots clés du titre (sans stop words)
      const titleWords = article.title
        .replace(/critical|vulnerability|exploit|attack|flaw|patch|update|zero.?day|actively|now|multiple|new|CVE/gi, "")
        .trim().slice(0, 80);
      const query = `${(article.vendors || [])[0] || ""} ${titleWords}`.trim();

      const cveIds = await _nvdKeywordSearch(query);
      if (cveIds.length > 0) {
        onUpdate(article.id, cveIds.slice(0, 3));
        console.log(`[Enricher] NVD trouvé ${cveIds[0]} pour "${article.title.slice(0, 50)}"`);
      }

      // Respecter le rate-limit NVD (5 req/30s sans clé API)
      await new Promise(r => setTimeout(r, 700));
    }
  }

  // ── Extraction entités ────────────────────────────────────────────────────

  function _extractEntities(text) {
    const vendorSet = new Set((text.match(VENDOR_RE) || []).map(v => v.trim()));

    // Remonter les produits vers leur vendor parent (ex. "FortiGate" → "Fortinet")
    (text.match(PRODUCT_RE) || []).forEach(p => {
      const key    = Object.keys(PRODUCT_ALIASES).find(k => k.toLowerCase() === p.toLowerCase());
      const parent = key ? PRODUCT_ALIASES[key] : null;
      if (parent) vendorSet.add(parent);
    });

    const vendors  = [...vendorSet];
    const cves     = [...new Set((text.match(CVE_REGEX) || []).map(c => c.toUpperCase()))];
    // Version numbers: vX.X.X ou X.X.X (basique)
    const versions = [...new Set((text.match(/\bv?\d+\.\d+(?:\.\d+)?\b/g) || []))].slice(0, 5);
    return { vendors, cves, versions };
  }

  // ── Stage principal : enrich(articles) ────────────────────────────────────

  async function enrich(articles) {
    // Collecter tous les CVE IDs du corpus
    const allCVEs = [...new Set(
      articles.flatMap(a => {
        const text = a.title + " " + (a.description || "");
        return (text.match(CVE_REGEX) || []).map(c => c.toUpperCase());
      })
    )];

    // Fetch EPSS + KEV en parallèle
    const [epssMap, kevMap] = await Promise.all([
      _fetchEPSS(allCVEs),
      _fetchKEV()
    ]);

    // Enrichir chaque article
    return articles.map(a => {
      const text     = a.title + " " + (a.description || "");
      const entities = _extractEntities(text);

      // EPSS : prendre le score max des CVE de l'article
      let epssScore = null, epssPercentile = null;
      entities.cves.forEach(cveId => {
        const e = epssMap[cveId];
        if (e && (epssScore === null || e.score > epssScore)) {
          epssScore      = e.score;
          epssPercentile = e.percentile;
        }
      });

      // KEV : vrai si au moins un CVE de l'article est dans la KEV
      const kevMatches    = entities.cves.filter(id => kevMap[id]);
      const kevApiLive    = Object.keys(kevMap).length > 0;
      // Fallback : conserver isKEV pré-renseigné si l'API n'a retourné aucune donnée
      const isKEV         = kevMatches.length > 0 || (!kevApiLive && !!a.isKEV);
      const kevInfo       = kevMatches.length > 0 ? kevMap[kevMatches[0]] : null;

      // Fallback cves : garder les CVE pré-renseignés si l'extraction texte n'en trouve pas
      let resolvedCves = entities.cves.length > 0 ? entities.cves : (a.cves || []);

      // KEV reverse lookup : si toujours 0 CVE mais vendor connu,
      // chercher un match produit dans le catalogue KEV exploité
      if (resolvedCves.length === 0 && entities.vendors.length > 0) {
        const kevHits = _kevReverseLookup(text, entities.vendors, kevMap);
        if (kevHits.length > 0) {
          resolvedCves = kevHits;
          console.log(`[Enricher] KEV reverse match ${kevHits[0]} ← "${a.title?.slice(0, 50)}"`);
        }
      }

      // Fallback EPSS : conserver le score pré-renseigné si l'API n'a rien retourné
      const resolvedEpss        = epssScore      !== null ? epssScore      : (a.epssScore      ?? null);
      const resolvedEpssPercent = epssPercentile !== null ? epssPercentile : (a.epssPercentile ?? null);

      return {
        ...a,
        // Entités
        vendors:        entities.vendors,
        products:       entities.versions,
        cves:           resolvedCves,
        // EPSS
        epssScore:      resolvedEpss,
        epssPercentile: resolvedEpssPercent,
        // CISA KEV
        isKEV,
        kevDateAdded:   kevInfo?.dateAdded     || null,
        kevDueDate:     kevInfo?.dueDate       || null,
        kevAction:      kevInfo?.requiredAction || null
      };
    });
  }

  // ── Cache helpers ─────────────────────────────────────────────────────────

  function _loadCache(key, ttl) {
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return null;
      const { data, savedAt } = JSON.parse(raw);
      if (Date.now() - savedAt > ttl) return null;
      return data;
    } catch { return null; }
  }

  function _saveCache(key, data) {
    try {
      localStorage.setItem(key, JSON.stringify({ data, savedAt: Date.now() }));
    } catch (e) { console.warn("[Enricher] Cache write:", e.message); }
  }

  // ── API publique ──────────────────────────────────────────────────────────
  return { enrich, enrichMissingCVEs };
})();
