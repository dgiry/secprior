// nvd.js — Enrichissement CVE via NVD API officielle (NIST)
// https://nvd.nist.gov/developers/vulnerabilities
//
// - Extrait les CVE IDs des articles (regex)
// - Fetch les données CVSS depuis l'API NVD
// - Cache les résultats 24h dans LocalStorage
// - Rate-limit : 1 requête / 600ms (respecte les 5 req/30s sans clé API)

const NVD = (() => {
  const CACHE_KEY   = "cv_nvd_cache";
  const CACHE_TTL   = 86_400_000; // 24h en ms
  const REQ_DELAY   = 650;        // ms entre requêtes (conservateur)
  const CVE_REGEX   = /CVE-\d{4}-\d{4,}/gi;

  // Backoff dynamique suite à 429 sur /api/nvd (millisecondes epoch)
  let backoffUntil = 0;

  // Déduplication des requêtes en cours par CVE (cveId -> Promise)
  const inflight = new Map();

  // ── Cache LocalStorage ───────────────────────────────────────────────────

  function getCache() {
    try {
      const raw = localStorage.getItem(CACHE_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch { return {}; }
  }

  function saveCache(data) {
    try { localStorage.setItem(CACHE_KEY, JSON.stringify(data)); }
    catch (e) { console.warn("[NVD] Cache write failed:", e.message); }
  }

  function getCached(cveId) {
    const cache = getCache();
    const entry = cache[cveId.toUpperCase()];
    if (!entry) return null;
    if (Date.now() - entry.cachedAt > CACHE_TTL) return null; // expiré
    return entry.data;
  }

  function setCached(cveId, data) {
    const cache = getCache();
    cache[cveId.toUpperCase()] = { data, cachedAt: Date.now() };
    // Pruning : garder max 500 entrées (FIFO)
    const keys = Object.keys(cache);
    if (keys.length > 500) {
      const oldest = keys.sort((a, b) => cache[a].cachedAt - cache[b].cachedAt);
      oldest.slice(0, keys.length - 500).forEach(k => delete cache[k]);
    }
    saveCache(cache);
  }

  // ── Parsing réponse NVD ───────────────────────────────────────────────────

  function parseNVDResponse(json, cveId) {
    const vuln = json?.vulnerabilities?.[0]?.cve;
    if (!vuln) return null;

    // Score CVSS : préférer v3.1, fallback v3.0, puis v2.0
    const metricsV31 = vuln.metrics?.cvssMetricV31?.[0]?.cvssData;
    const metricsV30 = vuln.metrics?.cvssMetricV30?.[0]?.cvssData;
    const metricsV2  = vuln.metrics?.cvssMetricV2?.[0]?.cvssData;
    const metrics    = metricsV31 || metricsV30 || metricsV2;

    const score    = metrics?.baseScore ?? null;
    const severity = metrics?.baseSeverity
      ?? vuln.metrics?.cvssMetricV2?.[0]?.baseSeverity
      ?? null;
    const vector   = metrics?.vectorString ?? null;
    const version  = metricsV31 ? "3.1" : metricsV30 ? "3.0" : metricsV2 ? "2.0" : null;

    // Description EN (ou FR si dispo)
    const descriptions = vuln.descriptions ?? [];
    const descEN = descriptions.find(d => d.lang === "en")?.value ?? "";

    // Dates
    const published = vuln.published ?? null;
    const modified  = vuln.lastModified ?? null;

    // CWE
    const cwe = vuln.weaknesses?.[0]?.description?.[0]?.value ?? null;

    // Références
    const refs = (vuln.references ?? []).slice(0, 3).map(r => r.url);

    return {
      cveId: cveId.toUpperCase(),
      score,
      severity: severity?.toUpperCase() ?? scoreToCvssLabel(score),
      vector,
      cvssVersion: version,
      description: descEN.slice(0, 300),
      published,
      modified,
      cwe,
      refs
    };
  }

  function scoreToCvssLabel(score) {
    if (score === null || score === undefined) return "N/A";
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    return "LOW";
  }

  // ── CSS class selon score CVSS ────────────────────────────────────────────

  function cvssClass(score) {
    if (score === null || score === undefined) return "cvss-na";
    if (score >= 9.0) return "cvss-critical";
    if (score >= 7.0) return "cvss-high";
    if (score >= 4.0) return "cvss-medium";
    return "cvss-low";
  }

  // ── Fetch une CVE depuis l'API NVD ────────────────────────────────────────
  // Sur Vercel : /api/nvd?cveId=... (clé API sécurisée côté serveur, cache CDN 24h)
  // En local   : appel direct NVD (clé optionnelle dans CONFIG.NVD_API_KEY)

  async function fetchCVE(cveId) {
    const key = String(cveId).toUpperCase();

    // 1) Cache long (24h)
    const cached = getCached(key);
    if (cached !== null) return cached;

    // 2) Dédup requêtes en cours
    if (inflight.has(key)) return inflight.get(key);

    // 3) Construire la requête
    let url, headers = {};
    if (CONFIG.USE_API) {
      url = `/api/nvd?cveId=${encodeURIComponent(key)}`;
    } else {
      url = `${CONFIG.NVD_API_URL}?cveId=${encodeURIComponent(key)}`;
      if (CONFIG.NVD_API_KEY) headers["apiKey"] = CONFIG.NVD_API_KEY;
    }

    const p = (async () => {
      try {
        const res = await fetch(url, {
          headers,
          signal: AbortSignal.timeout(12_000)
        });

        // Gestion douce 429 (rate-limit) — activer backoff + ne pas mettre en cache null durable
        if (res.status === 429) {
          const ra = parseInt(res.headers.get("Retry-After") || "60", 10);
          const retryMs = isNaN(ra) ? 60_000 : ra * 1000;
          backoffUntil = Date.now() + retryMs;
          console.warn(`[NVD] 429 rate-limited for ${key}. Backing off ~${Math.round(retryMs/1000)}s`);
          return null;
        }

        if (!res.ok) {
          // Autres erreurs : ne pas bloquer le flux — cache null pour éviter le spam
          console.warn(`[NVD] HTTP ${res.status} for ${key}`);
          setCached(key, null);
          return null;
        }

        const json = await res.json();
        const data = parseNVDResponse(json, key);
        setCached(key, data);
        return data;
      } catch (e) {
        console.warn(`[NVD] Erreur fetch ${key}:`, e.message);
        // Erreur réseau : cache null pour limiter les re-tentatives immédiates
        setCached(key, null);
        return null;
      }
    })().finally(() => {
      inflight.delete(key);
    });

    inflight.set(key, p);
    return p;
  }

  // ── Helper : délai entre requêtes ─────────────────────────────────────────

  function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ── Extraire CVE IDs uniques d'un texte ──────────────────────────────────

  function extractCVEIds(text) {
    const matches = (text || "").match(CVE_REGEX) ?? [];
    return [...new Set(matches.map(id => id.toUpperCase()))];
  }

  // ── Enrichir un tableau d'articles ───────────────────────────────────────
  // Appelé en arrière-plan après le rendu initial
  // onEnrich(articleId, cveData) → callback pour mettre à jour la carte

  async function enrichArticles(articles, onEnrich) {
    // Construire la file : articles avec CVE IDs, dédupliquer les CVE
    const tasks = []; // [{ articleId, cveId }]
    const seen  = new Set();

    for (const article of articles) {
      const text   = article.title + " " + (article.description ?? "");
      const cveIds = extractCVEIds(text);
      for (const cveId of cveIds) {
        // Priorité aux articles récents (< 7 jours)
        const age = Date.now() - new Date(article.pubDate).getTime();
        if (age < 7 * 86_400_000 && !seen.has(cveId)) {
          seen.add(cveId);
          tasks.push({ articleId: article.id, cveId });
        }
      }
    }

    if (tasks.length === 0) return;
    console.log(`[NVD] Enrichissement de ${tasks.length} CVE(s)...`);

    for (const { articleId, cveId } of tasks) {
      // Respecter un éventuel backoff global dû à 429
      if (backoffUntil > Date.now()) {
        await delay(backoffUntil - Date.now());
      }

      const data = await fetchCVE(cveId);
      if (data) {
        onEnrich(articleId, data);
      }
      await delay(REQ_DELAY); // Respecter le rate-limit NVD
    }

    console.log("[NVD] Enrichissement terminé.");
  }

  // ── API publique ──────────────────────────────────────────────────────────

  return {
    enrichArticles,
    extractCVEIds,
    fetchCVE,
    cvssClass,
    scoreToCvssLabel
  };
})();
