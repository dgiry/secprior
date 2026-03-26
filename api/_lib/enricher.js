// api/lib/enricher.js — Enrichissement serveur des articles : KEV, EPSS, CVSS
//
// Sources publiques, sans authentification :
//   • CISA KEV : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//   • EPSS     : https://api.first.org/data/v1/epss  (batch jusqu'à 50 CVEs)
//   • CVSS     : extraction regex depuis le texte de l'article (fallback sans NVD)
//
// Usage :
//   const { enrichArticles } = require("./enricher");
//   await enrichArticles(allArticles);  // modifie les articles en place

"use strict";

const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_API_URL = "https://api.first.org/data/v1/epss";
const EPSS_CHUNK   = 50; // nb max de CVEs par requête EPSS

// ── CISA KEV ─────────────────────────────────────────────────────────────────

/**
 * Télécharge la liste CISA Known Exploited Vulnerabilities.
 * @returns {Promise<Set<string>>} Set de CVE IDs en majuscules (ex: "CVE-2024-1234")
 */
async function fetchKEVSet() {
  try {
    const res = await fetch(CISA_KEV_URL, {
      headers: { "User-Agent": "CyberVeille-Pro/2.0" },
      signal: AbortSignal.timeout(10_000)
    });
    if (!res.ok) { console.warn("[enricher] KEV HTTP %d", res.status); return new Set(); }
    const json = await res.json();
    const ids = (json.vulnerabilities || []).map(v => (v.cveID || "").toUpperCase()).filter(Boolean);
    console.log("[enricher] KEV — %d vulnérabilités chargées", ids.length);
    return new Set(ids);
  } catch (e) {
    console.warn("[enricher] KEV fetch échoué :", e.message);
    return new Set(); // fallback propre
  }
}

// ── EPSS (FIRST.org) ──────────────────────────────────────────────────────────

/**
 * Récupère les scores EPSS pour une liste de CVE IDs (traitement par lots de 50).
 * @param {string[]} cveIds - ex: ["CVE-2024-1234", ...]
 * @returns {Promise<Map<string, number>>} Map<cveId_majuscules, epssScore 0-1>
 */
async function fetchEPSSMap(cveIds) {
  if (!cveIds.length) return new Map();
  const map = new Map();

  for (let i = 0; i < cveIds.length; i += EPSS_CHUNK) {
    const chunk = cveIds.slice(i, i + EPSS_CHUNK);
    try {
      const url = `${EPSS_API_URL}?cve=${chunk.join(",")}&limit=${chunk.length}`;
      const res = await fetch(url, {
        headers: { "User-Agent": "CyberVeille-Pro/2.0" },
        signal: AbortSignal.timeout(8_000)
      });
      if (!res.ok) { console.warn("[enricher] EPSS HTTP %d", res.status); continue; }
      const json = await res.json();
      for (const entry of (json.data || [])) {
        const score = parseFloat(entry.epss);
        if (!isNaN(score)) map.set((entry.cve || "").toUpperCase(), score);
      }
    } catch (e) {
      console.warn("[enricher] EPSS chunk %d échoué :", i, e.message);
      // pas de throw — on continue avec les autres chunks
    }
  }
  return map;
}

// ── CVSS textuel ──────────────────────────────────────────────────────────────

/**
 * Extrait un score CVSS depuis le texte d'un article (titre + description).
 * Gère : "CVSS 9.8", "CVSSv3: 7.5", "CVSS Score of 8.1", "CVSS:3.1/AV:... (9.0)"
 * @param {string} text
 * @returns {number|null} score 0-10 ou null si absent
 */
function _extractCVSS(text) {
  // Recherche un score numérique dans la zone CVSS (max 15 chars d'écart)
  const m = text.match(/cvss[^0-9]{0,15}([0-9]+\.[0-9])/i);
  if (!m) return null;
  const v = parseFloat(m[1]);
  return (v >= 0 && v <= 10) ? v : null;
}

// ── Application de l'enrichissement ──────────────────────────────────────────

/**
 * Applique les données KEV, EPSS et CVSS sur les articles (modification en place).
 * Ne touche pas aux champs déjà remplis (isKEV:true, epssScore non null, etc.).
 *
 * @param {Array}  articles
 * @param {{ kevSet: Set<string>, epssMap: Map<string,number> }} data
 * @returns {{ kevHits: number, epssHits: number, cvssHits: number }}
 */
function applyEnrichment(articles, { kevSet, epssMap }) {
  let kevHits = 0, epssHits = 0, cvssHits = 0;

  for (const a of articles) {
    // KEV — vrai si au moins un CVE de l'article est dans la CISA KEV list
    if (!a.isKEV && a.cveIds?.length) {
      if (a.cveIds.some(cve => kevSet.has(cve.toUpperCase()))) {
        a.isKEV = true;
        kevHits++;
      }
    }

    // EPSS — on retient le score maximum parmi tous les CVEs de l'article
    if (a.epssScore == null && a.cveIds?.length) {
      let best = null;
      for (const cve of a.cveIds) {
        const s = epssMap.get(cve.toUpperCase());
        if (s != null && (best === null || s > best)) best = s;
      }
      if (best !== null) { a.epssScore = best; epssHits++; }
    }

    // CVSS — extraction textuelle (fallback sans appel NVD)
    if (a.cvssScore == null) {
      const cvss = _extractCVSS(`${a.title || ""} ${a.description || ""}`);
      if (cvss !== null) { a.cvssScore = cvss; cvssHits++; }
    }
  }

  return { kevHits, epssHits, cvssHits };
}

// ── Pipeline principal ────────────────────────────────────────────────────────

/**
 * Pipeline complet d'enrichissement :
 *   1. Collecte tous les CVE IDs uniques des articles
 *   2. Fetch CISA KEV + EPSS en parallèle (fallback silencieux si erreur)
 *   3. Applique l'enrichissement sur les articles en place
 *
 * @param {Array} articles - modifiés en place (isKEV, epssScore, cvssScore)
 * @returns {Promise<{ kevSet: Set, epssMap: Map, stats: object }>}
 */
async function enrichArticles(articles) {
  // Collecte les CVEs uniques tous articles confondus
  const allCVEs = [...new Set(
    articles.flatMap(a => (a.cveIds || []).map(c => c.toUpperCase()))
  )];

  console.log("[enricher] %d CVEs uniques — lancement KEV + EPSS en parallèle…", allCVEs.length);

  // Fetch KEV et EPSS simultanément pour minimiser la latence
  const [kevSet, epssMap] = await Promise.all([
    fetchKEVSet(),
    fetchEPSSMap(allCVEs)
  ]);

  const stats = applyEnrichment(articles, { kevSet, epssMap });
  console.log("[enricher] ✓ KEV:%d EPSS:%d CVSS:%d articles enrichis",
    stats.kevHits, stats.epssHits, stats.cvssHits);

  return { kevSet, epssMap, stats };
}

module.exports = { enrichArticles, fetchKEVSet, fetchEPSSMap, applyEnrichment };
