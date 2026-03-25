// scorer.js — Stage 4 : Score composite 0-100
//
// Formule :
//   score = w_cvss    * normalize(cvss, 0, 10)        [0-10 → 0-1]
//         + w_epss    * epss                           [déjà 0-1]
//         + w_kev     * isKEV                          [booléen 0/1]
//         + w_sources * normalize(sourceCount, 1, 6)   [nb sources]
//         + w_keyword * keywordSignal                  [heuristique]
//
// Poids : cvss=0.30 | epss=0.25 | kev=0.25 | sources=0.10 | keyword=0.10
//
// Seuils dynamiques : HIGH ≥ 65 | MEDIUM ≥ 30 | LOW < 30
// (compatibles avec l'ancien système heuristique pour les articles sans CVE)

// ── Score composite ───────────────────────────────────────────────────────

function scoreComposite(article) {
  const W = { cvss: 0.30, epss: 0.25, kev: 0.25, sources: 0.10, keyword: 0.10 };

  // CVSS (de nvd.js ou null)
  const cvss = article.cvssScore ?? null;
  const normCVSS = cvss !== null ? Math.min(cvss, 10) / 10 : 0;

  // EPSS (de enricher.js ou null)
  const epss = article.epssScore ?? null;
  const normEPSS = epss !== null ? Math.min(epss, 1) : 0;

  // KEV
  const kevBonus = article.isKEV ? 1 : 0;

  // Multi-source signal (1 source = 0, 6 sources = 1)
  const sc = Math.max(1, article.sourceCount || 1);
  const normSources = Math.min((sc - 1) / 5, 1);

  // Signal mots-clés (réutilise l'heuristique v1 comme composante)
  const kwRaw = _keywordSignal(article.title, article.description);
  const normKW = kwRaw === "high" ? 1 : kwRaw === "medium" ? 0.5 : 0;

  const raw = (
    W.cvss    * normCVSS  +
    W.epss    * normEPSS  +
    W.kev     * kevBonus  +
    W.sources * normSources +
    W.keyword * normKW
  );

  const score = Math.round(raw * 100);

  return {
    score,
    breakdown: {
      cvss:    Math.round(W.cvss    * normCVSS    * 100),
      epss:    Math.round(W.epss    * normEPSS    * 100),
      kev:     Math.round(W.kev     * kevBonus    * 100),
      sources: Math.round(W.sources * normSources * 100),
      keyword: Math.round(W.keyword * normKW      * 100)
    }
  };
}

// ── Heuristique mots-clés (conservée comme signal interne) ───────────────

function _keywordSignal(title, desc) {
  const text = (title + " " + (desc || "")).toLowerCase();
  for (const kw of CONFIG.SCORER_HIGH) {
    if (text.includes(kw)) return "high";
  }
  let hits = 0;
  for (const kw of CONFIG.SCORER_MEDIUM) {
    if (text.includes(kw) && ++hits >= 2) return "medium";
  }
  if (/cve-\d{4}-\d+/.test(text)) return "medium";
  return "low";
}

// ── Compatibilité : scoreItem() conservé pour les articles avant pipeline ──

function scoreItem(title, desc) {
  return _keywordSignal(title, desc);
}

// ── Classify : score numérique → niveau sémantique ────────────────────────

function classifyScore(score) {
  if (score >= 65) return "high";
  if (score >= 30) return "medium";
  return "low";
}

// ── Méta-affichage ────────────────────────────────────────────────────────

function getCriticalityMeta(level) {
  switch (level) {
    case "high":   return { label: "HAUTE",   cssClass: "badge-high",   icon: "🔴" };
    case "medium": return { label: "MOYENNE", cssClass: "badge-medium", icon: "🟠" };
    default:       return { label: "BASSE",   cssClass: "badge-low",    icon: "🟢" };
  }
}

// ── Score bar (pour affichage visuel 0-100) ───────────────────────────────

function scoreBarClass(score) {
  if (score >= 65) return "score-bar-high";
  if (score >= 30) return "score-bar-medium";
  return "score-bar-low";
}
