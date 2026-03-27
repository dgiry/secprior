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

// ── Score de priorité digest ──────────────────────────────────────────────

/**
 * digestPriorityScore(article) → { score, base, bonus, breakdown }
 *
 * Complète scoreComposite pour le tri du briefing matinal.
 * Utilise le score composite comme base (0-100) et ajoute des bonus thématiques.
 * N'affecte PAS le score affiché ni la criticité des articles.
 *
 * Bonus :
 *   watchlist  +25 par terme matché (max 75) — sujet explicitement surveillé
 *   kev        +50                           — exploitation confirmée (CISA)
 *   epss       +35 si ≥ 70 %, +15 si ≥ 40 % — probabilité d'exploitation
 *   trending   +20                           — couverture multi-source
 *   sources    +5 par source supplémentaire (max 20)
 *   zeroDay    +30                           — vulnérabilité 0-day détectée
 */
function digestPriorityScore(article) {
  // Base : score composite déjà calculé, ou recalcul si absent
  const base = article.score != null ? article.score : scoreComposite(article).score;

  const bd = {};

  // Watchlist — signal fort : terme explicitement surveillé par l'utilisateur
  const wl     = Array.isArray(article.watchlistMatches) ? article.watchlistMatches.length : 0;
  bd.watchlist = Math.min(wl * 25, 75);

  // KEV actif — exploitation confirmée dans la nature
  bd.kev = article.isKEV ? 50 : 0;

  // EPSS — probabilité d'exploitation prochaine
  const epss = article.epssScore ?? null;
  bd.epss = epss != null ? (epss >= 0.70 ? 35 : epss >= 0.40 ? 15 : 0) : 0;

  // Trending / multi-source
  bd.trending = article.isTrending ? 20 : 0;
  bd.sources  = Math.min(((article.sourceCount || 1) - 1) * 5, 20);

  // Zero-day : vérifie les attackTags du contextualizer, puis le titre en fallback
  const isZeroDay = article.attackTags?.some(t => t.label === "0-Day")
    || /zero.?day|0.?day/i.test(article.title || "");
  bd.zeroDay = isZeroDay ? 30 : 0;

  const bonus = Object.values(bd).reduce((s, v) => s + v, 0);

  return {
    score:     base + bonus,  // score digest (non borné à 100)
    base,
    bonus,
    breakdown: bd             // lisible : watchlist, kev, epss, trending, sources, zeroDay
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

// ── Priorité explicable ────────────────────────────────────────────────────

/**
 * computePriority(article) → { priorityScore, priorityLevel, priorityReasons, prioritySignals }
 *
 * Transforme le score composite en décision de priorité explicable.
 * Aucun accès au DOM. Tolère toute donnée manquante.
 *
 * Niveaux :
 *   critical_now → action immédiate requise (KEV / EPSS élevé / watchlist + HIGH)
 *   investigate  → à analyser dans la journée
 *   watch        → surveiller, pas urgent
 *   low          → faible signal, bas de liste
 *
 * Ne modifie pas `score`, `criticality` ni `scoreBreakdown`.
 */
function computePriority(article) {
  const score   = article.score ?? 0;
  const reasons = [];

  // ── Extraction des signaux disponibles ────────────────────────────────────
  const kev      = !!article.isKEV;
  const epss     = (typeof article.epssScore === 'number') ? article.epssScore : null;
  const epssHigh = epss !== null && epss >= 0.50;
  const epssMed  = epss !== null && epss >= 0.10;
  const wl       = Array.isArray(article.watchlistMatches) && article.watchlistMatches.length > 0;
  const trending = !!article.isTrending;
  const sources  = Math.max(1, article.sourceCount || 1);
  const iocCount = article.iocCount || 0;
  const hasCVE   = Array.isArray(article.cves) && article.cves.length > 0;
  const isZeroDay = (article.attackTags || []).some(t => t.label === '0-Day')
                  || /zero.?day|0.?day/i.test(article.title || '');
  const hasAttack = Array.isArray(article.attackTags) && article.attackTags.length > 0;

  // ── Construction des raisons lisibles (ordre : signal fort d'abord) ───────
  if (kev)
    reasons.push("Exploitation active confirmée (CISA KEV)");
  if (epssHigh)
    reasons.push(`Probabilité d'exploitation élevée : ${(epss * 100).toFixed(0)}% (FIRST.org)`);
  else if (epssMed)
    reasons.push(`Probabilité d'exploitation : ${(epss * 100).toFixed(0)}% (FIRST.org)`);
  if (wl) {
    const terms = article.watchlistMatches.slice(0, 2).join(', ');
    reasons.push(`Terme watchlist matché : ${terms}`);
  }
  if (isZeroDay)
    reasons.push("Vulnérabilité 0-day — aucun patch disponible");
  if (trending)
    reasons.push(`Couvert par ${article.trendingCount || sources} sources simultanément`);
  else if (sources > 1)
    reasons.push(`Couvert par ${sources} sources distinctes`);
  if (iocCount > 0)
    reasons.push(`${iocCount} IOC${iocCount > 1 ? 's' : ''} extraits (IPs, domaines, hashes)`);
  if (hasAttack && !isZeroDay) {
    const tactics = article.attackTags.slice(0, 2).map(t => t.label).join(', ');
    reasons.push(`Tactique ATT&CK détectée : ${tactics}`);
  }
  if (hasCVE) {
    const cveStr = article.cves[0] + (article.cves.length > 1 ? ` +${article.cves.length - 1}` : '');
    reasons.push(`CVE référencé : ${cveStr}`);
  }
  if (score > 0 && reasons.length === 0)
    reasons.push(`Score composite : ${score}/100`);

  // ── Niveau de priorité ────────────────────────────────────────────────────
  let priorityLevel;
  if (kev || score >= 80 || (epssHigh && hasCVE) || (score >= 65 && wl)) {
    priorityLevel = "critical_now";
  } else if (score >= 45 || epssMed || (trending && score >= 25) || wl || isZeroDay) {
    priorityLevel = "investigate";
  } else if (score >= 20 || hasCVE || iocCount > 0) {
    priorityLevel = "watch";
  } else {
    priorityLevel = "low";
  }

  // ── Score de priorité (non borné à 100, pour tri futur) ──────────────────
  const priorityScore = score
    + (kev      ? 40 : 0)
    + (epssHigh ? 20 : epssMed ? 8 : 0)
    + (wl       ? 15 : 0)
    + (isZeroDay? 15 : 0)
    + (trending ?  8 : 0)
    + (iocCount ?  5 : 0);

  // ── Signaux structurés (pour usage programmatique) ───────────────────────
  const prioritySignals = {
    kev,
    epss:      epss !== null ? +(epss * 100).toFixed(1) : null,
    epssHigh,
    epssMed,
    watchlist: wl,
    trending,
    iocCount,
    isZeroDay,
    hasCVE,
    sources,
    baseScore: score
  };

  return { priorityScore, priorityLevel, priorityReasons: reasons, prioritySignals };
}

// ── Méta d'affichage par niveau de priorité ───────────────────────────────

function getPriorityMeta(level) {
  switch (level) {
    case "critical_now": return { icon: "🔴", label: "Action immédiate",   css: "critical-now" };
    case "investigate":  return { icon: "🟠", label: "À investiguer",      css: "investigate"  };
    case "watch":        return { icon: "🔵", label: "À surveiller",       css: "watch"        };
    default:             return { icon: "⚪", label: "Signal faible",       css: "low"          };
  }
}
