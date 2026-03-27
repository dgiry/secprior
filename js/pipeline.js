// pipeline.js — Orchestrateur du pipeline de veille en 6 étapes
//
// Étapes :
//   1. Collecter   : fetchAllFeeds()           → articles bruts des flux RSS
//   2. Enrichir    : Enricher.enrich()          → EPSS, KEV, entités (CVE, vendeurs)
//   3. Dédupliquer : Deduplicator.deduplicate() → fusion doublons CVE + Jaccard titre
//   4. Scorer      : scoreComposite()           → score composite 0-100 + criticité
//   5. Contextualiser : Contextualizer.contextualize() → watchlist, ATT&CK, trending
//   6. (Alerter)   : géré en aval par AlertManager dans app.js

const Pipeline = (() => {

  async function run(force = false) {
    console.log("[Pipeline] ▶ Démarrage du pipeline");

    // ── Étape 1 : Collecte ──────────────────────────────────────────────────
    const rawArticles = await fetchAllFeeds(force);
    console.log(`[Pipeline] 1. Collecte → ${rawArticles.length} articles`);

    if (rawArticles.length === 0) return [];

    // ── Étape 2 : Enrichissement EPSS + KEV ────────────────────────────────
    let articles;
    try {
      articles = await Enricher.enrich(rawArticles);
      console.log(`[Pipeline] 2. Enrichissement → ${articles.filter(a => a.isKEV).length} KEV, ` +
                  `${articles.filter(a => a.epssScore !== null).length} EPSS`);
    } catch (e) {
      console.warn("[Pipeline] 2. Enrichissement échoué (fallback brut):", e.message);
      articles = rawArticles;
    }

    // ── Étape 3 : Déduplication ────────────────────────────────────────────
    const deduped = Deduplicator.deduplicate(articles);
    console.log(`[Pipeline] 3. Déduplication → ${deduped.length} articles uniques`);

    // ── Étape 4 : Scoring composite ────────────────────────────────────────
    const scored = deduped.map(a => {
      const { score, breakdown } = scoreComposite(a);
      // Si aucune donnée d'enrichissement n'est disponible (sandbox/demo),
      // la criticité hérite du signal heuristique de feeds.js (scoreItem).
      const hasEnrichment = (a.cvssScore != null) || (a.epssScore != null) || a.isKEV;
      const criticality = hasEnrichment ? classifyScore(score) : (a.criticality || classifyScore(score));
      return { ...a, score, scoreBreakdown: breakdown, criticality };
    });

    const high   = scored.filter(a => a.criticality === "high").length;
    const medium = scored.filter(a => a.criticality === "medium").length;
    console.log(`[Pipeline] 4. Scoring → ${high} HIGH · ${medium} MEDIUM · ${scored.length - high - medium} LOW`);

    // ── Étape 5 : Contextualisation ────────────────────────────────────────
    const contextualized = Contextualizer.contextualize(scored);
    const trending    = contextualized.filter(a => a.isTrending).length;
    const watchlisted = contextualized.filter(a => a.watchlistMatches?.length > 0).length;
    console.log(`[Pipeline] 5. Contextualisation → ${trending} trending · ${watchlisted} watchlist hits`);

    // ── Étape 6 : Extraction IOCs ──────────────────────────────────────────
    const withIOCs   = IOCExtractor.enrichAll(contextualized);
    const iocArticles = withIOCs.filter(a => a.iocCount > 0).length;
    const totalIOCs   = withIOCs.reduce((n, a) => n + (a.iocCount || 0), 0);
    console.log(`[Pipeline] 6. IOCs → ${totalIOCs} IOCs extraits dans ${iocArticles} articles`);

    // ── Étape 7 : Priorité explicable ─────────────────────────────────────
    // computePriority() est défini dans scorer.js — utilise tous les signaux
    // enrichis aux étapes 2-6 (EPSS, KEV, watchlist, trending, IOC, CVE).
    // Ne modifie pas score, criticality ni scoreBreakdown.
    const withPriority = withIOCs.map(a => ({ ...a, ...computePriority(a) }));
    const critNow = withPriority.filter(a => a.priorityLevel === "critical_now").length;
    const invest  = withPriority.filter(a => a.priorityLevel === "investigate").length;
    console.log(`[Pipeline] 7. Priorité → ${critNow} critical_now · ${invest} investigate`);

    console.log("[Pipeline] ✅ Pipeline terminé");
    return withPriority;
  }

  return { run };
})();
