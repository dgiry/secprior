// pipeline.js — Orchestrateur du pipeline de veille en 7 étapes
//
// Étapes :
//   1. Collecter      : fetchAllFeeds()              → articles bruts des flux RSS
//   2. Enrichir       : Enricher.enrich()             → EPSS, KEV, entités (CVE, vendeurs)
//   3. Dédupliquer    : Deduplicator.deduplicate()    → fusion doublons CVE + Jaccard titre
//   4. IOC            : IOCExtractor.enrichAll()      → extraction IOCs (avant scoring)
//   5. Scorer         : scoreComposite()              → score composite 0-100 + criticité
//                       (inclut désormais le signal iocCount — W.ioc = 0.05)
//   6. Contextualiser : Contextualizer.contextualize() → watchlist, ATT&CK, trending
//   7. Priorité       : computePriority()             → niveau explicable + priorityScore
//   (Alerter)         : géré en aval par AlertManager dans app.js

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

    // ── Étape 4 : Extraction IOCs ──────────────────────────────────────────
    // Placée AVANT le scoring pour que scoreComposite() dispose de iocCount.
    const withIOCs    = IOCExtractor.enrichAll(deduped);
    const iocArticles = withIOCs.filter(a => a.iocCount > 0).length;
    const totalIOCs   = withIOCs.reduce((n, a) => n + (a.iocCount || 0), 0);
    console.log(`[Pipeline] 4. IOCs → ${totalIOCs} IOCs extraits dans ${iocArticles} articles`);

    // ── Étape 5 : Scoring composite ────────────────────────────────────────
    // scoreComposite() inclut désormais iocCount (W.ioc = 0.05).
    const scored = withIOCs.map(a => {
      const { score, breakdown } = scoreComposite(a);
      // Si aucune donnée d'enrichissement n'est disponible (sandbox/demo),
      // la criticité hérite du signal heuristique de feeds.js (scoreItem).
      const hasEnrichment = (a.cvssScore != null) || (a.epssScore != null) || a.isKEV;
      const criticality = hasEnrichment ? classifyScore(score) : (a.criticality || classifyScore(score));
      return { ...a, score, scoreBreakdown: breakdown, criticality };
    });

    const high   = scored.filter(a => a.criticality === "high").length;
    const medium = scored.filter(a => a.criticality === "medium").length;
    console.log(`[Pipeline] 5. Scoring → ${high} HIGH · ${medium} MEDIUM · ${scored.length - high - medium} LOW`);

    // ── Étape 6 : Contextualisation ────────────────────────────────────────
    const contextualized = Contextualizer.contextualize(scored);
    const trending    = contextualized.filter(a => a.isTrending).length;
    const watchlisted = contextualized.filter(a => a.watchlistMatches?.length > 0).length;
    console.log(`[Pipeline] 6. Contextualisation → ${trending} trending · ${watchlisted} watchlist hits`);

    // ── Étape 7 : Priorité explicable ─────────────────────────────────────
    // computePriority() est défini dans scorer.js — utilise tous les signaux
    // enrichis aux étapes 2-6 (EPSS, KEV, watchlist, trending, IOC, CVE).
    // Ne modifie pas score, criticality ni scoreBreakdown.
    const withPriority = contextualized.map(a => ({ ...a, ...computePriority(a) }));
    const critNow = withPriority.filter(a => a.priorityLevel === "critical_now").length;
    const invest  = withPriority.filter(a => a.priorityLevel === "investigate").length;
    console.log(`[Pipeline] 7. Priorité → ${critNow} critical_now · ${invest} investigate`);

    console.log("[Pipeline] ✅ Pipeline terminé");
    return withPriority;
  }

  return { run };
})();
