// ioc-auto-enricher.js — Background IOC enrichment for priority articles
//
// Automatically runs Deep IOC scan → OTX reputation on a small set of
// priority articles after each pipeline run. VirusTotal is NOT auto-run.
//
// Priority predicate (shouldAutoEnrichIOCs):
//   priorityLevel === 'critical_now'   (KEV / EPSS ≥ 0.7 / score ≥ 80)
//   AND (isKEV  OR  score >= 70)       — tight guard to avoid noisy false positives
//
// Quota / rate guards:
//   - Max 5 articles per pipeline run
//   - Max 5 OTX requests per article (same cap as manual flow)
//   - 200 ms between OTX calls  (OTX: 1 req/s free tier)
//   - 600 ms between articles   (breathing room between article-body + OTX batches)
//
// Anti-duplicate guards:
//   - Skips articles where _deepScanned is already true
//   - Skips articles where iocReputation already has results
//   - Skips articles where _autoEnriched is true (previous run)
//   - Demo articles are never auto-enriched
//
// After enrichment, onUpdate(article) is called — app.js persists to cache
// and asks ArticleModal to refresh the IOC panel if that article is open.

const IOCAutoEnricher = (() => {

  // ── Priority predicate ──────────────────────────────────────────────────────
  //
  // Strict subset of 'critical_now' — avoids enriching watchlist-heavy articles
  // that score critical_now via accumulated context bonuses but lack hard signals.
  //
  // V1 rule:
  //   Must be critical_now   (pipeline-computed, catches KEV / EPSS ≥0.7 / score ≥80)
  //   PLUS isKEV  OR  score ≥ 70   (double-guard: confirmed exploited or very high signal)

  function shouldAutoEnrichIOCs(article) {
    if (!article) return false;
    if (article.id?.startsWith('demo')) return false;                 // never auto-enrich demo
    if (article.priorityLevel !== 'critical_now') return false;       // only top priority
    return article.isKEV || (article.score ?? 0) >= 70;
  }

  // ── Main runner (non-blocking, called from app.js after Pipeline.run) ───────

  async function run(articles, onUpdate) {
    if (typeof CONFIG === 'undefined' || !CONFIG.USE_API) return;

    const candidates = articles
      .filter(shouldAutoEnrichIOCs)
      .filter(a => !a._autoEnriched && !a._deepScanned)
      .slice(0, 5);  // hard cap — never hammer the API on a big feed refresh

    if (!candidates.length) {
      console.log('[IOCAutoEnricher] No new priority articles to enrich this run');
      return;
    }

    console.log(`[IOCAutoEnricher] Queuing ${candidates.length} article(s) for background enrichment`);

    for (const article of candidates) {
      try {
        await _enrichOne(article);
        onUpdate(article);
      } catch (e) {
        console.warn(`[IOCAutoEnricher] Skipped "${article.title?.slice(0, 50)}":`, e.message);
      }
      // Pause between articles — gives OTX rate limiter time to breathe
      await _delay(600);
    }
  }

  // ── Enrich one article: deep scan → OTX ─────────────────────────────────────

  async function _enrichOne(article) {

    // ── Step 1: Deep IOC scan ─────────────────────────────────────────────────
    const bodyResp = await fetch(
      `/api/ioc?action=body&url=${encodeURIComponent(article.link)}`,
      { signal: AbortSignal.timeout(15_000) }
    );
    if (!bodyResp.ok) throw new Error(`Body fetch HTTP ${bodyResp.status}`);
    const { text, chars } = await bodyResp.json();

    if (typeof IOCExtractor === 'undefined') throw new Error('IOCExtractor not loaded');
    const enriched = IOCExtractor.enrichArticle(article, text);

    // Mutate in-place — same reference as state.articles (app.js holds it)
    article.iocs         = enriched.iocs;
    article.iocCount     = enriched.iocCount;
    article._deepChars   = chars || 0;
    article._deepScanned = true;

    const realCount = IOCExtractor.getRealIOCCount(article);
    console.log(`[IOCAutoEnricher] Deep scan → ${realCount} IOC(s) — "${article.title?.slice(0, 50)}"`);

    // ── Step 2: OTX reputation — only if real IOCs found ─────────────────────
    // Skip OTX if no real IOCs (saves quota) or if already enriched from cache.
    if (realCount === 0) {
      article._autoEnriched = true;
      return;
    }
    if (article.iocReputation && Object.keys(article.iocReputation).length > 0) {
      // Already has OTX results (e.g. restored from cache) — keep them, mark done.
      article._autoEnriched = true;
      return;
    }

    const iocs  = article.iocs || {};
    const tasks = [];
    (iocs.ips     || []).slice(0, 3).forEach(v => tasks.push({ type: 'ip',     value: v }));
    (iocs.domains || []).slice(0, 3).forEach(v => tasks.push({ type: 'domain', value: v }));
    (iocs.hashes  || []).slice(0, 2).forEach(h => tasks.push({ type: 'hash',   value: h.value }));
    (iocs.urls    || []).slice(0, 2).forEach(v => tasks.push({ type: 'url',    value: v }));
    const capped = tasks.slice(0, 5);  // hard cap: 5 OTX calls per article

    const otxKey     = localStorage.getItem('cv_otx_api_key') || '';
    const otxHeaders = otxKey ? { 'X-OTX-Key': otxKey } : {};
    const reputation = {};

    for (let i = 0; i < capped.length; i++) {
      const { type, value } = capped[i];
      try {
        const r = await fetch(
          `/api/ioc?action=reputation&type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`,
          { headers: otxHeaders, signal: AbortSignal.timeout(10_000) }
        );
        if (r.ok) {
          const data = await r.json();
          // OTX key not configured — abort silently (will show in panel naturally)
          if (data.otxUnavailable) break;
          if (!data.error) reputation[value] = data;
        }
      } catch { /* network error — skip this IOC silently */ }
      if (i < capped.length - 1) await _delay(200);
    }

    article.iocReputation = reputation;
    article._autoEnriched = true;

    const seenCount = Object.values(reputation)
      .filter(r => r.verdict === 'malicious' || r.verdict === 'suspicious').length;
    console.log(`[IOCAutoEnricher] OTX done → ${seenCount} referenced — "${article.title?.slice(0, 50)}"`);
  }

  function _delay(ms) { return new Promise(r => setTimeout(r, ms)); }

  // ── Public API ───────────────────────────────────────────────────────────────
  return { shouldAutoEnrichIOCs, run };

})();
