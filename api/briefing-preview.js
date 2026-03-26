// api/briefing-preview.js — Preview public du moteur de briefing (lecture seule)
//
// GET /api/briefing-preview
//
// Endpoint public, sans authentification.
// Exécute le pipeline complet (fetch → enrich → score → dedup → select) en mode
// preview : aucun email envoyé, aucune écriture KV.
// Résultat identique à /api/scheduled-digest?preview=1, accessible depuis le front.
//
// Utilisé par le panneau 📰 Briefing de l'interface.

"use strict";

const { parseRSS }          = require("./_lib/rss-parser");
const { enrichArticles }    = require("./_lib/enricher");
const { loadSentIds,
        loadSentTopics }    = require("./_lib/dedup-store");
const { digestPriorityScore,
        selectTopArticles,
        whyImportant,
        watchpoints }       = require("./_lib/digest-engine");
const { FEEDS }             = require("./_lib/feeds");

// ── Scoring heuristique (identique à scheduled-digest.js) ────────────────────

const _SCORER_HIGH = [
  "0day", "zero-day", "zero day", "actively exploited", "in the wild",
  "emergency patch", "critical vulnerability", "rce", "remote code execution",
  "ransomware", "exploit kit", "supply chain attack", "backdoor",
  "nation-state", "apt", "cvss 9", "cvss 10", "cvss:9", "cvss:10",
  "unauthenticated", "authentication bypass", "mass exploitation",
  "worm", "botnet", "firmware vulnerability", "cisa kev",
  "patch tuesday emergency", "out-of-band", "actively being exploited"
];
const _SCORER_MEDIUM = [
  "vulnerability", "cve-", "patch", "security update", "breach",
  "malware", "phishing", "ddos", "data leak", "data breach",
  "privilege escalation", "sql injection", "xss", "csrf",
  "trojan", "spyware", "keylogger", "advisory", "disclosure",
  "security flaw", "weak authentication", "misconfiguration",
  "credential", "password", "leak", "exposed", "unpatched"
];

function _keywordSignal(title, desc) {
  const text = ((title || "") + " " + (desc || "")).toLowerCase();
  for (const kw of _SCORER_HIGH)   { if (text.includes(kw)) return "high"; }
  let hits = 0;
  for (const kw of _SCORER_MEDIUM) { if (text.includes(kw) && ++hits >= 2) return "medium"; }
  if (/cve-\d{4}-\d+/.test(text))  return "medium";
  return "low";
}

function _scoreComposite(article) {
  const W     = { cvss: 0.30, epss: 0.25, kev: 0.25, sources: 0.10, keyword: 0.10 };
  const nCVSS = article.cvssScore != null ? Math.min(article.cvssScore, 10) / 10 : 0;
  const nEPSS = article.epssScore != null ? Math.min(article.epssScore, 1)       : 0;
  const kev   = article.isKEV ? 1 : 0;
  const nSrc  = Math.min((Math.max(1, article.sourceCount || 1) - 1) / 5, 1);
  const kwRaw = _keywordSignal(article.title, article.description);
  const nKW   = kwRaw === "high" ? 1 : kwRaw === "medium" ? 0.5 : 0;
  return Math.round(
    (W.cvss * nCVSS + W.epss * nEPSS + W.kev * kev + W.sources * nSrc + W.keyword * nKW) * 100
  );
}

function _scoreAll(articles) {
  for (const a of articles) {
    a.score = _scoreComposite(a);
    if      (a.score >= 65) a.criticality = "high";
    else if (a.score >= 30) a.criticality = "medium";
    else                    a.criticality = "low";
    if (a.criticality === "low" && (a.isKEV || (a.epssScore != null && a.epssScore >= 0.40))) {
      a.criticality = "medium";
    }
  }
}

// ── Déduplication par sujet (identique à scheduled-digest.js) ────────────────

const _STOP = new Set([
  "the","a","an","in","of","to","for","and","or","is","are","was","were","be",
  "with","how","new","update","patch","patches","patched","fix","fixes","fixed",
  "security","advisory","vulnerability","vulnerabilities","vuln","cve","exploit",
  "exploited","exploiting","critical","high","severe","alert","warning","report",
  "attack","attacks","threat","threats","flaw","flaws","bug","bugs","issue"
]);

function _normTitle(title) {
  return (title || "").toLowerCase().replace(/[^a-z0-9 ]/g, " ")
    .split(/\s+/).filter(w => w.length >= 3 && !_STOP.has(w)).slice(0, 4).join("-") || "misc";
}

function _topicKey(article) {
  if (Array.isArray(article.cveIds) && article.cveIds.length > 0) {
    return "cve:" + [...article.cveIds].map(c => c.toUpperCase()).sort().slice(0, 2).join("+");
  }
  return "title:" + _normTitle(article.title);
}

function _groupByTopic(articles) {
  const groups = new Map();
  for (const a of articles) {
    const key   = _topicKey(a);
    const entry = groups.get(key);
    if (!entry) {
      groups.set(key, { best: a, sources: new Set([a.sourceName]), count: 1 });
    } else {
      entry.sources.add(a.sourceName);
      entry.count++;
      if ((a.score ?? 0) > (entry.best.score ?? 0)) entry.best = a;
    }
  }
  return [...groups.values()].map(({ best, sources, count }) => ({
    ...best,
    _topicKey:   _topicKey(best),
    _groupSize:  count,
    sourceCount: Math.max(best.sourceCount || 1, sources.size)
  })).sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
}

// ── Fetch d'un flux RSS ───────────────────────────────────────────────────────

async function _fetchFeed(feed) {
  const res = await fetch(feed.url, {
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; CyberVeille-Pro/2.0; +https://github.com/dgiry/cyberveille-pro)",
      Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"
    },
    signal: AbortSignal.timeout(12_000)
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return parseRSS(await res.text(), feed.name);
}

// ── Fiche article preview (identique à scheduled-digest.js _previewArticle) ──

function _previewArticle(a, rank) {
  const { score: dps, base, bonus, breakdown } = digestPriorityScore(a);
  return {
    rank,
    title:      a.title,
    link:       a.link,
    sourceName: a.sourceName,
    pubDate:    a.pubDate instanceof Date ? a.pubDate.toISOString() : null,
    score:       a.score,
    criticality: a.criticality,
    digestScore: dps,
    digestBase:  base,
    digestBonus: bonus,
    digestBreakdown: {
      kev:       breakdown.kev,
      epss:      breakdown.epss,
      cvss:      breakdown.cvss,
      zeroDay:   breakdown.zeroDay,
      watchlist: breakdown.watchlist,
      trending:  breakdown.trending,
      sources:   breakdown.sources
    },
    isKEV:            a.isKEV      ?? false,
    epssScore:        a.epssScore  != null ? Math.round(a.epssScore * 1000) / 1000 : null,
    epssPercent:      a.epssScore  != null ? `${Math.round(a.epssScore * 100)} %`  : null,
    cvssScore:        a.cvssScore  ?? null,
    isTrending:       a.isTrending ?? false,
    sourceCount:      a.sourceCount ?? 1,
    cveIds:           (a.cveIds          || []).slice(0, 3),
    watchlistMatches: (a.watchlistMatches || []).slice(0, 5),
    topicKey:             a._topicKey || _topicKey(a),
    selectedRepresentative: true,
    groupedFrom:          a._groupSize || 1,
    selectionReasons: [
      a.isKEV                                   && "KEV actif",
      a.epssScore >= 0.70                       && `EPSS ${Math.round(a.epssScore * 100)} %`,
      a.epssScore >= 0.40 && a.epssScore < 0.70 && `EPSS modéré ${Math.round(a.epssScore * 100)} %`,
      a.cvssScore >= 9                          && `CVSS ${a.cvssScore} critique`,
      a.cvssScore >= 7    && a.cvssScore < 9    && `CVSS ${a.cvssScore}`,
      /zero.?day|0.?day/i.test(a.title || "")  && "zero-day",
      (a.watchlistMatches || []).length > 0     && `watchlist (${a.watchlistMatches.length})`,
      a.isTrending                              && "trending",
      (a.sourceCount || 1) >= 2                && `${a.sourceCount} sources`,
      a.criticality === "high"   && !a.isKEV   && "haute criticité",
      a.criticality === "medium" && !a.isKEV   && "criticité moyenne"
    ].filter(Boolean),
    whyImportant: whyImportant(a),
    watchpoints:  watchpoints(a)
  };
}

// ── Handler ───────────────────────────────────────────────────────────────────

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const t0 = Date.now();

  // ── 1. Fetch tous les flux en parallèle ────────────────────────────────────
  const results = await Promise.allSettled(FEEDS.map(_fetchFeed));
  const allArticles = [];
  let fetchOk = 0, fetchErr = 0;
  results.forEach((r, i) => {
    if (r.status === "fulfilled") { allArticles.push(...r.value); fetchOk++; }
    else fetchErr++;
  });

  if (allArticles.length === 0) {
    return res.status(503).json({ error: "Aucun article récupéré — tous les flux ont échoué" });
  }

  // ── 1.5. Enrichissement KEV / EPSS / CVSS ─────────────────────────────────
  let enrichStats = { kevHits: 0, epssHits: 0, cvssHits: 0 };
  try {
    enrichStats = (await enrichArticles(allArticles)).stats;
  } catch (_) { /* fallback mots-clés */ }

  const t1 = Date.now();

  // ── 1.6. Scoring post-enrichissement ──────────────────────────────────────
  _scoreAll(allArticles);

  // ── 2. Déduplication par id ────────────────────────────────────────────────
  const seen = new Set();
  const unique = allArticles.filter(a => {
    if (!a.id || seen.has(a.id)) return false;
    seen.add(a.id); return true;
  });

  // ── 3. Filtre articles récents (24 h, fallback 48 h) ──────────────────────
  const now  = Date.now();
  const H24  = 24 * 3600 * 1000;
  const H48  = 48 * 3600 * 1000;
  const l24  = unique.filter(a => a.pubDate instanceof Date && a.pubDate.getTime() >= now - H24);
  const queue = l24.length >= 3
    ? l24
    : unique.filter(a => a.pubDate instanceof Date && a.pubDate.getTime() >= now - H48);

  if (queue.length === 0) {
    return res.status(200).json({
      preview: true, generatedAt: new Date().toISOString(), top: [], rest: [],
      stats: { feeds: { ok: fetchOk, err: fetchErr, total: FEEDS.length },
               articles: { raw: allArticles.length, unique: unique.length, queue: 0 },
               enrichment: enrichStats, elapsedMs: Date.now() - t0 }
    });
  }

  // ── 3.5. Filtre IDs déjà envoyés ──────────────────────────────────────────
  const sentIds     = await loadSentIds();
  const afterIdDedup = sentIds.size > 0 ? queue.filter(a => !sentIds.has(a.id)) : queue;
  const idQueue     = afterIdDedup.length >= 3 ? afterIdDedup : queue;

  // ── 3.6. Groupement par sujet (intra-digest) ──────────────────────────────
  const topicQueue = _groupByTopic(idQueue);

  // ── 3.7. Filtre sujets déjà couverts ──────────────────────────────────────
  const sentTopics     = await loadSentTopics();
  const afterTopicDedup = sentTopics.size > 0
    ? topicQueue.filter(a => !sentTopics.has(a._topicKey))
    : topicQueue;
  const finalQueue = afterTopicDedup.length >= 3 ? afterTopicDedup : topicQueue;

  // ── 4. Sélection top articles ──────────────────────────────────────────────
  const top    = selectTopArticles(finalQueue, 5);
  const topIds = new Set(top.map(a => a.id));
  const rest   = finalQueue
    .filter(a => !topIds.has(a.id) && a.criticality !== "low")
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
    .slice(0, 10);

  return res.status(200).json({
    preview:     true,
    generatedAt: new Date().toISOString(),
    top:  top.map((a, i) => _previewArticle(a, i + 1)),
    rest: rest.map((a, i) => ({
      rank:        top.length + i + 1,
      title:       a.title,
      link:        a.link,
      sourceName:  a.sourceName,
      score:       a.score,
      digestScore: digestPriorityScore(a).score,
      criticality: a.criticality,
      topicKey:    a._topicKey || _topicKey(a),
      groupedFrom: a._groupSize || 1,
      isKEV:       a.isKEV ?? false,
      epssPercent: a.epssScore != null ? `${Math.round(a.epssScore * 100)} %` : null,
      cvssScore:   a.cvssScore ?? null
    })),
    stats: {
      feeds:      { ok: fetchOk, err: fetchErr, total: FEEDS.length },
      articles:   { raw: allArticles.length, unique: unique.length, queue: queue.length },
      dedup:      { topicGroups: topicQueue.length, finalQueue: finalQueue.length,
                    sentIds: sentIds.size, sentTopics: sentTopics.size },
      enrichment: enrichStats,
      elapsedMs:  Date.now() - t0,
      enrichMs:   t1 - t0
    }
  });
};
