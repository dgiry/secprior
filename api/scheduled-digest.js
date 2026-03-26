// api/scheduled-digest.js — Briefing cybersécurité quotidien côté serveur
//
// Déclenchement automatique : Vercel Cron (voir vercel.json → "crons")
// Déclenchement manuel     : GET /api/scheduled-digest?secret=<CRON_SECRET>
//
// Variables d'environnement requises (Vercel > Settings > Environment Variables) :
//   DIGEST_RECIPIENT   — adresse email destinataire du briefing
//   DIGEST_CHANNEL     — "resend" ou "sendgrid"  (défaut : "resend")
//   DIGEST_HOUR        — heure d'envoi locale Montréal, ex: "08:00" (défaut "08:00")
//   DIGEST_WEEKDAY     — jour 0-6 (0=dim) pour mode hebdomadaire ; vide = quotidien
//   CRON_SECRET        — secret partagé pour sécuriser les appels manuels
//   RESEND_API_KEY     — clé API Resend    (si DIGEST_CHANNEL=resend)
//   RESEND_FROM        — expéditeur Resend (ex: "CyberVeille Pro <alerts@...>")
//   SENDGRID_API_KEY   — clé API SendGrid  (si DIGEST_CHANNEL=sendgrid)
//   SENDGRID_FROM      — email expéditeur vérifié SendGrid

"use strict";

const { parseRSS }           = require("./lib/rss-parser");
const { enrichArticles }     = require("./lib/enricher");
const { loadSentIds,    saveSentIds,
        loadSentTopics, saveSentTopics,
        loadLastSlot,   saveLastSlot }   = require("./lib/dedup-store");
const { digestPriorityScore,
        selectTopArticles,
        formatBriefingHTML,
        formatBriefingText,
        whyImportant,
        watchpoints }        = require("./lib/digest-engine");
const { FEEDS }              = require("./lib/feeds"); // source canonique — modifier là-bas

// ── Scoring heuristique côté serveur (port de config.js + scorer.js) ─────────
// Utilisé pour attribuer score et criticality aux articles sans enrichissement NVD/EPSS.

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
  const W    = { cvss: 0.30, epss: 0.25, kev: 0.25, sources: 0.10, keyword: 0.10 };
  const nCVSS  = article.cvssScore != null ? Math.min(article.cvssScore, 10) / 10 : 0;
  const nEPSS  = article.epssScore != null ? Math.min(article.epssScore, 1)       : 0;
  const kev    = article.isKEV ? 1 : 0;
  const nSrc   = Math.min((Math.max(1, article.sourceCount || 1) - 1) / 5, 1);
  const kwRaw  = _keywordSignal(article.title, article.description);
  const nKW    = kwRaw === "high" ? 1 : kwRaw === "medium" ? 0.5 : 0;
  return Math.round(
    (W.cvss * nCVSS + W.epss * nEPSS + W.kev * kev + W.sources * nSrc + W.keyword * nKW) * 100
  );
}

// ── Déduplication par sujet ───────────────────────────────────────────────────

// Mots trop génériques pour discriminer un sujet — exclus du topic key titre
const _STOP = new Set([
  "the","a","an","in","of","to","for","and","or","is","are","was","were","be",
  "with","how","new","update","patch","patches","patched","fix","fixes","fixed",
  "security","advisory","vulnerability","vulnerabilities","vuln","cve","exploit",
  "exploited","exploiting","critical","high","severe","alert","warning","report",
  "attack","attacks","threat","threats","flaw","flaws","bug","bugs","issue"
]);

/**
 * Normalise un titre en 4 tokens significatifs (stop-words et ponctuation retirés).
 * @param {string} title
 * @returns {string} ex: "apache-http-rce-unauthenticated"
 */
function _normTitle(title) {
  const tokens = (title || "")
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, " ")
    .split(/\s+/)
    .filter(w => w.length >= 3 && !_STOP.has(w));
  return tokens.slice(0, 4).join("-") || "misc";
}

/**
 * Calcule une clé de sujet stable pour regrouper les articles similaires.
 * Règles (par ordre de priorité) :
 *   1. CVE(s) présents → "cve:CVE-2024-1234" ou "cve:CVE-2024-1234+CVE-2024-5678"
 *      (triés pour que l'ordre des CVEs n'importe pas)
 *   2. Sinon → "title:<4 tokens normalisés>"
 *
 * @param {object} article
 * @returns {string}
 */
function _topicKey(article) {
  if (Array.isArray(article.cveIds) && article.cveIds.length > 0) {
    const sorted = [...article.cveIds].map(c => c.toUpperCase()).sort().slice(0, 2);
    return "cve:" + sorted.join("+");
  }
  return "title:" + _normTitle(article.title);
}

/**
 * Regroupe les articles par topicKey et retourne le meilleur représentant
 * de chaque groupe (score composite le plus élevé).
 *
 * Effets secondaires utiles sur le représentant choisi :
 *   - _topicKey    : clé du groupe (string)
 *   - sourceCount  : max(sourceCount original, nb sources couvrant ce sujet)
 *                    → signal multi-source utilisé par digestPriorityScore
 *
 * @param {Array} articles
 * @returns {Array} un article par sujet, trié score décroissant
 */
function _groupByTopic(articles) {
  // Map topicKey → { best: article, sources: Set<string> }
  const groups = new Map();

  for (const a of articles) {
    const key   = _topicKey(a);
    const entry = groups.get(key);
    if (!entry) {
      groups.set(key, { best: a, sources: new Set([a.sourceName]) });
    } else {
      entry.sources.add(a.sourceName);
      // Promouvoir si meilleur score composite
      if ((a.score ?? 0) > (entry.best.score ?? 0)) {
        entry.best = a;
      }
    }
  }

  return [...groups.values()]
    .map(({ best, sources }) => ({
      ...best,
      _topicKey:   _topicKey(best),
      // Si plusieurs sources couvrent le même sujet, on amplifie sourceCount
      sourceCount: Math.max(best.sourceCount || 1, sources.size)
    }))
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
}

// ── Fetch d'un seul flux RSS (direct serveur — pas de CORS) ──────────────────
// Le scoring est intentionnellement absent ici : il sera appliqué APRÈS
// l'enrichissement KEV/EPSS/CVSS dans _scoreAll(), ce qui garantit des scores exacts.
async function _fetchFeed(feed) {
  const res = await fetch(feed.url, {
    headers: {
      "User-Agent":
        "Mozilla/5.0 (compatible; CyberVeille-Pro/2.0; +https://github.com/dgiry/cyberveille-pro)",
      Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"
    },
    signal: AbortSignal.timeout(12_000)
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const xml = await res.text();
  // Retourne les articles bruts — isKEV/epssScore/cvssScore remplis par enricher.js
  return parseRSS(xml, feed.name);
}

// ── Scoring post-enrichissement ───────────────────────────────────────────────
// Appelé après enrichArticles() pour que _scoreComposite() utilise les vraies
// valeurs KEV/EPSS/CVSS plutôt que des nulls.
function _scoreAll(articles) {
  for (const a of articles) {
    a.score = _scoreComposite(a);
    // criticality : seuils identiques à classifyScore() dans scorer.js
    if      (a.score >= 65) a.criticality = "high";
    else if (a.score >= 30) a.criticality = "medium";
    else                    a.criticality = "low";
    // Promotion : article avec KEV ou EPSS élevé mais texte peu explicite
    if (a.criticality === "low" && (a.isKEV || (a.epssScore != null && a.epssScore >= 0.40))) {
      a.criticality = "medium";
    }
  }
}

// ── Envoi email (Resend ou SendGrid) ─────────────────────────────────────────
async function _sendEmail({ channel, to, subject, html, text }) {
  if (channel === "resend") {
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) throw new Error("RESEND_API_KEY non configurée");
    const from = process.env.RESEND_FROM || "CyberVeille Pro <onboarding@resend.dev>";

    const res = await fetch("https://api.resend.com/emails", {
      method:  "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body:    JSON.stringify({ from, to: [to], subject, html, text,
        tags: [{ name: "source", value: "cyberveille-pro-cron" }] }),
      signal: AbortSignal.timeout(12_000)
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.message || `Resend HTTP ${res.status}`);
    return { channel: "resend", id: json.id };
  }

  if (channel === "sendgrid") {
    const apiKey = process.env.SENDGRID_API_KEY;
    if (!apiKey) throw new Error("SENDGRID_API_KEY non configurée");
    const fromEmail = process.env.SENDGRID_FROM;
    if (!fromEmail) throw new Error("SENDGRID_FROM non configurée");

    const res = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method:  "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body:    JSON.stringify({
        personalizations: [{ to: [{ email: to }], subject }],
        from:    { email: fromEmail, name: "CyberVeille Pro" },
        content: [
          ...(text ? [{ type: "text/plain", value: text }] : []),
          ...(html  ? [{ type: "text/html",  value: html  }] : [])
        ],
        categories: ["cyberveille-pro-cron"]
      }),
      signal: AbortSignal.timeout(12_000)
    });
    if (res.status !== 202) {
      const json = await res.json().catch(() => ({}));
      throw new Error(json.errors?.[0]?.message || `SendGrid HTTP ${res.status}`);
    }
    return { channel: "sendgrid" };
  }

  throw new Error(`Canal '${channel}' non supporté (utiliser "resend" ou "sendgrid")`);
}

// ── Helper timezone Montreal ──────────────────────────────────────────────────

/**
 * Retourne les composantes de l'heure courante en timezone America/Montreal.
 * Gère automatiquement EDT (UTC-4, été) et EST (UTC-5, hiver) via l'API Intl.
 *
 * @returns {{ hour, minute, weekday, slot, tz }}
 *   weekday : 0=dimanche … 6=samedi (même convention que Date.getDay())
 *   slot    : "YYYY-MM-DDTHH:MM" en heure de Montréal — clé d'anti-doublon par créneau exact
 */
function _montrealNow() {
  const tz = "America/Montreal";
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit",
      hour12:  false,
      weekday: "short"  // "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
    })
      .formatToParts(new Date())
      .filter(p => p.type !== "literal")
      .map(p  => [p.type, p.value])
  );
  const WD = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };
  const h = parseInt(parts.hour, 10) % 24; // garde contre "24" rare sur certains runtimes
  const m = parseInt(parts.minute, 10);
  return {
    hour:    h,
    minute:  m,
    weekday: WD[parts.weekday.toLowerCase().slice(0, 3)] ?? -1,
    slot:    `${parts.year}-${parts.month}-${parts.day}T${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}`, // ex: "2026-03-25T08:30"
    tz
  };
}

// ── Helper preview : fiche explicative d'un article pour la réponse JSON ──────
/**
 * Construit la fiche explicative complète d'un article top en mode preview.
 * Inclut scores, breakdown des bonus digest, signaux d'enrichissement et
 * raisons lisibles (whyImportant + watchpoints) — miroir exact du contenu email.
 *
 * @param {object} a    - article enrichi + scoré
 * @param {number} rank - position dans le top (1-based)
 * @returns {object}
 */
function _previewArticle(a, rank) {
  const { score: dps, base, bonus, breakdown } = digestPriorityScore(a);
  return {
    rank,
    title:      a.title,
    link:       a.link,
    sourceName: a.sourceName,
    pubDate:    a.pubDate instanceof Date ? a.pubDate.toISOString() : null,

    // ── Score composite (construit par _scoreComposite après enrichissement) ──
    score:       a.score,
    criticality: a.criticality,

    // ── Score de priorisation digest (base + bonus signals) ──────────────────
    digestScore: dps,      // score final utilisé pour classer dans le top
    digestBase:  base,     // = a.score (hérite du composite)
    digestBonus: bonus,    // total des bonifications appliquées
    digestBreakdown: {     // détail par signal — tous cumulatifs
      kev:       breakdown.kev,       // +50 si CISA KEV actif
      epss:      breakdown.epss,      // +35 si EPSS≥70 % · +15 si ≥40 %
      cvss:      breakdown.cvss,      // +30 si CVSS≥9 · +15 si ≥7 · +5 si ≥4
      zeroDay:   breakdown.zeroDay,   // +30 si "zero-day" / "0-day" dans le titre
      watchlist: breakdown.watchlist, // +25 par mot watchlist (plafonné 75)
      trending:  breakdown.trending,  // +20 si isTrending
      sources:   breakdown.sources    // +5 par source supplémentaire (plafonné 20)
    },

    // ── Signaux d'enrichissement (KEV / EPSS / CVSS) ─────────────────────────
    isKEV:            a.isKEV      ?? false,
    epssScore:        a.epssScore  != null ? Math.round(a.epssScore * 1000) / 1000 : null,
    epssPercent:      a.epssScore  != null ? `${Math.round(a.epssScore * 100)} %`  : null,
    cvssScore:        a.cvssScore  ?? null,
    isTrending:       a.isTrending ?? false,
    sourceCount:      a.sourceCount ?? 1,     // nb sources couvrant ce sujet (après groupByTopic)
    cveIds:           (a.cveIds          || []).slice(0, 3),
    watchlistMatches: (a.watchlistMatches || []).slice(0, 5),

    // ── Déduplication ─────────────────────────────────────────────────────────
    topicKey: a._topicKey || _topicKey(a),    // clé utilisée pour l'anti-doublon inter-digest

    // ── Étiquettes courtes de sélection (lecture rapide en un coup d'œil) ──────
    selectionReasons: [
      a.isKEV                                            && "KEV actif",
      a.epssScore >= 0.70                                && `EPSS ${Math.round(a.epssScore * 100)} %`,
      a.epssScore >= 0.40 && a.epssScore < 0.70          && `EPSS modéré ${Math.round(a.epssScore * 100)} %`,
      a.cvssScore >= 9                                   && `CVSS ${a.cvssScore} critique`,
      a.cvssScore >= 7    && a.cvssScore < 9             && `CVSS ${a.cvssScore}`,
      /zero.?day|0.?day/i.test(a.title || "")           && "zero-day",
      (a.watchlistMatches || []).length > 0              && `watchlist (${a.watchlistMatches.length})`,
      a.isTrending                                       && "trending",
      (a.sourceCount || 1) >= 2                         && `${a.sourceCount} sources`,
      a.criticality === "high"  && !a.isKEV              && "haute criticité",
      a.criticality === "medium"&& !a.isKEV              && "criticité moyenne"
    ].filter(Boolean),

    // ── Raisons lisibles (identiques au contenu de l'email généré) ───────────
    whyImportant: whyImportant(a),   // phrase d'explication ("Cette vulnérabilité est …")
    watchpoints:  watchpoints(a)     // liste de recommandations immédiates
  };
}

// ── Handler principal ─────────────────────────────────────────────────────────
module.exports = async (req, res) => {

  // ── Authentification ───────────────────────────────────────────────────────
  // Vercel Cron appelle le endpoint en GET avec Authorization: Bearer <CRON_SECRET>
  // Déclenchement manuel : GET /api/scheduled-digest?secret=<CRON_SECRET>
  // Mode test            : GET /api/scheduled-digest?secret=<CRON_SECRET>&preview=1
  //                        GET /api/scheduled-digest?secret=<CRON_SECRET>&html=1
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret) {
    const bearer   = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    const qsSecret = req.query?.secret || "";
    if (bearer !== cronSecret && qsSecret !== cronSecret) {
      return res.status(401).json({ error: "Non autorisé — CRON_SECRET invalide ou manquant" });
    }
  }

  // ── Mode preview / html ────────────────────────────────────────────────────
  // preview=1 : exécute tout le pipeline sans envoyer d'email ni persister les IDs
  // html=1    : retourne l'HTML du briefing brut (ouvrir dans un navigateur)
  const isPreview  = req.query?.preview === "1" || req.query?.preview === "true";
  const isHtmlOnly = req.query?.html    === "1";
  const isTestMode = isPreview || isHtmlOnly;

  // ── Vérifications env ──────────────────────────────────────────────────────
  const recipient = process.env.DIGEST_RECIPIENT;
  if (!recipient && !isTestMode) {
    return res.status(500).json({
      error: "Variable DIGEST_RECIPIENT manquante. Configurez-la dans Vercel > Settings > Environment Variables."
    });
  }
  const channel = (process.env.DIGEST_CHANNEL || "resend").toLowerCase();

  // ── 0. Vérification heure / minute / jour / créneau (America/Montreal) ──────
  // Le cron Vercel tourne toutes les minutes ("* * * * *").
  // La décision d'envoi est prise ici selon l'heure ET la minute locales de Montréal :
  //   EDT (UTC-4, fin mars → début nov) et EST (UTC-5, reste de l'année)
  //   sont gérés automatiquement par Intl.DateTimeFormat.
  // DIGEST_HOUR accepte le format "HH" ou "HH:MM" (ex: "08" ou "08:30") — défaut "08:00".
  const _digestRaw     = process.env.DIGEST_HOUR || "08:00";
  const [_digestH, _digestM] = _digestRaw.split(":").map(Number);
  const _digestMinute  = isNaN(_digestM) ? 0 : _digestM;
  const _digestWeekday = (process.env.DIGEST_WEEKDAY ?? "") !== ""
    ? parseInt(process.env.DIGEST_WEEKDAY, 10)
    : null; // null = mode quotidien
  const mtl = _montrealNow();

  if (!isTestMode) {
    // Mauvaise heure ou mauvaise minute → skip silencieux (cron reviendra dans 1 min)
    if (mtl.hour !== _digestH || mtl.minute !== _digestMinute) {
      return res.status(200).json({
        skipped: true,
        reason:  `Heure Montréal (${String(mtl.hour).padStart(2,"0")}:${String(mtl.minute).padStart(2,"0")}) ≠ DIGEST_HOUR (${_digestRaw})`,
        now:     mtl.slot,
        tz:      mtl.tz
      });
    }
    // Mode hebdomadaire : mauvais jour → skip
    if (_digestWeekday !== null && mtl.weekday !== _digestWeekday) {
      return res.status(200).json({
        skipped: true,
        reason:  `Jour Montréal (${mtl.weekday}) ≠ DIGEST_WEEKDAY (${_digestWeekday})`,
        now:     mtl.slot, tz: mtl.tz
      });
    }
    // Anti-doublon : briefing déjà envoyé pour ce créneau (nécessite KV)
    const lastSlot = await loadLastSlot();
    if (lastSlot === mtl.slot) {
      return res.status(200).json({
        skipped:  true,
        reason:   `Briefing déjà envoyé pour le créneau ${mtl.slot}`,
        lastSlot, tz: mtl.tz
      });
    }
  }

  const t0 = Date.now();
  console.log("[scheduled-digest] %s — %d sources — canal:%s — Montréal:%s",
    isTestMode ? "PREVIEW" : "Démarrage", FEEDS.length, channel, mtl.slot);

  // ── 1. Fetch tous les flux en parallèle ───────────────────────────────────
  const results = await Promise.allSettled(FEEDS.map(_fetchFeed));

  const allArticles = [];
  let fetchOk = 0, fetchErr = 0;
  const feedDetails = [];
  results.forEach((r, i) => {
    if (r.status === "fulfilled") {
      allArticles.push(...r.value);
      fetchOk++;
      feedDetails.push({ id: FEEDS[i].id, ok: true,  articles: r.value.length });
      console.log("[scheduled-digest] ✓ %-30s %d articles", FEEDS[i].name, r.value.length);
    } else {
      fetchErr++;
      const errMsg = r.reason?.message || "erreur inconnue";
      feedDetails.push({ id: FEEDS[i].id, ok: false, error: errMsg });
      console.warn("[scheduled-digest] ✗ %-30s %s", FEEDS[i].name, errMsg);
    }
  });

  const t1 = Date.now();
  console.log("[scheduled-digest] Fetch %dms — %d articles bruts (%d/%d sources OK)",
    t1 - t0, allArticles.length, fetchOk, FEEDS.length);

  if (allArticles.length === 0) {
    return res.status(503).json({
      error: "Aucun article récupéré — tous les flux ont échoué",
      feeds: feedDetails
    });
  }

  // ── 1.5. Enrichissement KEV / EPSS / CVSS ─────────────────────────────────
  // Fetch CISA KEV list + scores EPSS en parallèle, puis CVSS par extraction texte.
  // Les articles sont modifiés en place avant le scoring.
  let enrichStats = { kevHits: 0, epssHits: 0, cvssHits: 0 };
  try {
    const enrichResult = await enrichArticles(allArticles);
    enrichStats = enrichResult.stats;
  } catch (e) {
    // Fallback propre : l'enrichissement est optionnel
    console.warn("[scheduled-digest] Enrichissement échoué (fallback mots-clés) :", e.message);
  }

  const t2 = Date.now();
  console.log("[scheduled-digest] Enrichissement %dms — KEV:%d EPSS:%d CVSS:%d",
    t2 - t1, enrichStats.kevHits, enrichStats.epssHits, enrichStats.cvssHits);

  // ── 1.6. Scoring post-enrichissement ──────────────────────────────────────
  // Calcule score + criticality maintenant que KEV/EPSS/CVSS sont disponibles.
  _scoreAll(allArticles);

  // ── 2. Déduplique par id ──────────────────────────────────────────────────
  const seen   = new Set();
  const unique = allArticles.filter(a => {
    if (!a.id || seen.has(a.id)) return false;
    seen.add(a.id);
    return true;
  });

  // ── 3. Filtre les articles récents (24h ; fallback 48h si trop peu) ───────
  const H24   = 24 * 60 * 60 * 1000;
  const H48   = 48 * 60 * 60 * 1000;
  const now   = Date.now();
  const last24 = unique.filter(a => a.pubDate instanceof Date && a.pubDate.getTime() >= now - H24);
  const queue  = last24.length >= 3
    ? last24
    : unique.filter(a => a.pubDate instanceof Date && a.pubDate.getTime() >= now - H48);

  if (queue.length === 0) {
    console.log("[scheduled-digest] Aucun article dans les 48 h. Briefing non envoyé.");
    return res.status(200).json({
      success: false,
      message: "Aucun article dans les 48 dernières heures — briefing non envoyé.",
      feedsOk: fetchOk, feedsErr: fetchErr
    });
  }

  // ── 3.5. Filtre les articles déjà envoyés (par ID exact) ─────────────────
  const sentIds     = await loadSentIds();
  const afterIdDedup = sentIds.size > 0
    ? queue.filter(a => !sentIds.has(a.id))
    : queue;
  // Fallback ID : si trop peu d'articles, on reprend la queue complète
  const idQueue = afterIdDedup.length >= 3 ? afterIdDedup : queue;

  // ── 3.6. Déduplication intra-digest par sujet ─────────────────────────────
  // Regroupe CVE identiques et titres similaires → un représentant par sujet.
  // Consolide sourceCount pour les sujets couverts par plusieurs sources.
  const topicQueue = _groupByTopic(idQueue);

  // ── 3.7. Filtre les sujets déjà couverts dans les digest précédents ───────
  const sentTopics = await loadSentTopics();
  const afterTopicDedup = sentTopics.size > 0
    ? topicQueue.filter(a => !sentTopics.has(a._topicKey))
    : topicQueue;
  // Fallback topic : si trop peu de sujets frais, on reprend topicQueue entier
  const finalQueue = afterTopicDedup.length >= 3 ? afterTopicDedup : topicQueue;

  console.log(
    "[scheduled-digest] Dédup : %d articles → %d IDs uniques → %d sujets → %d frais",
    queue.length, idQueue.length, topicQueue.length, finalQueue.length
  );

  // ── 4. Sélection des articles du briefing ─────────────────────────────────
  const top    = selectTopArticles(finalQueue, 5);
  const topIds = new Set(top.map(a => a.id));
  const rest   = finalQueue
    .filter(a => !topIds.has(a.id) && a.criticality !== "low")
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
    .slice(0, 20);

  // Log détaillé des top articles sélectionnés (visible dans Vercel Logs)
  console.log("[scheduled-digest] Sélection — top:%d rest:%d queue:%d",
    top.length, rest.length, finalQueue.length);
  top.forEach((a, i) => {
    const flags = [
      a.isKEV                        ? "KEV"                                    : "",
      a.epssScore != null            ? `EPSS:${Math.round(a.epssScore * 100)}%` : "",
      a.cvssScore != null            ? `CVSS:${a.cvssScore}`                    : "",
      a.cveIds?.length               ? a.cveIds[0]                              : ""
    ].filter(Boolean).join(" ");
    console.log("  %d. [%s|%d%s] %s",
      i + 1, a.criticality.toUpperCase(), a.score,
      flags ? ` ${flags}` : "",
      a.title.substring(0, 80));
  });

  // ── Stats pipeline (partagées entre mode réel et preview) ─────────────────
  const pipelineStats = {
    feeds:      { ok: fetchOk, err: fetchErr, total: FEEDS.length, details: feedDetails },
    articles:   { raw: allArticles.length, unique: unique.length, queue: queue.length },
    enrichment: enrichStats,
    dedup: {
      filteredById:    queue.length - idQueue.length,
      topicGroups:     topicQueue.length,
      filteredByTopic: topicQueue.length - finalQueue.length,
      finalQueue:      finalQueue.length,
      sentIds:         sentIds.size,
      sentTopics:      sentTopics.size
    },
    selection:  { top: top.length, rest: rest.length },
    timings:    { fetchMs: t1 - t0, enrichMs: t2 - t1 }
  };

  // ── 5. Génération du briefing ─────────────────────────────────────────────
  const label = new Date().toLocaleDateString("fr-FR",
    { weekday: "long", day: "numeric", month: "long", year: "numeric" });
  const date  = new Date().toLocaleDateString("fr-FR",
    { day: "numeric", month: "long", year: "numeric" });

  const subject = `☀️ Briefing Cybersécurité — ${top.length} alertes prioritaires · ${date}`;
  const html    = formatBriefingHTML(top, rest, label);
  const text    = formatBriefingText(top, rest, label);

  // ── 6. Preview / HTML — sortie anticipée sans envoi ──────────────────────
  // ?html=1 : retourne l'HTML brut pour prévisualisation dans un navigateur
  if (isHtmlOnly) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(html);
  }

  // ?preview=1 : réponse JSON complète, pas d'email, pas de persistance KV
  if (isPreview) {
    const elapsed = Date.now() - t0;
    console.log("[scheduled-digest] ✅ PREVIEW terminé en %dms (email non envoyé)", elapsed);
    return res.status(200).json({
      preview: true,
      subject,
      // Articles du top : fiche explicative complète (scores, breakdown, raisons)
      top: top.map((a, i) => _previewArticle(a, i + 1)),
      // Articles secondaires : résumé léger (score + topicKey pour traçabilité)
      rest: rest.slice(0, 10).map((a, i) => ({
        rank:        top.length + i + 1,
        title:       a.title,
        sourceName:  a.sourceName,
        score:       a.score,
        digestScore: digestPriorityScore(a).score,
        criticality: a.criticality,
        topicKey:    a._topicKey || _topicKey(a),
        isKEV:       a.isKEV ?? false,
        epssPercent: a.epssScore != null ? `${Math.round(a.epssScore * 100)} %` : null,
        cvssScore:   a.cvssScore ?? null
      })),
      stats: { ...pipelineStats, elapsedMs: elapsed }
    });
  }

  // ── 7. Envoi réel ─────────────────────────────────────────────────────────
  try {
    const emailResult = await _sendEmail({ channel, to: recipient, subject, html, text });

    // Persiste IDs, topicKeys et créneau pour les gardes inter-digest
    await saveSentIds(top.map(a => a.id));
    await saveSentTopics(top.map(a => a._topicKey || _topicKey(a)));
    await saveLastSlot(mtl.slot);

    const elapsed = Date.now() - t0;
    console.log("[scheduled-digest] ✅ Envoyé en %dms — top:%d rest:%d sources:%d/%d",
      elapsed, top.length, rest.length, fetchOk, FEEDS.length);

    return res.status(200).json({
      success: true,
      ...emailResult,
      stats:   { ...pipelineStats, elapsedMs: elapsed }
    });
  } catch (err) {
    console.error("[scheduled-digest] ❌ Erreur envoi email :", err.message);
    return res.status(502).json({ error: `Envoi email échoué : ${err.message}` });
  }
};
