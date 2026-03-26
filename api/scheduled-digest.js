// api/scheduled-digest.js — Briefing cybersécurité quotidien côté serveur
//
// Déclenchement automatique : Vercel Cron (voir vercel.json → "crons")
// Déclenchement manuel     : GET /api/scheduled-digest?secret=<CRON_SECRET>
//
// Variables d'environnement requises (Vercel > Settings > Environment Variables) :
//   DIGEST_RECIPIENT   — adresse email destinataire du briefing
//   DIGEST_CHANNEL     — "resend" ou "sendgrid"  (défaut : "resend")
//   CRON_SECRET        — secret partagé pour sécuriser les appels manuels
//   RESEND_API_KEY     — clé API Resend    (si DIGEST_CHANNEL=resend)
//   RESEND_FROM        — expéditeur Resend (ex: "CyberVeille Pro <alerts@...>")
//   SENDGRID_API_KEY   — clé API SendGrid  (si DIGEST_CHANNEL=sendgrid)
//   SENDGRID_FROM      — email expéditeur vérifié SendGrid

"use strict";

const { parseRSS }           = require("./lib/rss-parser");
const { enrichArticles }     = require("./lib/enricher");
const { loadSentIds,
        saveSentIds }        = require("./lib/dedup-store");
const { selectTopArticles,
        formatBriefingHTML,
        formatBriefingText } = require("./lib/digest-engine");

// ── Flux RSS à surveiller (miroir de config.js → FEEDS) ──────────────────────
const FEEDS = [
  { id: "thehackernews",   name: "The Hacker News",       url: "https://feeds.feedburner.com/TheHackersNews" },
  { id: "krebsonsecurity", name: "Krebs on Security",     url: "https://krebsonsecurity.com/feed/" },
  { id: "bleepingcomputer",name: "Bleeping Computer",     url: "https://www.bleepingcomputer.com/feed/" },
  { id: "zataz",           name: "Zataz",                 url: "https://www.zataz.com/feed/" },
  { id: "certfr",          name: "CERT-FR",               url: "https://www.cert.ssi.gouv.fr/feed/" },
  { id: "cisa",            name: "CISA Advisories",       url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { id: "zdi",             name: "Zero Day Initiative",   url: "https://www.zerodayinitiative.com/rss/published/" },
  { id: "welivesecurity",  name: "WeLiveSecurity (ESET)", url: "https://www.welivesecurity.com/feed/" },
  { id: "sans",            name: "SANS ISC",              url: "https://isc.sans.edu/rssfeed_full.xml" },
  { id: "talos",           name: "Cisco Talos",           url: "https://blog.talosintelligence.com/rss/" },
  { id: "securelist",      name: "Securelist (Kaspersky)",url: "https://securelist.com/feed/" },
  { id: "unit42",          name: "Unit 42 (Palo Alto)",   url: "https://unit42.paloaltonetworks.com/feed/" },
  { id: "ncsc",            name: "NCSC UK",               url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml" }
];

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

// ── Handler principal ─────────────────────────────────────────────────────────
module.exports = async (req, res) => {

  // ── Authentification ───────────────────────────────────────────────────────
  // Vercel Cron appelle le endpoint en GET avec Authorization: Bearer <CRON_SECRET>
  // Déclenchement manuel : GET /api/scheduled-digest?secret=<CRON_SECRET>
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret) {
    const bearer   = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    const qsSecret = req.query?.secret || "";
    if (bearer !== cronSecret && qsSecret !== cronSecret) {
      return res.status(401).json({ error: "Non autorisé — CRON_SECRET invalide ou manquant" });
    }
  }

  // ── Vérifications env ──────────────────────────────────────────────────────
  const recipient = process.env.DIGEST_RECIPIENT;
  if (!recipient) {
    return res.status(500).json({
      error: "Variable DIGEST_RECIPIENT manquante. Configurez-la dans Vercel > Settings > Environment Variables."
    });
  }
  const channel = (process.env.DIGEST_CHANNEL || "resend").toLowerCase();

  const started = Date.now();
  console.log("[scheduled-digest] Démarrage — %d sources — canal : %s — destinataire : %s",
    FEEDS.length, channel, recipient);

  // ── 1. Fetch tous les flux en parallèle ───────────────────────────────────
  const results = await Promise.allSettled(FEEDS.map(_fetchFeed));

  const allArticles = [];
  let fetchOk = 0, fetchErr = 0;
  results.forEach((r, i) => {
    if (r.status === "fulfilled") {
      allArticles.push(...r.value);
      fetchOk++;
      console.log("[scheduled-digest] ✓ %-30s %d articles", FEEDS[i].name, r.value.length);
    } else {
      fetchErr++;
      console.warn("[scheduled-digest] ✗ %-30s %s", FEEDS[i].name, r.reason?.message || "erreur");
    }
  });

  if (allArticles.length === 0) {
    return res.status(503).json({
      error: "Aucun article récupéré — tous les flux ont échoué",
      feedsErr: fetchErr
    });
  }

  // ── 1.5. Enrichissement KEV / EPSS / CVSS ─────────────────────────────────
  // Fetch CISA KEV list + scores EPSS en parallèle, puis CVSS par extraction texte.
  // Les articles sont modifiés en place avant le scoring.
  let enrichStats = { kevHits: 0, epssHits: 0, cvssHits: 0 };
  try {
    const enrichResult = await enrichArticles(allArticles);
    enrichStats = enrichResult.stats;
    console.log("[scheduled-digest] ✓ Enrichissement — KEV:%d EPSS:%d CVSS:%d",
      enrichStats.kevHits, enrichStats.epssHits, enrichStats.cvssHits);
  } catch (e) {
    // Fallback propre : l'enrichissement est optionnel
    console.warn("[scheduled-digest] Enrichissement échoué (fallback mots-clés) :", e.message);
  }

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

  // ── 3.5. Filtre les articles déjà envoyés dans les digest précédents ─────
  // loadSentIds() retourne un Set vide si Vercel KV n'est pas configuré.
  const sentIds   = await loadSentIds();
  const freshQueue = sentIds.size > 0
    ? queue.filter(a => !sentIds.has(a.id))
    : queue;
  // Fallback : si trop peu d'articles après dédup, on reprend la queue complète
  const finalQueue = freshQueue.length >= 3 ? freshQueue : queue;
  if (sentIds.size > 0) {
    console.log("[scheduled-digest] Dédup : %d → %d articles (filtrés: %d)",
      queue.length, finalQueue.length, queue.length - finalQueue.length);
  }

  // ── 4. Sélection des articles du briefing ─────────────────────────────────
  const top    = selectTopArticles(finalQueue, 5);
  const topIds = new Set(top.map(a => a.id));
  const rest   = finalQueue
    .filter(a => !topIds.has(a.id) && a.criticality !== "low")
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
    .slice(0, 20);

  // ── 5. Génération du briefing ─────────────────────────────────────────────
  const label = new Date().toLocaleDateString("fr-FR",
    { weekday: "long", day: "numeric", month: "long", year: "numeric" });
  const date  = new Date().toLocaleDateString("fr-FR",
    { day: "numeric", month: "long", year: "numeric" });

  const subject = `☀️ Briefing Cybersécurité — ${top.length} alertes prioritaires · ${date}`;
  const html    = formatBriefingHTML(top, rest, label);
  const text    = formatBriefingText(top, rest, label);

  // ── 6. Envoi ──────────────────────────────────────────────────────────────
  try {
    const emailResult = await _sendEmail({ channel, to: recipient, subject, html, text });

    // Persiste les IDs des top articles pour éviter les répétitions demain
    await saveSentIds(top.map(a => a.id));

    const elapsed = Date.now() - started;
    console.log("[scheduled-digest] ✅ Envoyé en %d ms — top:%d rest:%d sources:%d/%d",
      elapsed, top.length, rest.length, fetchOk, FEEDS.length);

    return res.status(200).json({
      success: true,
      ...emailResult,
      stats: {
        topArticles:   top.length,
        otherArticles: rest.length,
        totalQueue:    queue.length,
        totalUnique:   unique.length,
        feedsOk:       fetchOk,
        feedsErr:      fetchErr,
        enrichment:    enrichStats,
        elapsedMs:     elapsed
      }
    });
  } catch (err) {
    console.error("[scheduled-digest] ❌ Erreur envoi email :", err.message);
    return res.status(502).json({ error: `Envoi email échoué : ${err.message}` });
  }
};
