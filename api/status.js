// api/status.js — Endpoint health/config du briefing serveur
//
// Accès public (pas d'auth) — ne retourne jamais de valeurs sensibles, uniquement
// des booléens "configuré / non configuré" pour faciliter le diagnostic.
//
// GET /api/status
//
// Exemple de réponse :
// {
//   "status": "ok",                  // "ok" | "degraded"
//   "timestamp": "2026-03-25T07:00Z",
//   "cron": { "schedule": "0 7 * * *", "description": "..." },
//   "email": { "channel": "resend", "recipient": true, "resend": true, ... },
//   "dedup": { "kvAvailable": false },
//   "feeds": { "count": 13 },
//   "warnings": []                   // liste des problèmes détectés
// }

"use strict";

const { FEEDS }       = require("./_lib/feeds");
const { loadLastRun, loadRunHistory, loadBriefingHistory } = require("./_lib/dedup-store");

// Two vercel.json crons cover both offsets of America/Montreal:
//   0 12 * * *  → 08:00 EDT (UTC-4, late Mar → early Nov)
//   0 13 * * *  → 08:00 EST (UTC-5, Nov → late Mar)
// The handler checks local Montreal time internally and skips if it's not DIGEST_HOUR.
const CRON_SCHEDULE = "0 12,13 * * * UTC (≈ 08:00 Montréal)";

module.exports = async (req, res) => {
  const channel = (process.env.DIGEST_CHANNEL || "resend").toLowerCase();

  // ── Heure locale Montréal courante (pour affichage) ───────────────────────
  const mtlParts = Object.fromEntries(
    new Intl.DateTimeFormat("en-CA", {
      timeZone: "America/Montreal",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", hour12: false
    }).formatToParts(new Date()).filter(p => p.type !== "literal").map(p => [p.type, p.value])
  );
  const mtlNow = `${mtlParts.year}-${mtlParts.month}-${mtlParts.day} ${mtlParts.hour}:${mtlParts.minute}`;

  // ── Vérification des variables d'environnement ────────────────────────────
  const email = {
    channel,
    recipient:  !!process.env.DIGEST_RECIPIENT,
    resend:     !!process.env.RESEND_API_KEY,
    resendFrom: !!process.env.RESEND_FROM,
    sendgrid:   !!process.env.SENDGRID_API_KEY,
    sendgridFrom: !!process.env.SENDGRID_FROM,
    cronSecret: !!process.env.CRON_SECRET
  };

  const dedup = {
    kvAvailable: !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN)
  };

  // ── Détection des problèmes de configuration ──────────────────────────────
  const warnings = [];

  if (!email.recipient)
    warnings.push("DIGEST_RECIPIENT missing — digest cannot be sent");

  if (channel === "resend" && !email.resend)
    warnings.push("RESEND_API_KEY missing");
  if (channel === "resend" && !email.resendFrom)
    warnings.push("RESEND_FROM not configured (will use onboarding@resend.dev)");

  if (channel === "sendgrid" && !email.sendgrid)
    warnings.push("SENDGRID_API_KEY missing");
  if (channel === "sendgrid" && !email.sendgridFrom)
    warnings.push("SENDGRID_FROM missing");

  if (!email.cronSecret)
    warnings.push("CRON_SECRET not configured — /api/scheduled-digest endpoint is unsecured");

  if (!dedup.kvAvailable)
    warnings.push("KV_REST_API_URL / KV_REST_API_TOKEN missing — run history and deduplication disabled");

  // ── Dernier run + historique (depuis KV) ─────────────────────────────────
  // null / [] si KV non configuré ou si aucun run n'a encore eu lieu.
  const [lastRun, runHistory, briefingHistory] = await Promise.all([
    loadLastRun(), loadRunHistory(), loadBriefingHistory()
  ]);

  // ── Réponse ───────────────────────────────────────────────────────────────
  return res.status(200).json({
    status:    warnings.length === 0 ? "ok" : "degraded",
    timestamp: new Date().toISOString(),
    cron: {
      schedule:    CRON_SCHEDULE,
      description: "Two UTC slots cover EDT (UTC-4) and EST (UTC-5) — handler checks Montreal local time and skips if not DIGEST_HOUR"
    },
    digest: {
      hour:        process.env.DIGEST_HOUR    || "08:00",   // format HH ou HH:MM
      weekday:     process.env.DIGEST_WEEKDAY || null,
      mode:        (process.env.DIGEST_WEEKDAY ?? "") !== "" ? "weekly" : "daily",
      tz:          "America/Montreal",
      nowMontreal: mtlNow
    },
    email,
    dedup,
    // État du dernier run significatif (null si KV absent ou jamais exécuté)
    lastRun,
    // Feeds en erreur lors du dernier run (extrait de lastRun.lastStats.feedErrors)
    feedErrors: (lastRun?.lastStats?.feedErrors || []),
    // Historique des N derniers runs ([] si KV absent)
    runHistory,
    // Historique des N derniers briefings envoyés ([] si KV absent ou aucun envoi)
    briefingHistory,
    feeds: {
      count:   FEEDS.length,
      sources: FEEDS.map(f => f.id)
    },
    ...(warnings.length > 0 && { warnings })
  });
};
