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

const { FEEDS } = require("./lib/feeds");

// Cron configuré dans vercel.json → "0 7 * * *"
const CRON_SCHEDULE = "0 7 * * *";

module.exports = async (req, res) => {
  const channel = (process.env.DIGEST_CHANNEL || "resend").toLowerCase();

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
    warnings.push("DIGEST_RECIPIENT manquant — le briefing ne peut pas être envoyé");

  if (channel === "resend" && !email.resend)
    warnings.push("RESEND_API_KEY manquante");
  if (channel === "resend" && !email.resendFrom)
    warnings.push("RESEND_FROM non configuré (utilisera onboarding@resend.dev)");

  if (channel === "sendgrid" && !email.sendgrid)
    warnings.push("SENDGRID_API_KEY manquante");
  if (channel === "sendgrid" && !email.sendgridFrom)
    warnings.push("SENDGRID_FROM manquant");

  if (!email.cronSecret)
    warnings.push("CRON_SECRET non configuré — endpoint /api/scheduled-digest non sécurisé");

  if (!dedup.kvAvailable)
    warnings.push("KV_REST_API_URL / KV_REST_API_TOKEN absents — déduplication inter-digest désactivée");

  // ── Réponse ───────────────────────────────────────────────────────────────
  return res.status(200).json({
    status:    warnings.length === 0 ? "ok" : "degraded",
    timestamp: new Date().toISOString(),
    cron: {
      schedule:    CRON_SCHEDULE,
      description: "Chaque jour à 07:00 UTC (09:00 Paris heure d'été, 08:00 heure d'hiver)"
    },
    email,
    dedup,
    feeds: {
      count:   FEEDS.length,
      sources: FEEDS.map(f => f.id)
    },
    ...(warnings.length > 0 && { warnings })
  });
};
