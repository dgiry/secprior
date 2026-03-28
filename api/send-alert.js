// api/send-alert.js — Dispatcher email sécurisé (Resend / SendGrid)
//
// ✅ Sécurité : les clés API ne sont JAMAIS exposées au navigateur
//    → stockées dans les variables d'environnement Vercel
//    → RESEND_API_KEY   : Dashboard Vercel > Settings > Environment Variables
//    → SENDGRID_API_KEY : idem
//    → RESEND_FROM      : ex "CyberVeille Pro <alerts@votredomaine.com>"
//    → SENDGRID_FROM    : ex "alerts@votredomaine.com"
//
// Payload attendu (POST JSON) :
//   { channel, to, subject, html, text, fromOverride? }

module.exports = async (req, res) => {
  // ── CORS : restreindre à l'origine de la requête (pas de wildcard en prod) ──
  const origin = req.headers.origin || "";
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  // Autoriser : origines explicitement listées + domaines Vercel natifs du projet
  const isAllowed =
    allowedOrigins.includes(origin) ||
    /^https:\/\/[a-z0-9-]+-[a-z0-9]+-[a-z0-9]+\.vercel\.app$/.test(origin) ||
    origin.endsWith(".vercel.app");

  if (isAllowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Alert-Token");
  res.setHeader("Vary", "Origin");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Méthode non autorisée" });

  // ── Auth optionnelle : ALERT_TOKEN (si défini dans les env vars Vercel) ─────
  const expectedToken = process.env.ALERT_TOKEN;
  if (expectedToken) {
    const providedToken = req.headers["x-alert-token"] || "";
    if (providedToken !== expectedToken) {
      console.warn("[send-alert] Token invalide — origin:", origin, "ip:", req.headers["x-forwarded-for"] || "?");
      return res.status(401).json({ error: "Token d'authentification invalide" });
    }
  }

  let body;
  try {
    body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: "Body JSON invalide" });
  }

  const { channel, to, subject, html, text } = body ?? {};

  if (!channel || !to || !subject || !(html || text)) {
    return res.status(400).json({
      error: "Champs requis manquants : channel, to, subject, html/text"
    });
  }

  // Validation basique de l'email destinataire
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)) {
    return res.status(400).json({ error: "Email destinataire invalide" });
  }

  // ── Canal Resend ────────────────────────────────────────────────────────────
  if (channel === "resend") {
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) {
      return res.status(500).json({
        error: "RESEND_API_KEY non configurée. Ajoutez-la dans Settings > Environment Variables sur Vercel."
      });
    }

    const from =
      body.fromOverride ||
      process.env.RESEND_FROM ||
      "CyberVeille Pro <onboarding@resend.dev>";

    try {
      const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from,
          to: [to],
          subject,
          html: html || undefined,
          text: text || undefined,
          tags: [
            { name: "source",  value: "cyberveille-pro" },
            { name: "channel", value: "resend" }
          ]
        }),
        signal: AbortSignal.timeout(12_000)
      });

      const json = await response.json().catch(() => ({}));
      if (!response.ok) {
        return res.status(response.status).json({
          error: json.message || json.name || `Resend erreur HTTP ${response.status}`
        });
      }

      console.log(`[send-alert] resend OK — id:${json.id} to:${to} subject:"${subject}"`);
      return res.status(200).json({ success: true, channel: "resend", id: json.id });
    } catch (err) {
      return res.status(502).json({ error: `Resend : ${err.message}` });
    }
  }

  // ── Canal SendGrid ─────────────────────────────────────────────────────────
  if (channel === "sendgrid") {
    const apiKey = process.env.SENDGRID_API_KEY;
    if (!apiKey) {
      return res.status(500).json({
        error: "SENDGRID_API_KEY non configurée. Ajoutez-la dans Settings > Environment Variables sur Vercel."
      });
    }

    const fromEmail = body.fromOverride || process.env.SENDGRID_FROM;
    if (!fromEmail) {
      return res.status(500).json({
        error: "SENDGRID_FROM non configurée (email expéditeur vérifié requis)."
      });
    }

    try {
      const response = await fetch("https://api.sendgrid.com/v3/mail/send", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          personalizations: [{ to: [{ email: to }], subject }],
          from: { email: fromEmail, name: "CyberVeille Pro" },
          content: [
            ...(text ? [{ type: "text/plain", value: text }] : []),
            ...(html  ? [{ type: "text/html",  value: html  }] : [])
          ],
          categories: ["cyberveille-pro"]
        }),
        signal: AbortSignal.timeout(12_000)
      });

      // SendGrid : 202 = succès, pas de body
      if (response.status !== 202) {
        const json = await response.json().catch(() => ({}));
        const msg = json.errors?.[0]?.message || `SendGrid HTTP ${response.status}`;
        return res.status(response.status).json({ error: msg });
      }

      console.log(`[send-alert] sendgrid OK (202) — to:${to} subject:"${subject}"`);
      return res.status(200).json({ success: true, channel: "sendgrid" });
    } catch (err) {
      return res.status(502).json({ error: `SendGrid : ${err.message}` });
    }
  }

  return res.status(400).json({
    error: `Canal '${channel}' non supporté par ce endpoint (webhook/emailjs/mailto gérés côté client)`
  });
};
