// email-alerts.js — Alertes email/webhook pour articles haute criticité
//
// Canaux supportés (configurables dans le modal ⚙️ Paramètres) :
//   1. Webhook générique  : POST JSON → Zapier / Make / n8n / Slack / Discord
//   2. EmailJS            : envoi email direct navigateur (gratuit, 200/mois)
//   3. Resend             : API email transactionnel (3 000 emails/mois gratuits)
//   4. SendGrid           : API email transactionnel Twilio (100 emails/jour gratuits)
//   5. mailto             : fallback client email local
//
// ⚠️  SÉCURITÉ : Les canaux Resend/SendGrid exposent la clé API côté navigateur.
//     Pour la production, utilisez un proxy serverless (Vercel/Netlify function).
//
// Logique :
//   - Après chaque refresh, compare les nouveaux articles HIGH à l'historique
//   - Respecte un cooldown configurable (défaut 30 min) pour éviter le spam
//   - Rate-limit : max ALERT_BATCH_SIZE articles par envoi (défaut 5)
//   - Stocke les IDs déjà alertés en LocalStorage

const AlertManager = (() => {
  const STORAGE_KEY   = "cv_alerted_ids";
  const SETTINGS_KEY  = "cv_alert_settings";
  const DIGEST_KEY    = "cv_alert_digest";   // file d'attente pour les digests

  // ── Paramètres par défaut ─────────────────────────────────────────────────

  const DEFAULTS = {
    enabled:         false,
    channel:         "webhook",  // "webhook"|"emailjs"|"resend"|"sendgrid"|"mailto"
    mode:            "immediate",// "immediate"|"urgent_only"|"daily_digest"|"weekly_digest"
    // Webhook
    webhookUrl:      "",
    // EmailJS
    emailjsService:  "",
    emailjsTemplate: "",
    emailjsPublicKey:"",
    // Resend
    resendApiKey:    "",
    resendFrom:      "",         // ex: "CyberVeille Pro <alerts@votredomaine.fr>"
    // SendGrid
    sendgridApiKey:  "",
    sendgridFrom:    "",         // ex: "alerts@votredomaine.fr"
    // Commun email
    recipientEmail:  "",
    // Politique d'envoi
    threshold:       "high",     // "high" | "medium"
    cooldownMs:      30 * 60_000,
    batchSize:       5,
    lastSentAt:      0,
    lastDigestAt:    0           // timestamp du dernier digest envoyé
  };

  // ── Persistance des paramètres ────────────────────────────────────────────

  function loadSettings() {
    try {
      const raw = localStorage.getItem(SETTINGS_KEY);
      return raw ? { ...DEFAULTS, ...JSON.parse(raw) } : { ...DEFAULTS };
    } catch { return { ...DEFAULTS }; }
  }

  function saveSettings(settings) {
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); }
    catch (e) { console.warn("[Alerts] Sauvegarde paramètres échouée:", e.message); }
  }

  // ── Historique des IDs alertés ────────────────────────────────────────────

  function getAlertedIds() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? new Set(JSON.parse(raw)) : new Set();
    } catch { return new Set(); }
  }

  function saveAlertedIds(ids) {
    try {
      // Garder les 1000 derniers pour éviter une croissance infinie
      const arr = [...ids].slice(-1000);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(arr));
    } catch {}
  }

  function markAsAlerted(ids) {
    const existing = getAlertedIds();
    ids.forEach(id => existing.add(id));
    saveAlertedIds(existing);
  }

  // ── File de digest (localStorage) ────────────────────────────────────────

  function _loadDigest() {
    try {
      const raw = localStorage.getItem(DIGEST_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  }

  function _saveDigest(queue) {
    try {
      localStorage.setItem(DIGEST_KEY, JSON.stringify(queue.slice(-200)));
    } catch {}
  }

  function _addToDigest(articles) {
    const queue   = _loadDigest();
    const existing = new Set(queue.map(a => a.id));
    articles.forEach(a => { if (!existing.has(a.id)) queue.push(a); });
    _saveDigest(queue);
  }

  function _clearDigest() {
    try { localStorage.removeItem(DIGEST_KEY); } catch {}
  }

  /** Retourne true si le digest est dû (daily = 24h, weekly = 7j). */
  function _digestDue(settings) {
    const elapsed  = Date.now() - (settings.lastDigestAt || 0);
    const interval = settings.mode === "weekly_digest"
      ? 7 * 24 * 3600_000
      : 24 * 3600_000;
    return elapsed >= interval;
  }

  /** true si l'article est urgent : KEV actif, EPSS ≥ 70 %, ou score ≥ 80. */
  function _isUrgent(a) {
    return !!a.isKEV
      || (a.epssScore !== null && a.epssScore >= 0.70)
      || (a.score     !== undefined && a.score >= 80);
  }

  // ── Filtrage des articles à alerter ───────────────────────────────────────

  function getNewAlertCandidates(articles, threshold) {
    const alerted = getAlertedIds();
    const levels  = threshold === "medium"
      ? ["high", "medium"]
      : ["high"];

    return articles.filter(
      a => levels.includes(a.criticality) && !alerted.has(a.id)
    );
  }

  // ── Formatage du corps d'alerte ───────────────────────────────────────────

  function formatAlertBody(articles) {
    return articles.map(a => {
      const crit = a.criticality === "high" ? "🔴 HAUTE" : "🟠 MOYENNE";
      const date = a.pubDate.toLocaleString("fr-FR");
      return `${crit} | ${a.sourceName} | ${date}\n${a.title}\n${a.link}`;
    }).join("\n\n---\n\n");
  }

  function formatAlertHTML(articles) {
    const rows = articles.map(a => {
      const color = a.criticality === "high" ? "#f85149" : "#f0883e";
      const badge = a.criticality === "high" ? "🔴 HAUTE" : "🟠 MOYENNE";
      return `
        <tr>
          <td style="padding:8px;border-bottom:1px solid #30363d">
            <span style="color:${color};font-weight:700">${badge}</span>
          </td>
          <td style="padding:8px;border-bottom:1px solid #30363d;color:#8b949e">
            ${a.sourceName}
          </td>
          <td style="padding:8px;border-bottom:1px solid #30363d">
            <a href="${a.link}" style="color:#58a6ff">${a.title}</a>
          </td>
        </tr>`;
    }).join("");

    return `
      <div style="font-family:monospace;background:#0d1117;color:#e6edf3;padding:20px;border-radius:8px">
        <h2 style="color:#f85149;margin-top:0">🛡️ CyberVeille Pro — Alerte Cybersécurité</h2>
        <p style="color:#8b949e">${articles.length} nouvelle(s) alerte(s) détectée(s)</p>
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr style="color:#8b949e;font-size:12px">
              <th style="text-align:left;padding:8px">CRITICITÉ</th>
              <th style="text-align:left;padding:8px">SOURCE</th>
              <th style="text-align:left;padding:8px">TITRE</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
        <p style="color:#8b949e;font-size:12px;margin-top:16px">
          Envoyé par CyberVeille Pro · ${new Date().toLocaleString("fr-FR")}
        </p>
      </div>`;
  }

  // ── Envoi digest (toute la file, puis nettoyage) ──────────────────────────

  async function _sendDigest(settings) {
    const queue = _loadDigest();
    if (queue.length === 0) {
      console.log("[Alerts] Digest dû mais file vide — rien à envoyer");
      return;
    }

    const label    = settings.mode === "weekly_digest" ? "hebdomadaire" : "quotidien";
    const articles = queue.slice(0, settings.batchSize * 4); // digest = 4x le batch normal
    const subject  = `📋 CyberVeille Pro — Digest ${label} (${articles.length} alertes)`;

    // Réutiliser le HTML existant avec un en-tête adapté
    const html = formatAlertHTML(articles).replace(
      "🛡️ CyberVeille Pro — Alerte Cybersécurité",
      `📋 CyberVeille Pro — Digest ${label}`
    ).replace(
      `${articles.length} nouvelle(s) alerte(s) détectée(s)`,
      `${articles.length} alerte(s) accumulée(s) — période ${label}`
    );
    const text = `Digest ${label} CyberVeille Pro\n\n` + formatAlertBody(articles);

    // Envoyer via le même canal configuré
    const digestSettings = { ...settings };
    await _dispatch(articles, digestSettings, subject, html, text);

    // Nettoyage : retirer les envoyés, MAJ lastDigestAt
    _clearDigest();
    markAsAlerted(articles.map(a => a.id));
    saveSettings({ ...settings, lastDigestAt: Date.now(), lastSentAt: Date.now() });

    if (window.UI) {
      UI.showToast(`📋 Digest ${label} envoyé — ${articles.length} alerte(s)`, "success");
    }
    console.log("[Alerts] Digest %s envoyé (%d articles)", label, articles.length);
  }

  /** Dispatch vers le bon canal avec subject/html/text optionnels (digest override). */
  async function _dispatch(batch, settings, subjectOverride, htmlOverride, textOverride) {
    switch (settings.channel) {
      case "webhook":  await sendWebhook(batch, settings, subjectOverride);  break;
      case "emailjs":  await sendEmailJS(batch, settings, subjectOverride, htmlOverride, textOverride); break;
      case "resend":   await sendResend(batch, settings, subjectOverride, htmlOverride, textOverride);  break;
      case "sendgrid": await sendSendGrid(batch, settings, subjectOverride, htmlOverride, textOverride);break;
      case "mailto":         sendMailto(batch, settings, subjectOverride, textOverride);               break;
      default: throw new Error(`Canal inconnu : ${settings.channel}`);
    }
  }

  // ── Canal 1 : Webhook générique ────────────────────────────────────────────

  async function sendWebhook(articles, settings, subjectOverride) {
    if (!settings.webhookUrl) throw new Error("URL webhook non configurée");

    const payload = {
      event:      subjectOverride ? "cyberveille_digest" : "cyberveille_alert",
      timestamp:  new Date().toISOString(),
      count:      articles.length,
      threshold:  settings.threshold,
      articles:   articles.map(a => ({
        id:          a.id,
        title:       a.title,
        source:      a.sourceName,
        criticality: a.criticality,
        link:        a.link,
        pubDate:     a.pubDate.toISOString(),
        description: a.description
      })),
      // Compatibilité Slack
      text:       `🛡️ *CyberVeille Pro* — ${articles.length} nouvelle(s) alerte(s)\n` +
                  articles.slice(0, 3).map(a =>
                    `>*${a.criticality === "high" ? "🔴" : "🟠"} ${a.title}*\n>${a.link}`
                  ).join("\n")
    };

    const res = await fetch(settings.webhookUrl, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
      signal:  AbortSignal.timeout(10000)
    });

    if (!res.ok) throw new Error(`Webhook HTTP ${res.status}`);
    console.log("[Alerts] Webhook envoyé (%d articles)", articles.length);
  }

  // ── Canal 2 : EmailJS ─────────────────────────────────────────────────────

  async function sendEmailJS(articles, settings, subjectOverride, htmlOverride, textOverride) {
    const { emailjsService, emailjsTemplate, emailjsPublicKey, recipientEmail } = settings;
    if (!emailjsService || !emailjsTemplate || !emailjsPublicKey) {
      throw new Error("Configuration EmailJS incomplète (service/template/clé publique)");
    }

    // Chargement dynamique du SDK EmailJS si absent
    if (!window.emailjs) {
      await loadScript("https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js");
      window.emailjs.init({ publicKey: emailjsPublicKey });
    }

    await window.emailjs.send(emailjsService, emailjsTemplate, {
      to_email:      recipientEmail,
      subject:       subjectOverride || `🛡️ CyberVeille Pro — ${articles.length} alerte(s) haute(s)`,
      message_text:  textOverride    || formatAlertBody(articles),
      message_html:  htmlOverride    || formatAlertHTML(articles),
      alert_count:   articles.length,
      sent_at:       new Date().toLocaleString("fr-FR")
    });

    console.log("[Alerts] Email EmailJS envoyé (%d articles)", articles.length);
  }

  // ── Canal 3 : Resend ──────────────────────────────────────────────────────
  // Sur Vercel : POST /api/send-alert (clé API sécurisée côté serveur ✅)
  // En local   : appel direct Resend API (clé dans le modal — seulement pour dev)

  async function sendResend(articles, settings, subjectOverride, htmlOverride, textOverride) {
    const { resendFrom, recipientEmail } = settings;
    if (!recipientEmail) throw new Error("Email destinataire manquant");

    const subject = subjectOverride || `🛡️ CyberVeille Pro — ${articles.length} alerte(s) haute(s)`;
    const html    = htmlOverride    || formatAlertHTML(articles);
    const text    = textOverride    || formatAlertBody(articles);

    if (CONFIG.USE_API) {
      // ── Vercel : clé API lue depuis process.env côté serveur ──────────────
      const res = await fetch("/api/send-alert", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({
          channel:      "resend",
          to:           recipientEmail,
          fromOverride: resendFrom || undefined,
          subject, html, text
        }),
        signal: AbortSignal.timeout(15_000)
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(json.error || `Resend HTTP ${res.status}`);
      console.log("[Alerts] Resend envoyé via /api/send-alert — id:", json.id);
    } else {
      // ── Local : appel direct (clé API dans le modal) ──────────────────────
      const { resendApiKey } = settings;
      if (!resendApiKey) throw new Error("Clé API Resend manquante (mode local)");
      const res = await fetch("https://api.resend.com/emails", {
        method:  "POST",
        headers: { "Authorization": `Bearer ${resendApiKey}`, "Content-Type": "application/json" },
        body:    JSON.stringify({
          from:    resendFrom || "CyberVeille Pro <onboarding@resend.dev>",
          to:      [recipientEmail],
          subject, html, text
        }),
        signal: AbortSignal.timeout(12_000)
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(json.message || json.name || `Resend HTTP ${res.status}`);
      console.log("[Alerts] Resend envoyé (local) — id:", json.id);
    }
  }

  // ── Canal 4 : SendGrid ────────────────────────────────────────────────────
  // Sur Vercel : POST /api/send-alert (clé API sécurisée côté serveur ✅)
  // En local   : appel direct SendGrid API (clé dans le modal — seulement pour dev)

  async function sendSendGrid(articles, settings, subjectOverride, htmlOverride, textOverride) {
    const { sendgridFrom, recipientEmail } = settings;
    if (!recipientEmail) throw new Error("Email destinataire manquant");

    const subject = subjectOverride || `🛡️ CyberVeille Pro — ${articles.length} alerte(s) haute(s)`;
    const html    = htmlOverride    || formatAlertHTML(articles);
    const text    = textOverride    || formatAlertBody(articles);

    if (CONFIG.USE_API) {
      // ── Vercel : clé API lue depuis process.env côté serveur ──────────────
      const res = await fetch("/api/send-alert", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({
          channel:      "sendgrid",
          to:           recipientEmail,
          fromOverride: sendgridFrom || undefined,
          subject, html, text
        }),
        signal: AbortSignal.timeout(15_000)
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(json.error || `SendGrid HTTP ${res.status}`);
      console.log("[Alerts] SendGrid envoyé via /api/send-alert");
    } else {
      // ── Local : appel direct (clé API dans le modal) ──────────────────────
      const { sendgridApiKey } = settings;
      if (!sendgridApiKey) throw new Error("Clé API SendGrid manquante (mode local)");
      if (!sendgridFrom)   throw new Error("Adresse expéditeur SendGrid manquante");
      const res = await fetch("https://api.sendgrid.com/v3/mail/send", {
        method:  "POST",
        headers: { "Authorization": `Bearer ${sendgridApiKey}`, "Content-Type": "application/json" },
        body:    JSON.stringify({
          personalizations: [{ to: [{ email: recipientEmail }], subject }],
          from:    { email: sendgridFrom, name: "CyberVeille Pro" },
          content: [{ type: "text/plain", value: text }, { type: "text/html", value: html }],
          categories: ["cyberveille-pro"]
        }),
        signal: AbortSignal.timeout(12_000)
      });
      if (res.status !== 202) {
        const json = await res.json().catch(() => ({}));
        throw new Error(json.errors?.[0]?.message || `SendGrid HTTP ${res.status}`);
      }
      console.log("[Alerts] SendGrid envoyé (local, 202 Accepted)");
    }
  }

  // ── Canal 5 : mailto (fallback, requiert action utilisateur) ──────────────

  function sendMailto(articles, settings, subjectOverride, textOverride) {
    const subject = encodeURIComponent(
      subjectOverride || `🛡️ CyberVeille Pro — ${articles.length} alerte(s) cybersécurité`
    );
    const body = encodeURIComponent(
      textOverride || (
        `CyberVeille Pro — Alertes haute criticité\n` +
        `Généré le ${new Date().toLocaleString("fr-FR")}\n\n` +
        formatAlertBody(articles)
      )
    );
    const email = settings.recipientEmail || "";
    window.open(`mailto:${email}?subject=${subject}&body=${body}`, "_blank");
    console.log("[Alerts] mailto ouvert (%d articles)", articles.length);
  }

  // ── Utilitaire : chargement script dynamique ──────────────────────────────

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      if (document.querySelector(`script[src="${src}"]`)) { resolve(); return; }
      const s = document.createElement("script");
      s.src = src; s.onload = resolve; s.onerror = reject;
      document.head.appendChild(s);
    });
  }

  // ── Point d'entrée principal : processNewArticles() ───────────────────────
  // Appelé après chaque refresh avec la liste des articles frais

  async function processNewArticles(articles) {
    const settings = loadSettings();
    if (!settings.enabled) return;

    const mode       = settings.mode || "immediate";
    const candidates = getNewAlertCandidates(articles, settings.threshold);

    // ── Mode : immediate ────────────────────────────────────────────────────
    if (mode === "immediate") {
      const elapsed = Date.now() - (settings.lastSentAt || 0);
      if (elapsed < settings.cooldownMs) {
        const rem = Math.ceil((settings.cooldownMs - elapsed) / 60_000);
        console.log(`[Alerts] Cooldown actif — prochain envoi dans ${rem} min`);
        return;
      }
      if (candidates.length === 0) { console.log("[Alerts] Aucune nouvelle alerte"); return; }
      await _sendImmediate(candidates.slice(0, settings.batchSize), settings);
      return;
    }

    // ── Mode : urgent_only ──────────────────────────────────────────────────
    if (mode === "urgent_only") {
      const urgent = candidates.filter(_isUrgent);
      if (urgent.length === 0) { console.log("[Alerts] Aucun article urgent (KEV/EPSS/score)"); return; }
      console.log(`[Alerts] ${urgent.length} article(s) urgent(s) détecté(s)`);
      await _sendImmediate(urgent.slice(0, settings.batchSize), settings);
      return;
    }

    // ── Modes digest : accumuler puis envoyer si délai écoulé ───────────────
    if (mode === "daily_digest" || mode === "weekly_digest") {
      if (candidates.length > 0) {
        _addToDigest(candidates);
        console.log(`[Alerts] ${candidates.length} article(s) ajouté(s) au digest (file : ${_loadDigest().length})`);
      }
      if (_digestDue(settings)) {
        try { await _sendDigest(settings); }
        catch (err) {
          console.error("[Alerts] Digest échoué:", err.message);
          if (window.UI) UI.showToast(`⚠️ Digest échoué : ${err.message}`, "error");
        }
      }
    }
  }

  /** Envoi immédiat (modes immediate et urgent_only). */
  async function _sendImmediate(batch, settings) {
    console.log(`[Alerts] ${batch.length} article(s) → ${settings.channel}`);
    try {
      await _dispatch(batch, settings);
      markAsAlerted(batch.map(a => a.id));
      saveSettings({ ...settings, lastSentAt: Date.now() });
      if (window.UI) {
        UI.showToast(`📧 Alerte envoyée — ${batch.length} article(s) via ${settings.channel}`, "success");
      }
    } catch (err) {
      console.error("[Alerts] Échec envoi:", err.message);
      if (window.UI) UI.showToast(`⚠️ Alerte échouée : ${err.message}`, "error");
    }
  }

  /** Force l'envoi immédiat du digest (bouton manuel dans l'UI). */
  async function flushDigest() {
    const settings = loadSettings();
    if (!settings.enabled) { UI.showToast("Alertes désactivées", "warning"); return; }
    const queue = _loadDigest();
    if (queue.length === 0) { UI.showToast("File de digest vide", "info"); return; }
    try {
      await _sendDigest({ ...settings, lastDigestAt: 0 }); // force l'envoi
      UI.showToast(`📋 Digest forcé — ${queue.length} article(s) envoyé(s)`, "success");
    } catch (err) {
      UI.showToast(`⚠️ Digest échoué : ${err.message}`, "error");
    }
  }

  // ── API publique ──────────────────────────────────────────────────────────

  return {
    processNewArticles,
    loadSettings,
    saveSettings,
    flushDigest,
    getDigestCount: () => _loadDigest().length,
    DEFAULTS
  };
})();
