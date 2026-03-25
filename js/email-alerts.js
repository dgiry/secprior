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

  // ── Sélection & analyse des articles pour le briefing ────────────────────

  /**
   * Sélectionne les 3–5 articles les plus critiques de la file.
   * Priorité : KEV actif > EPSS élevé > score > trending.
   */
  function _selectTopArticles(queue, max = 5) {
    const scored = queue.map(a => {
      let p = 0;
      if (a.isKEV)                                           p += 1000;
      if (a.epssScore !== null && a.epssScore >= 0.70)       p += 500 + Math.round(a.epssScore * 100);
      else if (a.epssScore !== null && a.epssScore >= 0.40)  p += 200 + Math.round(a.epssScore * 100);
      if (a.score !== undefined)                             p += a.score * 5;
      if (a.isTrending)                                      p += 50;
      return { ...a, _p: p };
    });
    scored.sort((a, b) => b._p - a._p);
    // Retourner au moins 3, au plus `max`
    return scored.slice(0, Math.max(3, Math.min(max, scored.length)));
  }

  /**
   * Génère une phrase expliquant pourquoi l'article est important.
   */
  function _whyImportant(a) {
    const r = [];
    if (a.isKEV)
      r.push("activement exploitée dans la nature (CISA KEV)");
    if (a.epssScore !== null && a.epssScore >= 0.70)
      r.push(`probabilité d'exploitation très élevée (EPSS ${Math.round(a.epssScore * 100)} %)`);
    else if (a.epssScore !== null && a.epssScore >= 0.40)
      r.push(`risque d'exploitation modéré (EPSS ${Math.round(a.epssScore * 100)} %)`);
    if (a.score >= 90)      r.push("score de criticité maximal");
    else if (a.score >= 80) r.push("score de criticité très élevé");
    if (a.isTrending)       r.push("en tendance sur les plateformes de threat intel");
    if (a.cveIds?.length)   r.push(`CVE : ${a.cveIds.slice(0, 2).join(", ")}`);
    if (r.length === 0)
      return a.criticality === "high"
        ? "Classé haute criticité par l'analyse automatique."
        : "Identifié comme menace potentielle.";
    return "Cette menace est " + r.join(", ") + ".";
  }

  /** Retourne les produits/secteurs touchés depuis les tags ou la source. */
  function _affectedProducts(a) {
    return a.tags?.length ? a.tags.slice(0, 4).join(" · ") : a.sourceName;
  }

  /**
   * Génère une liste de watchpoints immédiats selon le profil de la menace.
   */
  function _watchpoints(a) {
    const pts = [];
    if (a.isKEV)             pts.push("Appliquer les correctifs en urgence (délai CISA : 3 semaines)");
    if (a.epssScore >= 0.70) pts.push("Surveiller les logs d'exploitation sur les systèmes exposés");
    if (a.criticality === "high") pts.push("Vérifier l'exposition de vos actifs concernés");
    if (a.isTrending)        pts.push("Consulter les IoCs publiés par la communauté threat intel");
    if (a.cveIds?.length)    pts.push(`Vérifier le statut de patch pour ${a.cveIds[0]}`);
    if (pts.length === 0)    pts.push("Surveiller l'évolution et appliquer les recommandations du fournisseur");
    return pts;
  }

  // ── Formatage HTML du briefing ────────────────────────────────────────────

  /**
   * Génère l'email HTML complet du briefing matinal.
   * `top` = 3–5 articles prioritaires détaillés.
   * `rest` = autres alertes en format compact.
   */
  function _formatBriefingHTML(top, rest, label) {
    const now = new Date().toLocaleDateString("fr-FR",
      { weekday: "long", year: "numeric", month: "long", day: "numeric" });
    const total    = top.length + rest.length;
    const kevCount = [...top, ...rest].filter(a => a.isKEV).length;
    const highCount= [...top, ...rest].filter(a => a.criticality === "high").length;

    // Résumé exécutif
    let exec = `${total} menace(s) détectée(s) durant cette période`;
    if (kevCount > 0) exec += `, dont ${kevCount} vulnérabilité(s) KEV activement exploitée(s)`;
    if (highCount > 0) exec += `. ${highCount} alerte(s) haute criticité nécessitent votre attention`;
    exec += ".";

    // Cartes top alertes
    const topHTML = top.map(a => {
      const color = a.criticality === "high" ? "#f85149" : "#f0883e";
      const badge = a.criticality === "high" ? "🔴 HAUTE" : "🟠 MOYENNE";
      const meta  = [
        a.isKEV              ? "🚨 KEV ACTIF"                                          : "",
        a.epssScore !== null ? `EPSS ${Math.round(a.epssScore * 100)} %`               : "",
        a.score !== undefined ? `Score ${a.score}`                                      : ""
      ].filter(Boolean).join(" · ");
      const pts  = _watchpoints(a).map(p =>
        `<li style="margin:4px 0;color:#e6edf3">${p}</li>`).join("");

      return `
        <div style="border:1px solid ${color};border-radius:8px;padding:16px;margin-bottom:16px;background:#161b22">
          <div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:8px">
            <span style="color:${color};font-weight:700;font-size:13px">${badge}</span>
            ${meta ? `<span style="color:#8b949e;font-size:12px">${meta}</span>` : ""}
            <span style="color:#8b949e;font-size:12px;margin-left:auto">${a.sourceName}</span>
          </div>
          <h3 style="margin:0 0 8px;font-size:15px;line-height:1.4">
            <a href="${a.link}" style="color:#58a6ff;text-decoration:none">${a.title}</a>
          </h3>
          <p style="margin:0 0 8px;font-size:12px;color:#8b949e">🏷️ ${_affectedProducts(a)}</p>
          <p style="margin:0 0 12px;font-size:13px;color:#cdd9e5;background:#0d1117;
                    padding:10px;border-radius:4px;border-left:3px solid ${color}">
            📌 <strong>Pourquoi c'est important :</strong> ${_whyImportant(a)}
          </p>
          <div style="font-size:12px">
            <p style="margin:0 0 6px;color:#8b949e;font-weight:600;text-transform:uppercase;
                      letter-spacing:.5px">⚡ Watchpoints immédiats</p>
            <ul style="margin:0;padding-left:16px">${pts}</ul>
          </div>
        </div>`;
    }).join("");

    // Tableau compact des autres alertes
    const restHTML = rest.length === 0 ? "" : `
      <h3 style="color:#8b949e;font-size:13px;font-weight:600;text-transform:uppercase;
                 letter-spacing:.5px;margin:24px 0 12px">📋 Autres alertes (${rest.length})</h3>
      <table style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace">
        <tbody>
          ${rest.map(a => {
            const c = a.criticality === "high" ? "#f85149" : "#f0883e";
            const b = a.criticality === "high" ? "🔴" : "🟠";
            return `<tr>
              <td style="padding:5px 8px;border-bottom:1px solid #21262d;color:${c};white-space:nowrap">${b} ${a.criticality.toUpperCase()}</td>
              <td style="padding:5px 8px;border-bottom:1px solid #21262d;color:#8b949e;white-space:nowrap">${a.sourceName}</td>
              <td style="padding:5px 8px;border-bottom:1px solid #21262d">
                <a href="${a.link}" style="color:#58a6ff;text-decoration:none">${a.title}</a>
              </td>
            </tr>`;
          }).join("")}
        </tbody>
      </table>`;

    return `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
                  background:#0d1117;color:#e6edf3;padding:24px;border-radius:10px;max-width:680px;margin:0 auto">
        <!-- En-tête -->
        <div style="border-bottom:1px solid #30363d;padding-bottom:16px;margin-bottom:20px">
          <h1 style="margin:0 0 4px;font-size:20px;color:#e6edf3">☀️ Briefing Cybersécurité — ${now}</h1>
          <p style="margin:0;color:#8b949e;font-size:13px">CyberVeille Pro · Digest ${label}</p>
        </div>
        <!-- Résumé exécutif -->
        <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;margin-bottom:24px">
          <p style="margin:0 0 4px;color:#8b949e;font-size:11px;font-weight:600;
                    text-transform:uppercase;letter-spacing:.5px">RÉSUMÉ EXÉCUTIF</p>
          <p style="margin:0;font-size:14px;color:#cdd9e5">${exec}</p>
        </div>
        <!-- Top alertes -->
        <h2 style="font-size:15px;font-weight:700;color:#e6edf3;margin:0 0 16px;
                   text-transform:uppercase;letter-spacing:.5px">🎯 Top ${top.length} Alertes Prioritaires</h2>
        ${topHTML}
        <!-- Autres alertes -->
        ${restHTML}
        <!-- Pied de page -->
        <div style="border-top:1px solid #30363d;margin-top:24px;padding-top:16px;text-align:center">
          <p style="margin:0;color:#8b949e;font-size:11px">
            CyberVeille Pro · ${new Date().toLocaleString("fr-FR")} ·
            <a href="https://technocspace.com" style="color:#58a6ff">Ouvrir l'app</a>
          </p>
        </div>
      </div>`;
  }

  // ── Formatage texte brut du briefing ─────────────────────────────────────

  /** Version texte brut du briefing (fallback clients email sans HTML). */
  function _formatBriefingText(top, rest, label) {
    const now    = new Date().toLocaleDateString("fr-FR",
      { weekday: "long", year: "numeric", month: "long", day: "numeric" });
    const total    = top.length + rest.length;
    const kevCount = [...top, ...rest].filter(a => a.isKEV).length;
    const sep60  = "=".repeat(60);

    let t = `☀️ BRIEFING CYBERSÉCURITÉ — ${now.toUpperCase()}\n`;
    t += `CyberVeille Pro · Digest ${label}\n${sep60}\n\n`;

    t += "RÉSUMÉ EXÉCUTIF\n" + "-".repeat(30) + "\n";
    t += `${total} menace(s) détectée(s)`;
    if (kevCount > 0) t += `, dont ${kevCount} KEV activement exploitée(s)`;
    t += ".\n\n";

    t += `🎯 TOP ${top.length} ALERTES PRIORITAIRES\n${sep60}\n\n`;
    top.forEach((a, i) => {
      const badge = a.criticality === "high" ? "🔴 HAUTE" : "🟠 MOYENNE";
      const kev   = a.isKEV ? " | 🚨 KEV ACTIF" : "";
      const epss  = a.epssScore !== null
        ? ` | EPSS ${Math.round(a.epssScore * 100)} %` : "";
      t += `${i + 1}. ${badge}${kev}${epss}\n`;
      t += `   ${a.title}\n`;
      t += `   Source : ${a.sourceName} — ${_affectedProducts(a)}\n`;
      t += `   Lien   : ${a.link}\n`;
      t += `   ► ${_whyImportant(a)}\n`;
      _watchpoints(a).forEach(p => { t += `   • ${p}\n`; });
      t += "\n";
    });

    if (rest.length > 0) {
      t += `📋 AUTRES ALERTES (${rest.length})\n${"-".repeat(60)}\n`;
      rest.forEach(a => {
        const b = a.criticality === "high" ? "🔴" : "🟠";
        t += `${b} [${a.sourceName}] ${a.title}\n   ${a.link}\n`;
      });
      t += "\n";
    }

    t += `${sep60}\nGénéré par CyberVeille Pro le ${new Date().toLocaleString("fr-FR")}\n`;
    return t;
  }

  // ── Envoi digest (toute la file, puis nettoyage) ──────────────────────────

  async function _sendDigest(settings) {
    const queue = _loadDigest();
    if (queue.length === 0) {
      console.log("[Alerts] Digest dû mais file vide — rien à envoyer");
      return;
    }

    const label = settings.mode === "weekly_digest" ? "hebdomadaire" : "quotidien";

    // Sélectionner les top articles et le reste pour le briefing
    const top    = _selectTopArticles(queue, 5);
    const topIds = new Set(top.map(a => a.id));
    const rest   = queue.filter(a => !topIds.has(a.id));
    const total  = top.length + rest.length;

    const subject = `☀️ Briefing Cybersécurité ${label} — ${top.length} alertes prioritaires · ${new Date().toLocaleDateString("fr-FR")}`;
    const html    = _formatBriefingHTML(top, rest, label);
    const text    = _formatBriefingText(top, rest, label);

    await _dispatch([...top, ...rest], { ...settings }, subject, html, text);

    // Nettoyage : marquer tous comme alertés, MAJ lastDigestAt
    _clearDigest();
    markAsAlerted(queue.map(a => a.id));
    saveSettings({ ...settings, lastDigestAt: Date.now(), lastSentAt: Date.now() });

    if (window.UI) {
      UI.showToast(`☀️ Briefing ${label} envoyé — ${total} alerte(s)`, "success");
    }
    console.log("[Alerts] Briefing %s envoyé (%d articles, %d en top)", label, total, top.length);
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
