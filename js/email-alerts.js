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
  const HISTORY_KEY   = "cv_alert_history";  // historique des envois
  const HISTORY_MAX   = 200;                 // entrées conservées
  const DEDUPE_KEY    = "cv_alert_dedupe";   // anti-doublon temporel

  // Fenêtres d'anti-doublon (centralisées, modifiables ici)
  const DEDUPE_CONFIG = {
    windowMsImmediate:              60 * 60_000,          // 1 h   — mode immediate
    windowMsUrgent:                 3  * 60 * 60_000,     // 3 h   — mode urgent_only
    windowMsDigest:                 7  * 24 * 60 * 60_000,// 7 j   — cross-mode / inter-digest
    suppressDigestIfAlreadySent:    true,  // exclure du digest si déjà envoyé individuellement
    suppressDigestIfInRecentDigest: true,  // exclure si déjà dans un digest récent
    pruneAfterMs:                   30 * 24 * 60 * 60_000 // 30 j  — rétention store
  };

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
    lastDigestAt:    0,          // timestamp du dernier digest envoyé
    digestHour:      "08:00",    // heure locale d'envoi du digest (format HH:MM)
    digestWeekday:   1,          // jour d'envoi du weekly_digest (0=dim … 6=sam, défaut lundi)
    // Production Vercel : token optionnel pour authentifier /api/send-alert
    alertToken:      ""          // si vide, aucun header X-Alert-Token envoyé
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
    ids.filter(Boolean).forEach(id => existing.add(id)); // ignore les IDs undefined/null/""
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
    const queue    = _loadDigest();
    const existing = new Set(queue.map(a => a.id));
    let skipped = 0;
    articles.forEach(a => {
      if (existing.has(a.id)) return;
      if (shouldExcludeFromDigest(a)) { skipped++; return; } // étapes 5 & 6
      queue.push(a);
    });
    if (skipped > 0) console.log(`[Alerts] Dedupe digest : ${skipped} article(s) exclus (déjà envoyés)`);
    _saveDigest(queue);
  }

  function _clearDigest() {
    try { localStorage.removeItem(DIGEST_KEY); } catch {}
  }

  // ── Historique des alertes envoyées ──────────────────────────────────────

  function loadAlertHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  }

  function saveAlertHistory(history) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, HISTORY_MAX)));
    } catch (e) { console.warn("[Alerts] Sauvegarde historique échouée:", e.message); }
  }

  function appendAlertHistory(entry) {
    const h = loadAlertHistory();
    h.unshift(entry);            // plus récent en tête
    saveAlertHistory(h);
  }

  function clearAlertHistory() {
    try { localStorage.removeItem(HISTORY_KEY); } catch {}
  }

  /** Construit une entrée d'historique normalisée. */
  function _makeHistoryEntry(articles, settings, reason, success, errorMessage, meta) {
    return {
      id:           `alert_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      sentAt:       new Date().toISOString(),
      channel:      settings.channel,
      mode:         settings.mode,
      success,
      articleCount: articles.length,
      reason,
      titles:       articles.slice(0, 3).map(a => a.title || "").filter(Boolean),
      errorMessage: errorMessage || "",
      meta:         meta || {}
    };
  }

  /** Raison métier détaillée pour urgent_only. */
  function _urgentReason(batch) {
    if (batch.some(a => a.isKEV))                              return "urgent_only: kev";
    if (batch.some(a => a.epssScore >= 0.70))                  return "urgent_only: epss≥70%";
    if (batch.some(a => a.score !== undefined && a.score >= 80)) return "urgent_only: score≥80";
    return "urgent_only";
  }

  // ── Anti-doublon temporel (déduplication par fenêtre de temps) ───────────

  /**
   * Clé stable pour identifier un article de façon unique.
   * Priorité : id > URL canonique > CVE+source > titre+source
   */
  function makeAlertDedupeKey(article) {
    // 1. ID applicatif
    if (article.id && article.id.length > 4) return `id:${article.id}`;
    // 2. URL sans paramètres tracking
    if (article.link) {
      try {
        const u = new URL(article.link);
        ["utm_source","utm_medium","utm_campaign","ref","source","fbclid"]
          .forEach(p => u.searchParams.delete(p));
        return `url:${u.origin}${u.pathname}`;
      } catch {}
    }
    // 3. CVE principale + source
    const cve = (Array.isArray(article.cveIds) && article.cveIds[0])
      || ((article.title || "").match(/CVE-\d{4}-\d+/i) || [])[0];
    if (cve) {
      const src = (article.sourceName || "").toLowerCase().replace(/\s+/g,"").slice(0, 20);
      return `cve:${cve.toUpperCase()}:${src}`;
    }
    // 4. Titre normalisé + source
    const title = (article.title || "")
      .toLowerCase().replace(/[^a-z0-9]+/g, "_").slice(0, 60);
    const src = (article.sourceName || article.source || "").toLowerCase().slice(0, 15);
    return `t:${title}:${src}`;
  }

  function loadAlertDedupe() {
    try {
      const raw = localStorage.getItem(DEDUPE_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch { return {}; }
  }

  function saveAlertDedupe(state) {
    try {
      localStorage.setItem(DEDUPE_KEY, JSON.stringify(state));
    } catch (e) { console.warn("[Alerts] Sauvegarde dedupe échouée:", e.message); }
  }

  /** Purge in-place les entrées plus vieilles que pruneAfterMs. */
  function pruneAlertDedupe(state) {
    const cutoff = Date.now() - DEDUPE_CONFIG.pruneAfterMs;
    for (const key of Object.keys(state)) {
      if (new Date(state[key].sentAt).getTime() < cutoff) delete state[key];
    }
  }

  /**
   * Retourne true si l'article a déjà été envoyé dans la fenêtre windowMs.
   * Étape 3 (immediate) et 4 (urgent_only).
   */
  function wasRecentlySent(article, windowMs) {
    const entry = loadAlertDedupe()[makeAlertDedupeKey(article)];
    return !!entry && (Date.now() - new Date(entry.sentAt).getTime()) < windowMs;
  }

  /**
   * Enregistre un batch dans le store dedupe — une seule lecture/écriture.
   * Appelé après chaque envoi réussi.
   */
  function _markBatchSent(batch, mode, channel) {
    const state = loadAlertDedupe();
    const now   = new Date().toISOString();
    batch.forEach(a => {
      state[makeAlertDedupeKey(a)] = {
        sentAt: now, mode, channel,
        articleId: a.id  || "",
        title:     (a.title || "").slice(0, 100)
      };
    });
    pruneAlertDedupe(state);
    saveAlertDedupe(state);
  }

  /**
   * Étapes 5 & 6 — Retourne true si l'article doit être exclu de la file digest.
   * - Déjà envoyé individuellement (immediate/urgent) dans les 7 derniers jours.
   * - Déjà inclus dans un digest récent.
   */
  function shouldExcludeFromDigest(article) {
    const entry = loadAlertDedupe()[makeAlertDedupeKey(article)];
    if (!entry) return false;
    const age = Date.now() - new Date(entry.sentAt).getTime();
    if (age >= DEDUPE_CONFIG.windowMsDigest) return false;
    const isIndividual = entry.mode === "immediate" || entry.mode === "urgent_only";
    const isDigest     = entry.mode === "daily_digest" || entry.mode === "weekly_digest"
                      || entry.mode === "manual_digest_flush";
    return (DEDUPE_CONFIG.suppressDigestIfAlreadySent    && isIndividual)
        || (DEDUPE_CONFIG.suppressDigestIfInRecentDigest && isDigest);
  }

  /**
   * Retourne true si le digest est dû selon l'heure fixe configurée.
   * - daily_digest  : vrai si l'heure locale >= digestHour ET pas encore envoyé aujourd'hui.
   * - weekly_digest : même logique + au moins 6 jours depuis le dernier envoi.
   * Remplace l'ancienne logique purement basée sur un intervalle de 24h/7j.
   */
  function _digestDue(settings) {
    const [h, m]   = (settings.digestHour || "08:00").split(":").map(Number);
    const now      = new Date();

    // Heure de déclenchement prévue aujourd'hui
    const todaySlot = new Date(now);
    todaySlot.setHours(h, m, 0, 0);

    // Pas encore l'heure configurée → jamais dû
    if (now < todaySlot) return false;

    const last = settings.lastDigestAt || 0;

    if (settings.mode === "weekly_digest") {
      // Vérifier que c'est bien le jour configuré (0=dim … 6=sam)
      const weekday = settings.digestWeekday ?? 1;
      if (now.getDay() !== weekday) return false;
      // Bon jour + heure passée + pas encore envoyé sur ce créneau hebdo
      return last < todaySlot.getTime();
    }
    // daily_digest : dû si l'heure est passée ET pas encore envoyé depuis le slot du jour
    return last < todaySlot.getTime();
  }

  /** true si l'article est urgent : priorityLevel critique, KEV, EPSS ≥ 70 %, ou score ≥ 80. */
  function _isUrgent(a) {
    if (a.priorityLevel === "critical_now") return true;  // V2 : niveau priorité explicite
    return !!a.isKEV
      || (a.epssScore !== null && a.epssScore >= 0.70)
      || (a.score     !== undefined && a.score >= 80);
  }

  /**
   * Retourne { color, badge } pour un article selon son niveau de priorité.
   * V2 : utilise priorityLevel. Fallback V1 : criticality.
   */
  function _alertBadge(a) {
    if (a.priorityLevel) {
      switch (a.priorityLevel) {
        case "critical_now": return { color: "#f85149", badge: "🔴 CRITICAL" };
        case "investigate":  return { color: "#f0883e", badge: "🟠 HIGH"     };
        case "watch":        return { color: "#58a6ff", badge: "🔵 MEDIUM"   };
        default:             return { color: "#8b949e", badge: "⚪ LOW"      };
      }
    }
    // Fallback V1 : criticality (articles sans pipeline complet)
    return a.criticality === "high"
      ? { color: "#f85149", badge: "🔴 HIGH"    }
      : { color: "#f0883e", badge: "🟠 MEDIUM"  };
  }

  // ── Filtrage des articles à alerter ───────────────────────────────────────

  /**
   * Retourne les articles non encore alertés qui dépassent le seuil configuré.
   * V2 : filtre sur priorityLevel si disponible. Fallback V1 : criticality.
   */
  function getNewAlertCandidates(articles, threshold) {
    const alerted = getAlertedIds();
    return articles.filter(a => {
      if (alerted.has(a.id)) return false;
      // V2 : priorityLevel disponible (articles passés par le pipeline complet)
      if (a.priorityLevel) {
        return threshold === "medium"
          ? ["critical_now", "investigate"].includes(a.priorityLevel)
          : a.priorityLevel === "critical_now";
      }
      // Fallback V1 : criticality heuristique
      const levels = threshold === "medium" ? ["high", "medium"] : ["high"];
      return levels.includes(a.criticality);
    });
  }

  // ── Helpers de sécurité / robustesse pour la génération HTML ─────────────

  /** Échappe les caractères HTML sensibles (titre, source, etc.). */
  function _escHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  /** Retourne l'URL uniquement si elle est http/https, sinon "#". */
  function _safeHref(url) {
    try {
      const u = new URL(String(url || ""));
      return (u.protocol === "https:" || u.protocol === "http:") ? u.href : "#";
    } catch { return "#"; }
  }

  // ── Formatage du corps d'alerte ───────────────────────────────────────────

  function formatAlertBody(articles) {
    return articles.map(a => {
      const { badge } = _alertBadge(a);
      const date = a.pubDate instanceof Date ? a.pubDate.toLocaleString("en-US") : String(a.pubDate || "");
      return `${badge} | ${a.sourceName || "?"} | ${date}\n${a.title || "(untitled)"}\n${a.link || ""}`;
    }).join("\n\n---\n\n");
  }

  function formatAlertHTML(articles) {
    const rows = articles.map(a => {
      const { color, badge } = _alertBadge(a);
      return `
        <tr>
          <td style="padding:8px;border-bottom:1px solid #30363d">
            <span style="color:${color};font-weight:700">${badge}</span>
          </td>
          <td style="padding:8px;border-bottom:1px solid #30363d;color:#8b949e">
            ${_escHtml(a.sourceName || "")}
          </td>
          <td style="padding:8px;border-bottom:1px solid #30363d">
            <a href="${_safeHref(a.link)}" style="color:#58a6ff">${_escHtml(a.title || "(sans titre)")}</a>
          </td>
        </tr>`;
    }).join("");

    return `
      <div style="font-family:monospace;background:#0d1117;color:#e6edf3;padding:20px;border-radius:8px">
        <h2 style="color:#f85149;margin-top:0">🛡️ CyberVeille Pro — Security Alert</h2>
        <p style="color:#8b949e">${articles.length} new alert(s) detected</p>
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr style="color:#8b949e;font-size:12px">
              <th style="text-align:left;padding:8px">SEVERITY</th>
              <th style="text-align:left;padding:8px">SOURCE</th>
              <th style="text-align:left;padding:8px">TITLE</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
        <p style="color:#8b949e;font-size:12px;margin-top:16px">
          Sent by CyberVeille Pro · ${new Date().toLocaleString("en-US")}
        </p>
      </div>`;
  }

  // ── Sélection & analyse des articles pour le briefing ────────────────────

  /**
   * Sélectionne les 3–5 articles les plus critiques de la file.
   * Priorité : KEV actif > EPSS élevé > score > trending.
   */
  /**
   * Sélectionne les 3–5 articles les plus critiques via digestPriorityScore().
   * Fallback sur article.score si scorer.js n'est pas disponible.
   */
  function _selectTopArticles(queue, max = 5) {
    const scored = queue.map(a => ({
      ...a,
      _p: typeof digestPriorityScore === "function"
        ? (digestPriorityScore(a)?.score ?? 0)  // null-guard si le scorer retourne null
        : (a.score ?? 0)
    }));
    scored.sort((a, b) => b._p - a._p);
    // Retourner au moins 3, au plus `max`
    return scored.slice(0, Math.max(3, Math.min(max, scored.length)));
  }

  /**
   * Calcule les statistiques enrichies du digest :
   * total, HIGH, KEV, watchlist, top CVEs, top vendors, watchlist terms.
   */
  function _buildDigestStats(articles) {
    const total          = articles.length;
    // V2 : priorityLevel critique, fallback criticality
    const highCount      = articles.filter(a =>
      a.priorityLevel ? a.priorityLevel === "critical_now" : a.criticality === "high"
    ).length;
    const kevCount       = articles.filter(a => a.isKEV).length;
    const watchlistCount = articles.filter(a => a.watchlistMatches?.length > 0).length;

    // Top CVEs (par fréquence)
    const cveFreq = {};
    articles.forEach(a => (a.cveIds || []).forEach(cve => { cveFreq[cve] = (cveFreq[cve] || 0) + 1; }));
    const topCVEs = Object.entries(cveFreq).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([c]) => c);

    // Top vendors (détection légère sur titre + description + tags)
    const VD = [
      ["Microsoft",  ["microsoft","windows","azure","exchange","sharepoint","outlook","active directory","defender","hyper-v"]],
      ["Google",     ["google","chrome","android","chromium","workspace"]],
      ["Apple",      ["apple","ios","macos","safari","iphone","ipad"]],
      ["Cisco",      ["cisco","ios xe","nx-os","webex"]],
      ["Apache",     ["apache","log4j","tomcat","struts"]],
      ["VMware",     ["vmware","esxi","vcenter"]],
      ["Fortinet",   ["fortinet","fortigate","fortios","forticlient"]],
      ["Palo Alto",  ["palo alto","pan-os","prisma"]],
      ["Atlassian",  ["atlassian","confluence","jira","bitbucket"]],
      ["Linux",      ["linux","ubuntu","debian","red hat","rhel","kernel"]],
      ["Oracle",     ["oracle","weblogic","java"]],
      ["Ivanti",     ["ivanti","mobileiron"]],
      ["Citrix",     ["citrix","netscaler"]],
      ["F5",         ["f5","big-ip","nginx"]],
      ["Juniper",    ["juniper","junos"]],
      ["OpenSSL",    ["openssl","openssh"]],
      ["Veeam",      ["veeam"]],
      ["SolarWinds", ["solarwinds"]],
      ["GitLab",     ["gitlab"]],
      ["WordPress",  ["wordpress"]],
      ["SAP",        ["sap"]],
    ];
    const vCount = {};
    articles.forEach(a => {
      const hay = [a.title || "", a.description || "", ...(a.tags || [])].join(" ").toLowerCase();
      VD.forEach(([name, terms]) => {
        if (terms.some(t => hay.includes(t))) vCount[name] = (vCount[name] || 0) + 1;
      });
    });
    const topVendors = Object.entries(vCount).sort((a, b) => b[1] - a[1])
      .slice(0, 5).map(([name, count]) => ({ name, count }));

    // Watchlist terms (par fréquence)
    const wFreq = {};
    articles.forEach(a => (a.watchlistMatches || []).forEach(t => { wFreq[t] = (wFreq[t] || 0) + 1; }));
    const watchlistTerms = Object.entries(wFreq).sort((a, b) => b[1] - a[1])
      .slice(0, 5).map(([term, count]) => ({ term, count }));

    return { total, highCount, kevCount, watchlistCount, topCVEs, topVendors, watchlistTerms };
  }

  /** Bloc HTML des statistiques enrichies (KPI chips + CVE + vendors + watchlist). */
  function _statsBlockHTML(stats) {
    const chips = [
      { label: "Articles",   value: stats.total,        color: "#e6edf3", bg: "#21262d" },
      { label: "🔴 CRITICAL", value: stats.highCount,     color: "#f85149", bg: stats.highCount  > 0 ? "#2d1515" : "#161b22" },
      { label: "🚨 KEV",     value: stats.kevCount,      color: stats.kevCount    > 0 ? "#f85149" : "#8b949e", bg: stats.kevCount > 0 ? "#2d1515" : "#161b22" },
    ];
    if (stats.watchlistCount > 0)
      chips.push({ label: "👁 Watchlist", value: stats.watchlistCount, color: "#3fb950", bg: "#0d2818" });

    const w = `${Math.floor(100 / chips.length)}%`;
    const chipsHTML = `
      <table width="100%" cellpadding="0" cellspacing="6" style="border-collapse:separate;margin-bottom:4px">
        <tr>
          ${chips.map(c => `
            <td width="${w}" align="center" style="background:${c.bg};border-radius:6px;padding:10px 6px">
              <div style="font-size:22px;font-weight:700;color:${c.color};line-height:1.2">${c.value}</div>
              <div style="font-size:11px;color:#8b949e;margin-top:3px">${c.label}</div>
            </td>`).join("")}
        </tr>
      </table>`;

    const lines = [];
    if (stats.topCVEs.length > 0) {
      const badges = stats.topCVEs.map(c =>
        `<span style="display:inline-block;background:#1a1a2e;color:#c4b5fd;font-family:monospace;font-size:11px;padding:2px 6px;border-radius:3px;margin:2px 3px 2px 0">${c}</span>`
      ).join("");
      lines.push(`<p style="margin:8px 0 0;font-size:11px;color:#8b949e">
        <strong style="text-transform:uppercase;letter-spacing:.5px">🔍 Top CVE</strong>&nbsp; ${badges}</p>`);
    }
    if (stats.topVendors.length > 0) {
      const vList = stats.topVendors.map(v =>
        `<strong style="color:#e6edf3">${v.name}</strong>&nbsp;<span style="color:#8b949e">(${v.count})</span>`
      ).join(" · ");
      lines.push(`<p style="margin:8px 0 0;font-size:11px;color:#8b949e">
        <strong style="text-transform:uppercase;letter-spacing:.5px">🏢 Vendors</strong>&nbsp; ${vList}</p>`);
    }
    if (stats.watchlistTerms.length > 0) {
      const wBadges = stats.watchlistTerms.map(w =>
        `<span style="display:inline-block;background:#0d2818;color:#3fb950;font-size:11px;padding:2px 6px;border-radius:3px;margin:2px 3px 2px 0">${w.term}&nbsp;(${w.count})</span>`
      ).join("");
      lines.push(`<p style="margin:8px 0 0;font-size:11px;color:#8b949e">
        <strong style="text-transform:uppercase;letter-spacing:.5px">👁 Watchlist</strong>&nbsp; ${wBadges}</p>`);
    }

    return `<div style="margin-bottom:20px">${chipsHTML}${lines.join("")}</div>`;
  }

  /** Version texte brut des statistiques enrichies. */
  function _statsBlockText(stats) {
    let t = "STATISTIQUES DU DIGEST\n" + "-".repeat(30) + "\n";
    t += `Total : ${stats.total} · HIGH : ${stats.highCount} · KEV : ${stats.kevCount}`;
    if (stats.watchlistCount > 0) t += ` · Watchlist : ${stats.watchlistCount} hits`;
    t += "\n";
    if (stats.topCVEs.length > 0)     t += `Top CVE    : ${stats.topCVEs.join(", ")}\n`;
    if (stats.topVendors.length > 0)   t += `Vendors    : ${stats.topVendors.map(v => `${v.name} (${v.count})`).join(", ")}\n`;
    if (stats.watchlistTerms.length > 0) t += `Watchlist  : ${stats.watchlistTerms.map(w => `${w.term} (${w.count})`).join(", ")}\n`;
    return t + "\n";
  }

  /**
   * Génère une phrase expliquant pourquoi l'article est important.
   */
  function _whyImportant(a) {
    // Prédicats conçus pour s'accorder avec "Cette vulnérabilité est …"
    const r = [];
    if (a.isKEV)
      r.push("actively exploited in the wild (CISA KEV)");
    if (a.epssScore != null && a.epssScore >= 0.70)
      r.push(`with very high exploitation probability (EPSS ${Math.round(a.epssScore * 100)}%)`);
    else if (a.epssScore != null && a.epssScore >= 0.40)
      r.push(`with moderate exploitation risk (EPSS ${Math.round(a.epssScore * 100)}%)`);
    if (a.score != null && a.score >= 90)      r.push("maximum severity");
    else if (a.score != null && a.score >= 80) r.push("very high severity");
    if (a.isTrending)     r.push("en forte circulation sur les plateformes de threat intel");
    if (a.cveIds?.length) r.push(`referenced as ${a.cveIds.slice(0, 2).join(", ")}`);
    if (r.length === 0)
      return a.priorityLevel === "critical_now"
        ? "Classified as critical priority by multi-signal analysis."
        : a.criticality === "high"
          ? "Classified as high severity by automated analysis."
          : "Identified as potential threat.";
    return "This vulnerability is " + r.join(", ") + ".";
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
    if (a.isKEV)
      pts.push("Apply patches urgently (CISA deadline: 3 weeks)");
    if (a.epssScore != null && a.epssScore >= 0.70)
      pts.push("Monitor exploitation logs on exposed systems");
    // "Vérifier l'exposition" seulement si aucun point plus spécifique n'a été ajouté
    if (pts.length === 0 && (a.priorityLevel === "critical_now" || a.criticality === "high"))
      pts.push("Check the exposure of your affected assets");
    if (a.isTrending)
      pts.push("Consult IoCs published by the threat intelligence community");
    if (a.cveIds?.length)
      pts.push(`Verify patch status for ${a.cveIds[0]}`);
    if (pts.length === 0)
      pts.push("Monitor developments and apply vendor recommendations");
    return pts;
  }

  // ── Formatage HTML du briefing ────────────────────────────────────────────

  /**
   * Génère l'email HTML complet du briefing matinal.
   * `top` = 3–5 articles prioritaires détaillés.
   * `rest` = autres alertes en format compact.
   */
  function _formatBriefingHTML(top, rest, label, stats = null) {
    const now = new Date().toLocaleDateString("en-US",
      { weekday: "long", year: "numeric", month: "long", day: "numeric" });
    const total    = top.length + rest.length;
    const kevCount = [...top, ...rest].filter(a => a.isKEV).length;
    const highCount= [...top, ...rest].filter(a =>
      a.priorityLevel ? a.priorityLevel === "critical_now" : a.criticality === "high"
    ).length;

    // Résumé exécutif
    let exec = `${total} threat(s) detected during this period`;
    if (kevCount > 0) exec += `, including ${kevCount} KEV vulnerability(ies) actively exploited`;
    if (highCount > 0) exec += `. ${highCount} critical alert(s) require your attention`;
    exec += ".";

    // Cartes top alertes
    const topHTML = top.map(a => {
      const { color, badge } = _alertBadge(a);
      const meta  = [
        a.isKEV             ? "🚨 KEV ACTIVE"                                     : "",
        a.epssScore != null ? `EPSS ${Math.round(a.epssScore * 100)} %`          : "",
        a.score     != null ? `Score ${a.score}`                                  : ""
      ].filter(Boolean).join(" · ");
      const pts  = _watchpoints(a).map(p =>
        `<li style="margin:4px 0;color:#e6edf3">${p}</li>`).join("");

      return `
        <div style="border:1px solid ${color};border-radius:8px;padding:16px;margin-bottom:16px;background:#161b22">
          <div style="margin-bottom:8px;overflow:hidden">
            <span style="color:#8b949e;font-size:12px;float:right">${_escHtml(a.sourceName || "")}</span>
            <span style="color:${color};font-weight:700;font-size:13px">${badge}</span>
            ${meta ? `<span style="color:#8b949e;font-size:12px"> · ${meta}</span>` : ""}
          </div>
          <h3 style="margin:0 0 8px;font-size:15px;line-height:1.4;word-break:break-word">
            <a href="${_safeHref(a.link)}" style="color:#58a6ff;text-decoration:none">${_escHtml(a.title || "(sans titre)")}</a>
          </h3>
          <p style="margin:0 0 8px;font-size:12px;color:#8b949e">🏷️ ${_affectedProducts(a)}</p>
          <p style="margin:0 0 12px;font-size:13px;color:#cdd9e5;background:#0d1117;
                    padding:10px;border-radius:4px;border-left:3px solid ${color}">
            📌 <strong>Why it matters:</strong> ${_whyImportant(a)}
          </p>
          <div style="font-size:12px">
            <p style="margin:0 0 6px;color:#8b949e;font-weight:600;text-transform:uppercase;
                      letter-spacing:.5px">⚡ Immediate watchpoints</p>
            <ul style="margin:0;padding-left:16px">${pts}</ul>
          </div>
        </div>`;
    }).join("");

    // Tableau compact des autres alertes
    const restHTML = rest.length === 0 ? "" : `
      <h3 style="color:#8b949e;font-size:13px;font-weight:600;text-transform:uppercase;
                 letter-spacing:.5px;margin:24px 0 12px">📋 Other alerts (${rest.length})</h3>
      <table style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace">
        <tbody>
          ${rest.map(a => {
            const { color: c, badge: bFull } = _alertBadge(a);
            return `<tr>
              <td style="padding:5px 8px;border-bottom:1px solid #21262d;color:${c};white-space:nowrap">${_escHtml(bFull)}</td>
              <td style="padding:5px 8px;border-bottom:1px solid #21262d;color:#8b949e">${_escHtml(a.sourceName || "")}</td>
              <td style="padding:5px 8px;border-bottom:1px solid #21262d;word-break:break-word">
                <a href="${_safeHref(a.link)}" style="color:#58a6ff;text-decoration:none">${_escHtml(a.title || "(sans titre)")}</a>
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
          <h1 style="margin:0 0 4px;font-size:20px;color:#e6edf3">☀️ Cybersecurity Briefing — ${now}</h1>
          <p style="margin:0;color:#8b949e;font-size:13px">CyberVeille Pro · Digest ${label}</p>
        </div>
        <!-- Executive summary -->
        <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;margin-bottom:24px">
          <p style="margin:0 0 4px;color:#8b949e;font-size:11px;font-weight:600;
                    text-transform:uppercase;letter-spacing:.5px">EXECUTIVE SUMMARY</p>
          <p style="margin:0;font-size:14px;color:#cdd9e5">${exec}</p>
        </div>
        <!-- Statistiques enrichies -->
        ${stats ? _statsBlockHTML(stats) : ""}
        <!-- Top alertes -->
        <h2 style="font-size:15px;font-weight:700;color:#e6edf3;margin:0 0 16px;
                   text-transform:uppercase;letter-spacing:.5px">🎯 Top ${top.length} Priority Alerts</h2>
        ${topHTML}
        <!-- Autres alertes -->
        ${restHTML}
        <!-- Pied de page -->
        <div style="border-top:1px solid #30363d;margin-top:24px;padding-top:16px;text-align:center">
          <p style="margin:0;color:#8b949e;font-size:11px">
            CyberVeille Pro · ${new Date().toLocaleString("en-US")} ·
            <a href="https://technocspace.com" style="color:#58a6ff">Open app</a>
          </p>
        </div>
      </div>`;
  }

  // ── Formatage texte brut du briefing ─────────────────────────────────────

  /** Version texte brut du briefing (fallback clients email sans HTML). */
  function _formatBriefingText(top, rest, label, stats = null) {
    const now    = new Date().toLocaleDateString("en-US",
      { weekday: "long", year: "numeric", month: "long", day: "numeric" });
    const total    = top.length + rest.length;
    const kevCount = [...top, ...rest].filter(a => a.isKEV).length;
    const sep60  = "=".repeat(60);

    let t = `☀️ CYBERSECURITY BRIEFING — ${now.toUpperCase()}\n`;
    t += `CyberVeille Pro · Digest ${label}\n${sep60}\n\n`;

    t += "EXECUTIVE SUMMARY\n" + "-".repeat(30) + "\n";
    t += `${total} threat(s) detected`;
    if (kevCount > 0) t += `, including ${kevCount} KEV actively exploited`;
    t += ".\n\n";

    if (stats) t += _statsBlockText(stats);

    t += `🎯 TOP ${top.length} PRIORITY ALERTS\n${sep60}\n\n`;
    top.forEach((a, i) => {
      const { badge } = _alertBadge(a);
      const kev   = a.isKEV ? " | 🚨 KEV ACTIF" : "";
      const epss  = a.epssScore !== null
        ? ` | EPSS ${Math.round(a.epssScore * 100)} %` : "";
      t += `${i + 1}. ${badge}${kev}${epss}\n`;
      t += `   ${a.title || "(sans titre)"}\n`;
      t += `   Source : ${a.sourceName || "?"} — ${_affectedProducts(a)}\n`;
      t += `   Link   : ${a.link || ""}\n`;
      t += `   ► ${_whyImportant(a)}\n`;
      _watchpoints(a).forEach(p => { t += `   • ${p}\n`; });
      t += "\n";
    });

    if (rest.length > 0) {
      t += `📋 OTHER ALERTS (${rest.length})\n${"-".repeat(60)}\n`;
      rest.forEach(a => {
        const { badge: b } = _alertBadge(a);
        t += `${b} [${a.sourceName || "?"}] ${a.title || "(untitled)"}\n   ${a.link || ""}\n`;
      });
      t += "\n";
    }

    t += `${sep60}\nGenerated by CyberVeille Pro on ${new Date().toLocaleString("en-US")}\n`;
    return t;
  }

  // ── Envoi digest (toute la file, puis nettoyage) ──────────────────────────

  async function _sendDigest(settings, isManual = false) {
    const queue = _loadDigest();
    if (queue.length === 0) {
      console.log("[Alerts] Digest dû mais file vide — rien à envoyer");
      return;
    }

    const label   = settings.mode === "weekly_digest" ? "weekly" : "daily";
    const top     = _selectTopArticles(queue, 5);
    const topIds  = new Set(top.map(a => a.id));
    const rest    = queue.filter(a => !topIds.has(a.id));
    const total   = top.length + rest.length;
    const allArts = [...top, ...rest];
    const reason  = isManual ? "manual_digest_flush" : settings.mode;
    const stats   = _buildDigestStats(allArts);

    const subject = `☀️ ${label.charAt(0).toUpperCase() + label.slice(1)} Cybersecurity Briefing — ${top.length} priority alerts · ${new Date().toLocaleDateString("en-US")}`;
    const html    = _formatBriefingHTML(top, rest, label, stats);
    const text    = _formatBriefingText(top, rest, label, stats);

    try {
      await _dispatch(allArts, { ...settings }, subject, html, text);
      // Nettoyage : marquer tous comme alertés, MAJ lastDigestAt
      _clearDigest();
      markAsAlerted(queue.map(a => a.id));
      saveSettings({ ...settings, lastDigestAt: Date.now(), lastSentAt: Date.now() });
      _markBatchSent(allArts, reason, settings.channel);
      appendAlertHistory(_makeHistoryEntry(allArts, settings, reason, true, "", { digest: true, manualFlush: isManual }));
      // Toast uniquement si appelé automatiquement — flushDigest() gère son propre message
      if (window.UI && !isManual) UI.showToast(`☀️ ${label} briefing sent — ${total} alert(s)`, "success");
      console.log("[Alerts] Briefing %s envoyé (%d articles, %d en top)", label, total, top.length);
    } catch (err) {
      appendAlertHistory(_makeHistoryEntry(allArts, settings, reason, false, err.message, { digest: true, manualFlush: isManual }));
      throw err; // re-throw → caller affiche le toast d'erreur
    }
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
    if (!settings.webhookUrl) throw new Error("Webhook URL not configured");

    // Métriques d'enveloppe
    const _maxPrioOrder = { critical_now: 4, investigate: 3, watch: 2, low: 1 };
    const _topPrio = articles.reduce((best, a) => {
      const rank = _maxPrioOrder[a.priorityLevel] || 0;
      return rank > (_maxPrioOrder[best] || 0) ? a.priorityLevel : best;
    }, null);

    const payload = {
      event:             subjectOverride ? "cyberveille_digest" : "cyberveille_alert",
      timestamp:         new Date().toISOString(),
      count:             articles.length,
      threshold:         settings.threshold,
      // Métriques d'enveloppe enrichies
      maxPriorityLevel:  _topPrio,
      maxPriorityScore:  Math.max(...articles.map(a => a.priorityScore || 0), 0) || null,
      kevCount:          articles.filter(a => a.isKEV).length,
      watchlistCount:    articles.filter(a => a.watchlistMatches?.length > 0).length,
      articles:   articles.map(a => ({
        id:            a.id,
        title:         a.title,
        source:        a.sourceName,
        criticality:   a.criticality,
        priorityLevel: a.priorityLevel || null,
        priorityScore: a.priorityScore  || null,
        link:          a.link,
        pubDate:       a.pubDate instanceof Date ? a.pubDate.toISOString() : String(a.pubDate || ""),
        description:   a.description,
        // Signaux enrichis
        summary:       (a.priorityReasons || []).slice(0, 2).join(" · ") || a.description?.slice(0, 120) || null,
        topSignals: {
          kev:          a.isKEV || false,
          epss:         a.epssScore != null ? parseFloat((a.epssScore * 100).toFixed(1)) : null,
          watchlistHit: (a.watchlistMatches?.length || 0) > 0,
          iocCount:     a.iocCount || 0,
          trending:     a.isTrending || false,
          cves:         (a.cves || a.cveIds || []).slice(0, 5)
        },
        // Recommandations clés (si Recommender disponible)
        keyRecommendations: (typeof Recommender !== "undefined"
          ? (Recommender.getRecommendations?.(a) || []).slice(0, 3).map(r => r.action || r.label || r)
          : []).filter(Boolean)
      })),
      // Compatibilité Slack / Teams
      text:       `🛡️ *CyberVeille Pro* — ${articles.length} new alert(s)` +
                  (_topPrio ? ` · Max priority: ${_topPrio}` : '') + "\n" +
                  articles.slice(0, 3).map(a =>
                    `>*${_alertBadge(a).badge} ${a.title}*\n>${a.link}`
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
      throw new Error("Incomplete EmailJS configuration (service/template/public key)");
    }

    // Chargement dynamique du SDK EmailJS si absent
    if (!window.emailjs) {
      await loadScript("https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js");
      window.emailjs.init({ publicKey: emailjsPublicKey });
    }

    await window.emailjs.send(emailjsService, emailjsTemplate, {
      to_email:      recipientEmail,
      subject:       subjectOverride || `🛡️ CyberVeille Pro — ${articles.length} high-priority alert(s)`,
      message_text:  textOverride    || formatAlertBody(articles),
      message_html:  htmlOverride    || formatAlertHTML(articles),
      alert_count:   articles.length,
      sent_at: new Date().toLocaleString("en-US")
    });

    console.log("[Alerts] Email EmailJS envoyé (%d articles)", articles.length);
  }

  // ── Canal 3 : Resend ──────────────────────────────────────────────────────
  // Sur Vercel : POST /api/send-alert (clé API sécurisée côté serveur ✅)
  // Expéditeur sandbox Resend (vérifié par Resend, utilisable sans domaine propre)
  const RESEND_SANDBOX_FROM = "CyberVeille Pro <onboarding@resend.dev>";

  /**
   * Retourne l'expéditeur Resend résolu.
   * - Si resendFrom est renseigné → utiliser tel quel
   * - Sinon → fallback sandbox identique en local ET en mode API
   */
  function _resolvedResendFrom(resendFrom) {
    return (resendFrom && resendFrom.trim()) ? resendFrom.trim() : RESEND_SANDBOX_FROM;
  }

  // En local   : appel direct Resend API (clé dans le modal — seulement pour dev)

  async function sendResend(articles, settings, subjectOverride, htmlOverride, textOverride) {
    const { resendFrom, recipientEmail } = settings;
    if (!recipientEmail) throw new Error("Recipient email missing");

    const subject = subjectOverride || `🛡️ CyberVeille Pro — ${articles.length} high-severity alert(s)`;
    const html    = htmlOverride    || formatAlertHTML(articles);
    const text    = textOverride    || formatAlertBody(articles);

    if (CONFIG.USE_API) {
      // ── Vercel : clé API lue depuis process.env côté serveur ──────────────
      const headers = { "Content-Type": "application/json" };
      if (settings.alertToken) headers["X-Alert-Token"] = settings.alertToken;
      const res = await fetch("/api/send-alert", {
        method:  "POST",
        headers,
        body:    JSON.stringify({
          channel:      "resend",
          to:           recipientEmail,
          fromOverride: _resolvedResendFrom(resendFrom),
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
      if (!resendApiKey) throw new Error("Resend API key missing (local mode)");
      const res = await fetch("https://api.resend.com/emails", {
        method:  "POST",
        headers: { "Authorization": `Bearer ${resendApiKey}`, "Content-Type": "application/json" },
        body:    JSON.stringify({
          from:    _resolvedResendFrom(resendFrom),
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

    const subject = subjectOverride || `🛡️ CyberVeille Pro — ${articles.length} high-severity alert(s)`;
    const html    = htmlOverride    || formatAlertHTML(articles);
    const text    = textOverride    || formatAlertBody(articles);

    if (CONFIG.USE_API) {
      // ── Vercel : clé API lue depuis process.env côté serveur ──────────────
      const headers = { "Content-Type": "application/json" };
      if (settings.alertToken) headers["X-Alert-Token"] = settings.alertToken;
      const res = await fetch("/api/send-alert", {
        method:  "POST",
        headers,
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
      if (!sendgridApiKey) throw new Error("SendGrid API key missing (local mode)");
      if (!sendgridFrom)   throw new Error("SendGrid sender address missing");
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
      subjectOverride || `🛡️ CyberVeille Pro — ${articles.length} cybersecurity alert(s)`
    );
    const body = encodeURIComponent(
      textOverride || (
        `CyberVeille Pro — High severity alerts\n` +
        `Generated on ${new Date().toLocaleString("en-US")}\n\n` +
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
      // Étape 3 — anti-doublon immediate
      const toSend = candidates.filter(a => !wasRecentlySent(a, DEDUPE_CONFIG.windowMsImmediate));
      if (toSend.length === 0) { console.log("[Alerts] Immédiat : tous les candidats déjà envoyés récemment (dedupe)"); return; }
      if (toSend.length < candidates.length) console.log(`[Alerts] Dedupe immediate : ${candidates.length - toSend.length} article(s) filtrés`);
      await _sendImmediate(toSend.slice(0, settings.batchSize), settings, "immediate");
      return;
    }

    // ── Mode : urgent_only ──────────────────────────────────────────────────
    if (mode === "urgent_only") {
      const urgent = candidates.filter(_isUrgent);
      if (urgent.length === 0) { console.log("[Alerts] Aucun article urgent (KEV/EPSS/score)"); return; }
      // Étape 4 — anti-doublon urgent_only
      const toSendUrgent = urgent.filter(a => !wasRecentlySent(a, DEDUPE_CONFIG.windowMsUrgent));
      if (toSendUrgent.length === 0) { console.log("[Alerts] Urgent : tous déjà envoyés récemment (dedupe)"); return; }
      if (toSendUrgent.length < urgent.length) console.log(`[Alerts] Dedupe urgent : ${urgent.length - toSendUrgent.length} article(s) filtrés`);
      await _sendImmediate(toSendUrgent.slice(0, settings.batchSize), settings, _urgentReason(toSendUrgent));
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
          if (window.UI) UI.showToast(`⚠️ Digest failed: ${err.message}`, "error");
        }
      }
    }
  }

  /** Envoi immédiat (modes immediate et urgent_only). */
  async function _sendImmediate(batch, settings, reason) {
    console.log(`[Alerts] ${batch.length} article(s) → ${settings.channel}`);
    try {
      await _dispatch(batch, settings);
      markAsAlerted(batch.map(a => a.id));
      saveSettings({ ...settings, lastSentAt: Date.now() });
      _markBatchSent(batch, reason || settings.mode, settings.channel);
      appendAlertHistory(_makeHistoryEntry(batch, settings, reason || settings.mode, true, ""));
      if (window.UI) {
        UI.showToast(`📧 Alert sent — ${batch.length} article(s) via ${settings.channel}`, "success");
      }
    } catch (err) {
      appendAlertHistory(_makeHistoryEntry(batch, settings, reason || settings.mode, false, err.message));
      console.error("[Alerts] Échec envoi:", err.message);
      if (window.UI) UI.showToast(`⚠️ Alert failed: ${err.message}`, "error");
    }
  }

  /** Force l'envoi immédiat du digest (bouton manuel dans l'UI). */
  async function flushDigest() {
    const settings = loadSettings();
    if (!settings.enabled) { UI.showToast("Alerts disabled", "warning"); return; }
    const queue = _loadDigest();
    if (queue.length === 0) { UI.showToast("Digest queue empty", "info"); return; }
    try {
      await _sendDigest({ ...settings, lastDigestAt: 0 }, true); // isManual = true
      UI.showToast(`📋 Digest forced — ${queue.length} article(s) sent`, "success");
    } catch (err) {
      UI.showToast(`⚠️ Digest failed: ${err.message}`, "error");
    }
  }

  // ── API publique ──────────────────────────────────────────────────────────

  return {
    processNewArticles,
    loadSettings,
    saveSettings,
    flushDigest,
    getDigestCount:    () => _loadDigest().length,
    loadAlertHistory,
    clearAlertHistory,
    DEFAULTS
  };
})();
