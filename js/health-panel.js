// health-panel.js — Panneau 🩺 Santé / Ops (état opérationnel du moteur serveur)
//
// Appelle GET /api/status (endpoint public, lecture seule).
// Affiche l'état du dernier run, la config email, le cron et le fuseau Montréal.
//
// Pattern identique à BriefingPanel / StatsPanel : toggle show/hide + lazy load.

const HealthPanel = (() => {

  let _cache   = null;   // dernière réponse /api/status
  let _loading = false;

  // ── Visibilité ──────────────────────────────────────────────────────────────
  function _isVisible() {
    return document.getElementById("health-panel")?.style.display !== "none";
  }

  // ── Toggle ──────────────────────────────────────────────────────────────────
  async function toggle() {
    const panel = document.getElementById("health-panel");
    const btn   = document.getElementById("btn-health");
    if (!panel) return;

    const nowVisible = !_isVisible();
    panel.style.display = nowVisible ? "block" : "none";
    btn?.classList.toggle("active", nowVisible);

    if (nowVisible && !_cache && !_loading) await _load();
  }

  // ── Refresh forcé ───────────────────────────────────────────────────────────
  async function refresh() {
    _cache = null;
    if (_isVisible()) await _load();
  }

  function init() { /* lazy — rien à faire */ }

  // ── Fetch /api/status ───────────────────────────────────────────────────────
  async function _load() {
    if (_loading) return;
    _loading = true;
    _renderLoading();
    try {
      const res = await fetch("/api/status", { signal: AbortSignal.timeout(10_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      _cache = await res.json();
      _render(_cache);
    } catch (e) {
      _renderError(e.message || "Unknown error");
    } finally {
      _loading = false;
    }
  }

  // ── Helpers d'affichage ─────────────────────────────────────────────────────

  function _renderLoading() {
    const el = document.getElementById("health-list");
    if (el) el.innerHTML = '<div class="hp-state hp-loading">⏳ Loading…</div>';
  }

  function _renderError(msg) {
    const el = document.getElementById("health-list");
    if (el) el.innerHTML = `<div class="hp-state hp-error">❌ ${msg}</div>`;
  }

  /** Formate un timestamp ISO en date/heure locale FR, ou "—" si null. */
  function _ts(iso) {
    if (!iso) return '<span class="hp-null">—</span>';
    const d = new Date(iso);
    return `<span class="hp-ts" title="${iso}">${d.toLocaleDateString("en-US", { day: "2-digit", month: "2-digit" })} ${d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>`;
  }

  /** Convertit une valeur bool/null en pill colorée. */
  function _bool(val, labelOk, labelNo) {
    return val
      ? `<span class="hp-pill hp-ok">${labelOk}</span>`
      : `<span class="hp-pill hp-no">${labelNo}</span>`;
  }

  /** Badge de résultat du dernier run (libellés humains). */
  function _resultBadge(result) {
    if (!result) return '<span class="hp-pill hp-null">No run</span>';
    const map = {
      sent:       '<span class="hp-pill hp-ok">✅ Sent</span>',
      failed:     '<span class="hp-pill hp-err">❌ Send failed</span>',
      noArticles: '<span class="hp-pill hp-warn">⚠️ No articles</span>'
    };
    return map[result] || `<span class="hp-pill hp-null">${result}</span>`;
  }

  /** Calcule l'heure du prochain run attendu à partir de la config digest. */
  function _nextRunLabel(dg) {
    if (!dg || !dg.hour) return "—";
    const parts  = String(dg.hour).split(":");
    const targetH = parseInt(parts[0], 10);
    const targetM = parseInt(parts[1] || "0", 10);
    if (isNaN(targetH)) return dg.hour;
    const pad      = n => String(n).padStart(2, "0");
    const timeStr  = `${pad(targetH)}h${pad(targetM)}`;
    if (dg.mode === "weekly" && dg.weekday != null) {
      const days = ["dim", "lun", "mar", "mer", "jeu", "ven", "sam"];
      return `${days[dg.weekday] || "?"} at ${timeStr}`;
    }
    if (!dg.nowMontreal) return `at ${timeStr}`;
    const nowTime = dg.nowMontreal.split(" ")[1] || "";
    const [curH, curM] = nowTime.split(":").map(Number);
    const ahead = curH * 60 + curM < targetH * 60 + targetM;
    return `${ahead ? "today" : "tomorrow"} at ${timeStr}`;
  }

  /** Bandeau résumé : état global + impact + prochain run en un coup d'œil. */
  function _renderSummary(d) {
    const lr = d.lastRun  || {};
    const ls = lr.lastStats || {};
    const dg = d.digest   || {};
    const globalOk = d.status === "ok";

    // Impact lisible du dernier run
    const impactMap = {
      sent:       `Briefing sent${ls.topCount != null ? `, ${ls.topCount} article${ls.topCount > 1 ? "s" : ""} selected` : ""}`,
      failed:     "Send failure — check email configuration",
      noArticles: "No article in the last 48h — briefing not sent"
    };
    const impact = lr.lastResult ? (impactMap[lr.lastResult] || lr.lastResult) : "No run recorded";

    // Cause principale (1re alerte ou raison d'échec)
    const cause = Array.isArray(d.warnings) && d.warnings.length
      ? d.warnings[0]
      : (lr.lastResult === "failed" && lr.lastReason) ? lr.lastReason : "";

    const statusLabel = globalOk
      ? '<span class="hp-sum-status hp-sum-ok">✅ System operational</span>'
      : '<span class="hp-sum-status hp-sum-warn">⚠️ Degraded</span>';

    return `
<div class="hp-summary ${globalOk ? "hp-summary-ok" : "hp-summary-warn"}">
  ${statusLabel}
  <div class="hp-sum-grid">
    <span class="hp-sum-lbl">📤 Last result</span><span class="hp-sum-val">${impact}</span>
    <span class="hp-sum-lbl">⏭ Next run</span><span class="hp-sum-val">${_nextRunLabel(dg)}</span>
    ${cause ? `<span class="hp-sum-lbl">⚠️ Alert</span><span class="hp-sum-val hp-sum-cause">${cause}</span>` : ""}
  </div>
</div>`;
  }   // ← fermeture de _renderSummary

  // ── Feeds en erreur ─────────────────────────────────────────────────────────
  function _renderFeedErrors(feedErrors, totalFeeds) {
    const errCount = Array.isArray(feedErrors) ? feedErrors.length : 0;
    const total    = totalFeeds > 0 ? totalFeeds : (errCount || "?");
    const okCount  = typeof totalFeeds === "number" && totalFeeds > 0
      ? totalFeeds - errCount : "—";

    if (errCount === 0) {
      const okLabel = typeof okCount === "number"
        ? `✅ ${okCount}/${total} OK`
        : "✅ All feeds OK";
      return `
<div class="hp-section">
  <div class="hp-section-head">📡 RSS Feeds (last run)</div>
  <div class="hp-row hp-row-ok">${okLabel}</div>
</div>`;
    }
    const rows = feedErrors.map(f => {
      const idTag = f.id && f.name && f.id !== f.name
        ? ` <code class="hp-feed-id">${f.id}</code>`
        : "";
      return `
  <div class="hp-feed-err-row">
    <span class="hp-feed-name">${f.name || f.id}${idTag}</span>
    <span class="hp-feed-err-msg">${f.error || "unknown error"}</span>
  </div>`;
    }).join("");
    const errLabel = typeof okCount === "number"
      ? `${okCount}/${total} OK`
      : `${errCount} with errors`;
    return `
<div class="hp-section">
  <div class="hp-section-head">📡 RSS Feeds (last run) <span class="hp-err-count">${errLabel}</span></div>
  ${rows}
</div>`;
  }

  // ── Historique des runs ──────────────────────────────────────────────────────
  function _renderRunHistory(history) {
    if (!Array.isArray(history) || history.length === 0) {
      return `
<div class="hp-section">
  <div class="hp-section-head">📋 Run history</div>
  <div class="hp-row hp-null-row">No history available (KV required)</div>
</div>`;
    }

    const rows = history.map((r, i) => {
      const isLast  = i === 0;
      const badge   = r.lastResult === "sent"
        ? '<span class="hp-pill hp-ok hp-pill-sm">✅ Sent</span>'
        : r.lastResult === "failed"
          ? '<span class="hp-pill hp-err hp-pill-sm">❌ Failed</span>'
          : '<span class="hp-pill hp-warn hp-pill-sm">⚠️ No art.</span>';

      const d   = new Date(r.lastRunAt);
      const ts  = isNaN(d) ? r.lastRunAt : `${d.toLocaleDateString("en-US", { day: "2-digit", month: "2-digit" })} ${d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}`;
      const slotStr = r.slot ? `<br><span class="hp-hist-slot">${r.slot}</span>` : "";
      const ls  = r.lastStats || {};
      const feedsTotal = (ls.feedsOk ?? 0) + (ls.feedsErr ?? 0);
      const feedsStr   = feedsTotal > 0
        ? `<span class="${ls.feedsErr > 0 ? "hp-hist-feeds-warn" : "hp-hist-feeds-ok"}">${ls.feedsOk ?? 0}/${feedsTotal} flux</span>`
        : "";
      const errBadge = ls.feedsErr > 0
        ? `<span class="hp-pill hp-warn hp-pill-sm">${ls.feedsErr} err</span>`
        : "";
      const reason = r.lastReason
        ? `<span class="hp-hist-reason" title="${r.lastReason}">${r.lastReason.slice(0, 60)}${r.lastReason.length > 60 ? "…" : ""}</span>`
        : "";
      return `<tr class="${isLast ? "hp-hist-last" : ""}">
  <td class="hp-hist-ts">${ts}${slotStr}</td>
  <td>${badge}</td>
  <td class="hp-hist-stats">${feedsStr} ${ls.rawArticles ?? "—"} bruts · ${ls.uniqueArticles ?? "—"} uniq · top <strong>${ls.topCount ?? "—"}</strong> ${errBadge}</td>
  <td>${reason}</td>
</tr>`;
    }).join("");

    return `
<div class="hp-section">
  <div class="hp-section-head">📋 Run history (${history.length})</div>
  <table class="hp-hist-table"><tbody>${rows}</tbody></table>
</div>`;
  }

  // ── Historique des briefings envoyés ────────────────────────────────────────
  function _renderBriefingHistory(history) {
    if (!Array.isArray(history) || history.length === 0) {
      return `
<div class="hp-section">
  <div class="hp-section-head">📬 Sent briefings</div>
  <div class="hp-row hp-null-row">No briefing recorded (KV required, or no send yet)</div>
</div>`;
    }

    const MAX_ARTS = 3;

    const cards = history.map((b, i) => {
      const d   = new Date(b.sentAt);
      const ts  = isNaN(d) ? b.sentAt
        : `${d.toLocaleDateString("en-US", { day: "2-digit", month: "2-digit", year: "2-digit" })} ${d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}`;
      const slotBadge = b.slot
        ? `<span class="hp-bh-slot">${b.slot}</span>`
        : "";

      const rawSubj = b.subject ? b.subject.replace(/^[^\x20-\x7E]*/, "").trim() : "";
      const subjDisplay = rawSubj.slice(0, 72) + (rawSubj.length > 72 ? "…" : "");
      const safeSubj    = rawSubj.replace(/"/g, "&quot;");
      const subjEl = rawSubj
        ? `<span class="hp-bh-subj" title="Cliquer pour copier" data-subj="${safeSubj}"
             onclick="navigator.clipboard.writeText(this.dataset.subj).then(()=>{const e=this;e.classList.add('hp-bh-copied');setTimeout(()=>e.classList.remove('hp-bh-copied'),1500)})"
            >${subjDisplay} <span class="hp-bh-copy-icon">⎘</span></span>`
        : `<span class="hp-bh-subj hp-null">—</span>`;

      const arts       = Array.isArray(b.topArticles) ? b.topArticles : [];
      const totalCount = b.topCount ?? arts.length;
      const visible    = arts.slice(0, MAX_ARTS);
      const hiddenCount = Math.max(0, totalCount - visible.length);

      const artRows = visible.map(a => {
        const crit = a.criticality === "high"   ? '🔴'
                   : a.criticality === "medium" ? '🟠' : '🟢';
        const kev  = a.isKEV ? ' <span class="hp-pill hp-err hp-pill-sm">KEV</span>' : "";
        const epss = a.epssScore != null && a.epssScore > 0
          ? ` <span class="hp-pill hp-pill-sm" style="background:#1e3a5f;color:#93c5fd">EPSS ${Math.round(a.epssScore * 100)}%</span>` : "";
        const cve  = a.cveId ? ` <code class="hp-feed-id">${a.cveId}</code>` : "";
        const title = a.link
          ? `<a href="${a.link}" target="_blank" rel="noopener" class="hp-bh-link">${a.title || "—"}</a>`
          : (a.title || "—");
        return `<div class="hp-bh-art">${crit} ${title}${kev}${epss}${cve}</div>`;
      }).join("");

      const moreRow = hiddenCount > 0
        ? `<div class="hp-bh-more">+ ${hiddenCount} autre${hiddenCount > 1 ? "s" : ""}</div>`
        : "";

      const isFirst = i === 0;
      return `
<div class="hp-bh-card${isFirst ? " hp-bh-card-last" : ""}">
  <div class="hp-bh-head">
    <span class="hp-bh-ts">${ts}</span>${slotBadge}
    <span class="hp-bh-count"><strong>${totalCount}</strong> alerte${totalCount > 1 ? "s" : ""}</span>
    ${subjEl}
  </div>
  ${artRows}${moreRow}
</div>`;
    }).join("");

    return `
<div class="hp-section">
  <div class="hp-section-head">📬 Sent briefings (${history.length})</div>
  <div class="hp-bh-list">${cards}</div>
</div>`;
  }

  // ── Rendu principal ─────────────────────────────────────────────────────────
  function _render(d) {
    const el = document.getElementById("health-list");
    if (!el) return;

    const lr  = d.lastRun   || {};
    const ls  = lr.lastStats || {};
    const em  = d.email     || {};
    const cr  = d.cron      || {};
    const dg  = d.digest    || {};
    const dd  = d.dedup     || {};

    // Statut global
    const globalOk   = d.status === "ok";
    const globalBadge = globalOk
      ? '<span class="hp-pill hp-ok">✅ OK</span>'
      : '<span class="hp-pill hp-warn">⚠️ degraded</span>';

    const warnings = Array.isArray(d.warnings) && d.warnings.length
      ? `<ul class="hp-warnings">${d.warnings.map(w => `<li>⚠️ ${w}</li>`).join("")}</ul>`
      : "";

    el.innerHTML = `

<!-- ── Bandeau résumé ────────────────────────────────────────────────── -->
${_renderSummary(d)}

<!-- ── Statut global ─────────────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">🩺 Global status</div>
  <div class="hp-row"><span class="hp-lbl">Status</span><span>${globalBadge}</span></div>
  <div class="hp-row"><span class="hp-lbl">Checked on</span><span>${_ts(d.timestamp)}</span></div>
  ${warnings}
</div>

<!-- ── Dernier run ────────────────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">🕐 Last run</div>
  <div class="hp-row"><span class="hp-lbl">Executed on</span><span>${_ts(lr.lastRunAt)}</span></div>
  <div class="hp-row"><span class="hp-lbl">Slot (Montreal)</span><span class="hp-code">${lr.slot || "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Result</span><span>${_resultBadge(lr.lastResult)}</span></div>
  ${lr.lastReason ? `<div class="hp-row"><span class="hp-lbl">Reason</span><span class="hp-reason-txt">${lr.lastReason}</span></div>` : ""}
  <div class="hp-row"><span class="hp-lbl">Last sent</span><span>${_ts(lr.lastSentAt)}</span></div>
  <div class="hp-row"><span class="hp-lbl">Last success</span><span>${_ts(lr.lastSuccessAt)}</span></div>
  <div class="hp-row"><span class="hp-lbl">Last failure</span><span>${_ts(lr.lastFailureAt)}</span></div>
</div>

<!-- ── Stats du dernier run ───────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">📊 Pipeline stats</div>
  <div class="hp-row"><span class="hp-lbl">Feeds OK / error</span>
    <span><strong>${ls.feedsOk ?? "—"}</strong> ok · <strong class="${ls.feedsErr > 0 ? "hp-val-err" : ""}">${ls.feedsErr ?? "—"}</strong> err</span>
  </div>
  <div class="hp-row"><span class="hp-lbl">Raw articles</span><span>${ls.rawArticles ?? "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Unique articles</span><span>${ls.uniqueArticles ?? "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Top selected</span><span><strong>${ls.topCount ?? "—"}</strong></span></div>
</div>

<!-- ── Cron & planning ─────────────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">⏱ Cron & schedule</div>
  <div class="hp-row"><span class="hp-lbl">Schedule</span><span class="hp-code">${cr.schedule || "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Send time</span><span class="hp-code">${dg.hour || "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Mode</span><span>${dg.mode || "—"}</span></div>
  ${dg.weekday != null ? `<div class="hp-row"><span class="hp-lbl">Jour (0=dim)</span><span>${dg.weekday}</span></div>` : ""}
  <div class="hp-row"><span class="hp-lbl">Timezone</span><span class="hp-code">${dg.tz || "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Montreal time</span><span class="hp-code">${dg.nowMontreal || "—"}</span></div>
</div>

<!-- ── Email ──────────────────────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">✉️ Email</div>
  <div class="hp-row"><span class="hp-lbl">Canal</span><span class="hp-code">${em.channel || "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Recipient</span><span>${_bool(em.recipient, "configured", "missing")}</span></div>
  <div class="hp-row"><span class="hp-lbl">CRON_SECRET</span><span>${_bool(em.cronSecret, "configured", "absent")}</span></div>
  ${em.channel === "resend"    ? `
  <div class="hp-row"><span class="hp-lbl">RESEND_API_KEY</span><span>${_bool(em.resend,     "configured", "missing")}</span></div>
  <div class="hp-row"><span class="hp-lbl">RESEND_FROM</span><span>${_bool(em.resendFrom, "configured", "missing")}</span></div>` : ""}
  ${em.channel === "sendgrid"  ? `
  <div class="hp-row"><span class="hp-lbl">SENDGRID_API_KEY</span><span>${_bool(em.sendgrid,     "configured", "missing")}</span></div>
  <div class="hp-row"><span class="hp-lbl">SENDGRID_FROM</span><span>${_bool(em.sendgridFrom, "configured", "missing")}</span></div>` : ""}
</div>

<!-- ── Déduplication KV ───────────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">🔁 Déduplication KV</div>
  <div class="hp-row"><span class="hp-lbl">Vercel KV</span><span>${_bool(dd.kvAvailable, "available", "not configured")}</span></div>
</div>

<!-- ── Feeds en erreur ────────────────────────────────────────────────── -->
${_renderFeedErrors(d.feedErrors, d.feeds?.count)}

<!-- ── Historique des runs ────────────────────────────────────────────── -->
${_renderRunHistory(d.runHistory)}

<!-- ── Historique des briefings envoyés ──────────────────────────────── -->
${_renderBriefingHistory(d.briefingHistory)}`;
  }

  return { init, toggle, refresh };
})();
