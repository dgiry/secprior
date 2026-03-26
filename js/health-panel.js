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
      _renderError(e.message || "Erreur inconnue");
    } finally {
      _loading = false;
    }
  }

  // ── Helpers d'affichage ─────────────────────────────────────────────────────

  function _renderLoading() {
    const el = document.getElementById("health-list");
    if (el) el.innerHTML = '<div class="hp-state hp-loading">⏳ Chargement…</div>';
  }

  function _renderError(msg) {
    const el = document.getElementById("health-list");
    if (el) el.innerHTML = `<div class="hp-state hp-error">❌ ${msg}</div>`;
  }

  /** Formate un timestamp ISO en date/heure locale FR, ou "—" si null. */
  function _ts(iso) {
    if (!iso) return '<span class="hp-null">—</span>';
    const d = new Date(iso);
    return `<span class="hp-ts" title="${iso}">${d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" })} ${d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>`;
  }

  /** Convertit une valeur bool/null en pill colorée. */
  function _bool(val, labelOk, labelNo) {
    return val
      ? `<span class="hp-pill hp-ok">${labelOk}</span>`
      : `<span class="hp-pill hp-no">${labelNo}</span>`;
  }

  /** Badge de résultat du dernier run. */
  function _resultBadge(result) {
    if (!result) return '<span class="hp-pill hp-null">aucun run</span>';
    const map = {
      sent:       '<span class="hp-pill hp-ok">✅ sent</span>',
      failed:     '<span class="hp-pill hp-err">❌ failed</span>',
      noArticles: '<span class="hp-pill hp-warn">⚠️ noArticles</span>'
    };
    return map[result] || `<span class="hp-pill hp-null">${result}</span>`;
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

<!-- ── Statut global ─────────────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">🩺 État global</div>
  <div class="hp-row"><span class="hp-lbl">Statut</span><span>${globalBadge}</span></div>
  <div class="hp-row"><span class="hp-lbl">Horodatage</span><span>${_ts(d.timestamp)}</span></div>
  ${warnings}
</div>

<!-- ── Dernier run ────────────────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">🕐 Dernier run</div>
  <div class="hp-row"><span class="hp-lbl">lastRunAt</span><span>${_ts(lr.lastRunAt)}</span></div>
  <div class="hp-row"><span class="hp-lbl">slot (Montréal)</span><span class="hp-code">${lr.slot || "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">lastResult</span><span>${_resultBadge(lr.lastResult)}</span></div>
  ${lr.lastReason ? `<div class="hp-row"><span class="hp-lbl">lastReason</span><span class="hp-reason-txt">${lr.lastReason}</span></div>` : ""}
  <div class="hp-row"><span class="hp-lbl">lastSentAt</span><span>${_ts(lr.lastSentAt)}</span></div>
  <div class="hp-row"><span class="hp-lbl">lastSuccessAt</span><span>${_ts(lr.lastSuccessAt)}</span></div>
  <div class="hp-row"><span class="hp-lbl">lastFailureAt</span><span>${_ts(lr.lastFailureAt)}</span></div>
</div>

<!-- ── Stats du dernier run ───────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">📊 Stats pipeline</div>
  <div class="hp-row"><span class="hp-lbl">Flux OK / erreur</span>
    <span><strong>${ls.feedsOk ?? "—"}</strong> ok · <strong class="${ls.feedsErr > 0 ? "hp-val-err" : ""}">${ls.feedsErr ?? "—"}</strong> err</span>
  </div>
  <div class="hp-row"><span class="hp-lbl">Articles bruts</span><span>${ls.rawArticles ?? "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Articles uniques</span><span>${ls.uniqueArticles ?? "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Top sélectionnés</span><span><strong>${ls.topCount ?? "—"}</strong></span></div>
</div>

<!-- ── Cron & planning ─────────────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">⏱ Cron & planning</div>
  <div class="hp-row"><span class="hp-lbl">Schedule</span><span class="hp-code">${cr.schedule || "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Heure d'envoi</span><span class="hp-code">${dg.hour || "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Mode</span><span>${dg.mode || "—"}</span></div>
  ${dg.weekday != null ? `<div class="hp-row"><span class="hp-lbl">Jour (0=dim)</span><span>${dg.weekday}</span></div>` : ""}
  <div class="hp-row"><span class="hp-lbl">Timezone</span><span class="hp-code">${dg.tz || "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Heure Montréal</span><span class="hp-code">${dg.nowMontreal || "—"}</span></div>
</div>

<!-- ── Email ──────────────────────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">✉️ Email</div>
  <div class="hp-row"><span class="hp-lbl">Canal</span><span class="hp-code">${em.channel || "—"}</span></div>
  <div class="hp-row"><span class="hp-lbl">Destinataire</span><span>${_bool(em.recipient, "configuré", "manquant")}</span></div>
  <div class="hp-row"><span class="hp-lbl">CRON_SECRET</span><span>${_bool(em.cronSecret, "configuré", "absent")}</span></div>
  ${em.channel === "resend"    ? `
  <div class="hp-row"><span class="hp-lbl">RESEND_API_KEY</span><span>${_bool(em.resend,     "configuré", "manquant")}</span></div>
  <div class="hp-row"><span class="hp-lbl">RESEND_FROM</span><span>${_bool(em.resendFrom, "configuré", "manquant")}</span></div>` : ""}
  ${em.channel === "sendgrid"  ? `
  <div class="hp-row"><span class="hp-lbl">SENDGRID_API_KEY</span><span>${_bool(em.sendgrid,     "configuré", "manquant")}</span></div>
  <div class="hp-row"><span class="hp-lbl">SENDGRID_FROM</span><span>${_bool(em.sendgridFrom, "configuré", "manquant")}</span></div>` : ""}
</div>

<!-- ── Déduplication KV ───────────────────────────────────────────────── -->
<div class="hp-section">
  <div class="hp-section-head">🔁 Déduplication KV</div>
  <div class="hp-row"><span class="hp-lbl">Vercel KV</span><span>${_bool(dd.kvAvailable, "disponible", "non configuré")}</span></div>
</div>`;
  }

  return { init, toggle, refresh };
})();
