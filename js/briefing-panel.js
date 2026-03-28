// briefing-panel.js — Panneau 📰 Briefing (sélection temps réel du moteur digest)
//
// Appelle GET /api/briefing-preview (endpoint public, lecture seule).
// Affiche les top articles tels que le cron les sélectionnerait maintenant,
// avec tous les signaux debug : digestScore, breakdown, topicKey, whyImportant…
//
// Pattern identique à StatsPanel : toggle show/hide + lazy load.

const BriefingPanel = (() => {

  let _cache   = null;   // dernière réponse JSON du serveur
  let _loading = false;  // verrou pour éviter les appels parallèles

  // ── Visibilité ──────────────────────────────────────────────────────────────
  function _isVisible() {
    return document.getElementById("briefing-panel")?.style.display !== "none";
  }

  // ── Toggle ──────────────────────────────────────────────────────────────────
  async function toggle() {
    const panel = document.getElementById("briefing-panel");
    const btn   = document.getElementById("btn-briefing");
    if (!panel) return;

    const nowVisible = !_isVisible();
    panel.style.display = nowVisible ? "block" : "none";
    btn?.classList.toggle("active", nowVisible);

    // Charge les données au premier affichage (lazy)
    if (nowVisible && !_cache && !_loading) {
      await _load();
    }
  }

  // ── Refresh forcé (bouton ↻ dans le panneau) ────────────────────────────────
  async function refresh() {
    _cache = null;
    if (_isVisible()) await _load();
  }

  // ── Init (appelé depuis app.js) ─────────────────────────────────────────────
  function init() {
    // Rien à faire pour l'instant — le panneau est lazy-loaded au premier toggle
  }

  // ── Fetch /api/briefing-preview ─────────────────────────────────────────────
  async function _load() {
    if (_loading) return;
    _loading = true;
    _renderLoading();

    try {
      if (!CONFIG.USE_API) {
        _renderError("Le panneau Briefing est disponible uniquement en mode Vercel (USE_API = true).");
        return;
      }
      const res = await fetch("/api/briefing-preview", {
        signal: AbortSignal.timeout(35_000)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      _cache = await res.json();
      _render(_cache);
    } catch (e) {
      _renderError(e.message || "Unknown error");
    } finally {
      _loading = false;
    }
  }

  // ── Rendu ───────────────────────────────────────────────────────────────────

  function _renderLoading() {
    const el = document.getElementById("briefing-list");
    if (el) el.innerHTML = '<div class="bp-state bp-loading">⏳ Loading briefing…</div>';
    _setMeta("");
  }

  function _renderError(msg) {
    const el = document.getElementById("briefing-list");
    if (el) el.innerHTML = `<div class="bp-state bp-error">❌ ${msg}</div>`;
    _setMeta("");
  }

  function _setMeta(text) {
    const el = document.getElementById("briefing-meta");
    if (el) el.textContent = text;
  }

  function _render(data) {
    const list = document.getElementById("briefing-list");
    if (!list) return;

    // Ligne de méta (heure, stats pipeline)
    if (data.generatedAt || data.stats) {
      const s   = data.stats || {};
      const gen = data.generatedAt
        ? new Date(data.generatedAt).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
        : "";
      const parts = [
        gen && `Generated at ${gen}`,
        s.feeds  && `${s.feeds.ok}/${s.feeds.total} sources`,
        s.articles && `${s.articles.raw} articles bruts`,
        s.enrichment?.kevHits  > 0 && `${s.enrichment.kevHits} KEV`,
        s.enrichment?.epssHits > 0 && `${s.enrichment.epssHits} EPSS`,
        s.elapsedMs != null && `${s.elapsedMs} ms`
      ].filter(Boolean);
      _setMeta(parts.join(" · "));
    }

    if (!data.top?.length) {
      list.innerHTML = '<div class="bp-state bp-empty">No article selected for this briefing.</div>';
      return;
    }

    list.innerHTML =
      data.top.map(a => _cardHTML(a)).join("") +
      (data.rest?.length ? _restHTML(data.rest) : "");
  }

  // ── Carte article top ────────────────────────────────────────────────────────
  function _cardHTML(a) {
    const isHigh = a.criticality === "high";
    const color  = isHigh ? "var(--err)" : "var(--warn)";
    const badge  = isHigh ? "🔴 HIGH"  : "🟠 MEDIUM";

    // Badges signaux
    const signals = [
      a.isKEV         && '<span class="bp-badge bp-kev">🚨 KEV</span>',
      a.epssPercent   && `<span class="bp-badge bp-epss">EPSS ${a.epssPercent}</span>`,
      a.cvssScore != null && `<span class="bp-badge bp-cvss">CVSS ${a.cvssScore}</span>`,
      a.isTrending    && '<span class="bp-badge bp-trend">🔥 Trending</span>',
      a.groupedFrom > 1 && `<span class="bp-badge bp-group">📎 ${a.groupedFrom} sources</span>`
    ].filter(Boolean).join("");

    // Étiquettes de sélection
    const reasons = (a.selectionReasons || [])
      .map(r => `<span class="bp-reason">${r}</span>`).join("");

    // Breakdown digest
    const bd = a.digestBreakdown || {};
    const bdParts = [
      bd.kev      > 0 && `kev+${bd.kev}`,
      bd.epss     > 0 && `epss+${bd.epss}`,
      bd.cvss     > 0 && `cvss+${bd.cvss}`,
      bd.zeroDay  > 0 && `0day+${bd.zeroDay}`,
      bd.watchlist > 0 && `watch+${bd.watchlist}`,
      bd.trending > 0 && `trend+${bd.trending}`,
      bd.sources  > 0 && `src+${bd.sources}`
    ].filter(Boolean).join(" ");

    // Watchpoints
    const wpts = (a.watchpoints || []).map(p => `<li>${p}</li>`).join("");

    // Date de publication
    const pub = a.pubDate
      ? new Date(a.pubDate).toLocaleString("en-US", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })
      : "";

    return `
<div class="bp-card" style="border-color:${color}">
  <div class="bp-card-head">
    <span class="bp-rank">#${a.rank}</span>
    <span class="bp-crit" style="color:${color}">${badge}</span>
    <span class="bp-src">${a.sourceName}${pub ? ` · ${pub}` : ""}</span>
    <span class="bp-score-line">digestScore <strong>${a.digestScore}</strong> · base ${a.digestBase} + bonus ${a.digestBonus}${bdParts ? ` <span class="bp-bd">(${bdParts})</span>` : ""}</span>
  </div>
  <div class="bp-title-row">
    <a href="${a.link}" target="_blank" rel="noopener">${a.title}</a>
  </div>
  ${signals ? `<div class="bp-signals">${signals}</div>` : ""}
  ${reasons ? `<div class="bp-reasons">⚡ ${reasons}</div>` : ""}
  <div class="bp-topic">🔑 <code>${a.topicKey}</code>${a.groupedFrom > 1 ? ` · grouped from ${a.groupedFrom} articles` : ""}</div>
  <div class="bp-why">📌 ${a.whyImportant}</div>
  ${wpts ? `<ul class="bp-watchpoints">${wpts}</ul>` : ""}
</div>`;
  }

  // ── Tableau articles rest ────────────────────────────────────────────────────
  function _restHTML(rest) {
    const rows = rest.map(a => {
      const isHigh = a.criticality === "high";
      const color  = isHigh ? "var(--err)" : "var(--warn)";
      return `<tr>
  <td class="bp-rt-rank">#${a.rank}</td>
  <td style="color:${color}">${isHigh ? "🔴" : "🟠"}</td>
  <td class="bp-rt-title"><a href="${a.link || "#"}" target="_blank" rel="noopener" title="${a.topicKey}">${a.title}</a></td>
  <td class="bp-rt-src">${a.sourceName}</td>
  <td class="bp-rt-ds">${a.digestScore}</td>
  <td>${a.isKEV ? '<span class="bp-badge bp-kev">KEV</span>' : ""}</td>
</tr>`;
    }).join("");

    return `
<div class="bp-rest">
  <h4 class="bp-rest-h4">📋 Autres alertes (${rest.length})</h4>
  <table class="bp-rest-table"><tbody>${rows}</tbody></table>
</div>`;
  }

  /**
   * Retourne un Set des IDs des articles top briefing en cache,
   * ou null si le briefing n'a pas encore été chargé.
   */
  function getTopIds() {
    if (!_cache || !Array.isArray(_cache.top)) return null;
    return new Set(_cache.top.map(a => a.id).filter(Boolean));
  }

  return { init, toggle, refresh, getTopIds };
})();
