// visibility-panel.js — Panneau 👁 Visibilité (V1)
//
// Vue de synthèse opérationnelle :
//   KPI cards · Qualité d'enrichissement · Santé des flux
//   Top Vendors · Top Incidents (avec statut analyste)
//
// Réutilise : FeedManager · IncidentPanel.buildIncidentIndex · EntityStatus
// Pas de dépendance externe supplémentaire.
//
// API publique : init, toggle, update

const VisibilityPanel = (() => {

  let _articles = [];

  // ── Calcul ─────────────────────────────────────────────────────────────────

  function _compute(articles) {
    const total  = articles.length || 1;          // évite division par zéro
    const now    = Date.now();
    const ago24h = now - 24 * 3_600_000;

    const articles24h = articles.filter(a => {
      const t = a.pubDate instanceof Date ? a.pubDate.getTime()
              : (a.pubDate ? new Date(a.pubDate).getTime() : 0);
      return t >= ago24h;
    });

    // Feeds
    const feeds       = (typeof FeedManager !== "undefined") ? FeedManager.getAllFeeds() : [];
    const activeFeeds = feeds.filter(f => f.enabled).length;

    // CVE / KEV / Watchlist
    const cveSet   = new Set(articles.flatMap(a => (a.cveIds || a.cves || []).map(c => c.toUpperCase())));
    const kevCount = articles.filter(a => a.isKEV).length;
    const wlHits   = articles.filter(a => (a.watchlistMatches || []).length > 0).length;

    // Incidents
    const incidents = (typeof IncidentPanel !== "undefined")
      ? IncidentPanel.buildIncidentIndex(articles) : [];

    // Qualité d'enrichissement
    const pct = n => Math.round(n / total * 100);
    const enrichment = {
      withCvePct:       pct(articles.filter(a => (a.cveIds || a.cves || []).length > 0).length),
      withEpssPct:      pct(articles.filter(a => a.epssScore != null).length),
      withKevPct:       pct(articles.filter(a => a.isKEV).length),
      withVendorsPct:   pct(articles.filter(a => (a.vendors || []).length > 0).length),
      withIocPct:       pct(articles.filter(a => (a.iocCount || 0) > 0).length),
      withScorePct:     pct(articles.filter(a => (a.score || 0) > 0).length),
      withWatchlistPct: pct(articles.filter(a => (a.watchlistMatches || []).length > 0).length)
    };

    // Top vendors (agrégé depuis les articles)
    const vendorMap = new Map();
    articles.forEach(a => {
      (a.vendors || []).forEach(v => {
        if (!v) return;
        if (!vendorMap.has(v)) vendorMap.set(v, { name: v, count: 0, kevCount: 0, wlHit: false, incidents: 0 });
        const e = vendorMap.get(v);
        e.count++;
        if (a.isKEV) e.kevCount++;
        if ((a.watchlistMatches || []).length > 0) e.wlHit = true;
      });
    });
    incidents.forEach(i => {
      i.vendors.forEach(v => { const e = vendorMap.get(v); if (e) e.incidents++; });
    });
    const topVendors   = [...vendorMap.values()].sort((a, b) => b.count - a.count).slice(0, 8);
    const topIncidents = incidents.slice(0, 8);

    return {
      kpis: {
        activeFeeds, totalFeeds: feeds.length,
        articles24h:   articles24h.length,
        totalArticles: articles.length,
        cveCount:      cveSet.size,
        kevCount, wlHits,
        incidentCount: incidents.length
      },
      enrichment,
      feeds,
      topVendors,
      topIncidents
    };
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  function _esc(s) {
    return String(s || "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function _fmtDT(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleDateString("fr-FR", {
        day: "2-digit", month: "2-digit",
        hour: "2-digit", minute: "2-digit"
      });
    } catch { return "—"; }
  }

  function _fmtD(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" });
    } catch { return "—"; }
  }

  function _barColor(pct) {
    if (pct >= 70) return "var(--ok)";
    if (pct >= 30) return "var(--warn)";
    return "var(--err)";
  }

  // ── Blocs HTML ─────────────────────────────────────────────────────────────

  function _kpiCardsHTML(kpis) {
    const feedColor  = kpis.activeFeeds === kpis.totalFeeds ? "ok"
                     : kpis.activeFeeds > 0 ? "warn" : "err";
    const cards = [
      { icon: "📡", value: `${kpis.activeFeeds}/${kpis.totalFeeds}`, label: "Flux actifs",    col: feedColor },
      { icon: "📰", value: kpis.articles24h,                         label: "Articles 24h",   col: "neutral" },
      { icon: "📋", value: kpis.totalArticles,                       label: "Articles total", col: "neutral" },
      { icon: "🔍", value: kpis.cveCount,                            label: "CVE détectées",  col: kpis.cveCount   > 0 ? "warn" : "neutral" },
      { icon: "🚨", value: kpis.kevCount,                            label: "KEV confirmées", col: kpis.kevCount   > 0 ? "err"  : "neutral" },
      { icon: "👁",  value: kpis.wlHits,                             label: "Watchlist hits", col: kpis.wlHits     > 0 ? "warn" : "neutral" },
      { icon: "🎯", value: kpis.incidentCount,                       label: "Incidents",      col: kpis.incidentCount > 0 ? "warn" : "neutral" },
    ];
    return `<div class="vb-kpi-grid">${cards.map(c => `
      <div class="vb-kpi-card vb-kpi-${c.col}">
        <div class="vb-kpi-icon">${c.icon}</div>
        <div class="vb-kpi-value">${c.value}</div>
        <div class="vb-kpi-label">${c.label}</div>
      </div>`).join("")}</div>`;
  }

  function _enrichmentHTML(enr) {
    const rows = [
      { icon: "🔍", label: "CVE détectées",     pct: enr.withCvePct },
      { icon: "📊", label: "EPSS scorées",       pct: enr.withEpssPct },
      { icon: "🚨", label: "Marquées KEV",       pct: enr.withKevPct },
      { icon: "🏢", label: "Vendor identifié",   pct: enr.withVendorsPct },
      { icon: "🔗", label: "IOC extraits",       pct: enr.withIocPct },
      { icon: "⚡", label: "Score calculé",      pct: enr.withScorePct },
      { icon: "👁",  label: "Watchlist hit",     pct: enr.withWatchlistPct },
    ];
    return `<div class="vb-enr-list">${rows.map(r => `
      <div class="vb-enr-row">
        <span class="vb-enr-icon">${r.icon}</span>
        <span class="vb-enr-label">${r.label}</span>
        <div class="vb-enr-bar-wrap">
          <div class="vb-enr-bar-fill" style="width:${r.pct}%;background:${_barColor(r.pct)}"></div>
        </div>
        <span class="vb-enr-pct">${r.pct}%</span>
      </div>`).join("")}</div>`;
  }

  function _feedsHTML(feeds) {
    if (!feeds.length) return `<p class="vb-empty">Aucun flux configuré.</p>`;
    return `<div class="vb-feed-scroll"><table class="vb-feed-table">
      <thead><tr class="vb-thead">
        <th>Flux</th><th>St.</th><th>État</th>
        <th>Dernier OK</th><th>Dernière err.</th>
        <th class="vb-num">Items</th><th>Message</th>
      </tr></thead>
      <tbody>${feeds.map(f => {
        const dot  = f.lastStatus === "ok" ? "🟢" : f.lastStatus === "error" ? "🔴" : "⚪";
        const enBadge = f.enabled
          ? `<span class="vb-badge vb-ok">actif</span>`
          : `<span class="vb-badge vb-muted">off</span>`;
        const err = f.lastErrorMessage
          ? `<span class="vb-feed-err" title="${_esc(f.lastErrorMessage)}">${_esc(f.lastErrorMessage.slice(0,55))}${f.lastErrorMessage.length > 55 ? "…" : ""}</span>`
          : "";
        return `<tr class="vb-feed-row">
          <td><span class="vb-feed-name"><span>${f.icon || "📡"}</span>${_esc(f.name)}</span></td>
          <td>${dot}</td>
          <td>${enBadge}</td>
          <td class="vb-feed-meta">${_fmtDT(f.lastSuccessAt)}</td>
          <td class="vb-feed-meta">${_fmtDT(f.lastErrorAt)}</td>
          <td class="vb-num">${f.lastItemCount ?? "—"}</td>
          <td class="vb-errmsg">${err}</td>
        </tr>`;
      }).join("")}</tbody>
    </table></div>`;
  }

  function _topVendorsHTML(vendors) {
    if (!vendors.length) return `<p class="vb-empty">Aucun vendor détecté dans les articles.</p>`;
    return `<table class="vb-top-table">
      <thead><tr class="vb-thead">
        <th>Vendor</th>
        <th class="vb-num">Art.</th>
        <th class="vb-num">Inc.</th>
        <th class="vb-num">KEV</th>
        <th>WL</th>
      </tr></thead>
      <tbody>${vendors.map(v => `
        <tr class="vb-top-row">
          <td>${_esc(v.name)}</td>
          <td class="vb-num">${v.count}</td>
          <td class="vb-num vb-dim">${v.incidents || "—"}</td>
          <td class="vb-num">${v.kevCount > 0
            ? `<span class="vb-badge vb-err">${v.kevCount}</span>` : "—"}</td>
          <td>${v.wlHit ? `<span class="vb-badge vb-warn">👁</span>` : "—"}</td>
        </tr>`).join("")}
      </tbody>
    </table>`;
  }

  function _topIncidentsHTML(incidents) {
    if (!incidents.length) return `<p class="vb-empty">Aucun incident consolidé pour l'instant.</p>`;
    return `<table class="vb-top-table">
      <thead><tr class="vb-thead">
        <th>Incident</th>
        <th class="vb-num">Art.</th>
        <th class="vb-num">Score</th>
        <th>Signaux</th>
        <th class="vb-num">Vu le</th>
        <th>Statut</th>
      </tr></thead>
      <tbody>${incidents.map(i => {
        const sig = [
          i.kev          ? `<span class="vb-badge vb-err">🚨 KEV</span>` : "",
          i.watchlistHit ? `<span class="vb-badge vb-warn">👁 WL</span>` : "",
          i.trending     ? `<span class="vb-badge vb-neutral">🔥</span>` : ""
        ].filter(Boolean).join(" ");

        let stBadge = `<span class="vb-dim">—</span>`;
        if (typeof EntityStatus !== "undefined") {
          const st = EntityStatus.getEffectiveStatus("incident", i.incidentId);
          if (st !== "new") {
            const m = EntityStatus.STATUS_META[st];
            stBadge = `<span class="es-badge es-${st}" style="color:${m.color};background:${m.bg}">${m.emoji} ${m.label}</span>`;
          }
        }

        return `<tr class="vb-top-row">
          <td class="vb-inc-title" title="${_esc(i.title)}">${_esc(i.title)}</td>
          <td class="vb-num">${i.articleCount}</td>
          <td class="vb-num">${i.maxScore > 0 ? i.maxScore : "—"}</td>
          <td>${sig || '<span class="vb-dim">—</span>'}</td>
          <td class="vb-num vb-dim">${_fmtD(i.lastSeen)}</td>
          <td>${stBadge}</td>
        </tr>`;
      }).join("")}
      </tbody>
    </table>`;
  }

  // ── Rendu principal ────────────────────────────────────────────────────────

  function _render() {
    const content = document.getElementById("visibility-content");
    if (!content) return;

    const data = _compute(_articles);
    const { kpis, enrichment, feeds, topVendors, topIncidents } = data;

    const feedOkCount = feeds.filter(f => f.lastStatus === "ok").length;
    const meta = document.getElementById("vb-meta");
    if (meta) meta.textContent = `${kpis.totalArticles} articles · ${feedOkCount}/${feeds.length} flux OK`;

    content.innerHTML = `
      <section class="vb-section">
        ${_kpiCardsHTML(kpis)}
      </section>

      <section class="vb-section vb-two-col">
        <div class="vb-col">
          <h3 class="vb-section-title">📊 Qualité d'enrichissement</h3>
          <p class="vb-section-sub">${kpis.totalArticles} article${kpis.totalArticles !== 1 ? "s" : ""} analysé${kpis.totalArticles !== 1 ? "s" : ""}</p>
          ${_enrichmentHTML(enrichment)}
        </div>
        <div class="vb-col">
          <h3 class="vb-section-title">🏢 Top Vendors</h3>
          <p class="vb-section-sub">${topVendors.length} vendor${topVendors.length !== 1 ? "s" : ""} identifié${topVendors.length !== 1 ? "s" : ""}</p>
          ${_topVendorsHTML(topVendors)}
        </div>
      </section>

      <section class="vb-section">
        <h3 class="vb-section-title">📡 Santé des flux</h3>
        <p class="vb-section-sub">${kpis.activeFeeds} flux actif${kpis.activeFeeds !== 1 ? "s" : ""} sur ${kpis.totalFeeds}</p>
        ${_feedsHTML(feeds)}
      </section>

      <section class="vb-section">
        <h3 class="vb-section-title">🎯 Top Incidents</h3>
        <p class="vb-section-sub">${topIncidents.length} sur ${kpis.incidentCount} incident${kpis.incidentCount !== 1 ? "s" : ""} consolidé${kpis.incidentCount !== 1 ? "s" : ""}</p>
        ${_topIncidentsHTML(topIncidents)}
      </section>`;
  }

  // ── Visibilité ─────────────────────────────────────────────────────────────

  function _isVisible() {
    return document.getElementById("visibility-panel")?.style.display !== "none";
  }

  // ── API publique ───────────────────────────────────────────────────────────

  function init() {
    document.getElementById("btn-visibility")?.addEventListener("click", toggle);
  }

  function toggle() {
    const panel = document.getElementById("visibility-panel");
    const btn   = document.getElementById("btn-visibility");
    if (!panel) return;
    const nowVisible = !_isVisible();
    panel.style.display = nowVisible ? "block" : "none";
    btn?.classList.toggle("active", nowVisible);
    if (nowVisible) _render();
  }

  function update(articles) {
    _articles = articles || [];
    if (_isVisible()) _render();
  }

  return { init, toggle, update };
})();
