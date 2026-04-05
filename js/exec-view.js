// exec-view.js — Exec / CISO View
// Lightweight decision-oriented summary for executives and stakeholders.
// Answers "What matters now?" in under 30 seconds.
// Reuses existing article signals: priorityLevel, isKEV, priorityScore,
// scoreBreakdown, prioritySignals, vendors, cves, watchlistMatches.
// No new scoring engine — pure aggregation of existing enriched data.

const ExecView = (function () {
  'use strict';

  let _articles = [];

  // ── Public API ─────────────────────────────────────────────────────────────

  function init() {
    document.getElementById('btn-exec-view')?.addEventListener('click', open);
    document.getElementById('exec-view-close')?.addEventListener('click', close);
    document.getElementById('modal-exec-view')?.addEventListener('click', e => {
      if (e.target === e.currentTarget) close();
    });
  }

  function update(articles) {
    _articles = articles || [];
    // Re-render live if modal is already open
    const modal = document.getElementById('modal-exec-view');
    if (modal && modal.style.display !== 'none') _render();
  }

  function open() {
    const modal = document.getElementById('modal-exec-view');
    if (!modal) return;
    _render();
    modal.style.display = 'flex';
  }

  function close() {
    const modal = document.getElementById('modal-exec-view');
    if (modal) modal.style.display = 'none';
  }

  // ── Posture ────────────────────────────────────────────────────────────────

  function _computePosture(arts) {
    const critCount = arts.filter(a => a.priorityLevel === 'critical_now').length;
    const invCount  = arts.filter(a => a.priorityLevel === 'investigate').length;
    const kevCount  = arts.filter(a => a.isKEV).length;

    let level, css, icon, desc;
    if (critCount > 0) {
      level = 'CRITICAL'; css = 'critical'; icon = '🔴';
      desc  = `${critCount} critical threat${critCount !== 1 ? 's require' : ' requires'} immediate action`;
    } else if (invCount > 5 || kevCount > 2) {
      level = 'HIGH'; css = 'high'; icon = '🟠';
      desc  = kevCount > 2
        ? `${kevCount} actively exploited vulnerabilities detected`
        : `${invCount} threats under active investigation`;
    } else if (kevCount > 0 || invCount > 0) {
      level = 'ELEVATED'; css = 'elevated'; icon = '🟡';
      desc  = kevCount > 0
        ? `${kevCount} KEV item${kevCount !== 1 ? 's' : ''} warrant attention`
        : `${invCount} item${invCount !== 1 ? 's' : ''} under investigation`;
    } else {
      level = 'NOMINAL'; css = 'nominal'; icon = '🟢';
      desc  = 'No critical or elevated threats detected in the current period';
    }

    return { level, css, icon, desc, critCount, invCount, kevCount };
  }

  // ── Signals ────────────────────────────────────────────────────────────────

  function _watchlistHits(arts) {
    return arts.filter(a => (a.watchlistMatches || []).length > 0).length;
  }

  function _topVendors(arts, max) {
    const tally = {};
    arts.forEach(a => {
      (a.vendors || []).forEach(v => {
        if (v && v.length > 1) tally[v] = (tally[v] || 0) + 1;
      });
    });
    return Object.entries(tally)
      .sort((a, b) => b[1] - a[1])
      .slice(0, max || 6)
      .map(([name, count]) => ({ name, count }));
  }

  function _topCVEs(arts, max) {
    const bag = {};
    arts.forEach(a => {
      (a.cves || []).forEach(cve => {
        if (!bag[cve]) bag[cve] = { cve, epss: 0, kev: false, count: 0 };
        bag[cve].count++;
        if ((a.epssScore || 0) > bag[cve].epss) bag[cve].epss = a.epssScore;
        if (a.isKEV) bag[cve].kev = true;
      });
    });
    return Object.values(bag)
      .sort((a, b) => (b.epss - a.epss) || (b.count - a.count) || (b.kev - a.kev))
      .slice(0, max || 5);
  }

  function _topIncidents(arts, max) {
    if (typeof IncidentPanel === 'undefined') return [];
    try {
      const incs = IncidentPanel.buildIncidentIndex(arts);
      return incs
        .sort((a, b) => (b.incidentPriorityScore || 0) - (a.incidentPriorityScore || 0))
        .slice(0, max || 3);
    } catch (_) { return []; }
  }

  // ── Executive summary heuristic ────────────────────────────────────────────

  function _buildSummary(posture, wlHits, vendors) {
    const lines = [];
    const { critCount, kevCount, invCount } = posture;

    // Line 1 — threat posture
    if (critCount > 0) {
      lines.push(`${critCount} critical threat${critCount !== 1 ? 's require' : ' requires'} immediate review.`);
    } else if (invCount > 0) {
      lines.push(`${invCount} threat${invCount !== 1 ? 's are' : ' is'} under investigation — no immediate action required.`);
    } else {
      lines.push('No critical or high-priority threats detected in the current period.');
    }

    // Line 2 — active exploits
    if (kevCount > 0) {
      lines.push(`${kevCount} item${kevCount !== 1 ? 's involve' : ' involves'} actively exploited vulnerabilities (CISA KEV).`);
    }

    // Line 3 — environment relevance
    if (wlHits > 0) {
      lines.push(`${wlHits} article${wlHits !== 1 ? 's match' : ' matches'} your tracked technologies.`);
    }

    // Line 4 — top vendors
    if (vendors.length > 0) {
      const top2 = vendors.slice(0, 2).map(v => v.name).join(' and ');
      lines.push(`${top2} ${vendors.length > 1 ? 'are' : 'is'} the most referenced vendor${vendors.length > 1 ? 's' : ''} this period.`);
    }

    return lines;
  }

  // ── HTML builders ──────────────────────────────────────────────────────────

  function _kpiTile(icon, value, label, cls) {
    const highlight = value > 0 && cls !== 'ev-kpi-inv';
    return `<div class="ev-kpi ${cls}${highlight ? ' ev-kpi-active' : ''}">
      <span class="ev-kpi-value">${value}</span>
      <span class="ev-kpi-label">${icon} ${label}</span>
    </div>`;
  }

  function _incidentCard(inc) {
    const lvl = inc.incidentPriorityLevel || 'low';
    const pm  = (typeof getPriorityMeta === 'function') ? getPriorityMeta(lvl) : { icon: '⚪', label: lvl };
    const chips = [
      inc.kev         ? `<span class="ev-chip ev-chip-kev">🔑 KEV</span>` : '',
      inc.watchlistHit? `<span class="ev-chip ev-chip-wl">👁 Matches you</span>` : '',
      (inc.maxEpss && inc.maxEpss > 0.3)
        ? `<span class="ev-chip ev-chip-epss">📊 EPSS ${Math.round(inc.maxEpss * 100)}%</span>` : '',
    ].filter(Boolean).join('');
    const vendors = (inc.vendors || []).slice(0, 3).join(', ');

    return `<div class="ev-incident-card ev-inc-${lvl}">
      <div class="ev-inc-header">
        <span class="ev-inc-icon">${pm.icon}</span>
        <span class="ev-inc-title">${inc.title}</span>
      </div>
      ${chips ? `<div class="ev-inc-chips">${chips}</div>` : ''}
      ${vendors ? `<div class="ev-inc-meta">Vendors: ${vendors}</div>` : ''}
      ${inc.articleCount > 1 ? `<div class="ev-inc-meta">${inc.articleCount} articles · ${inc.sourceCount} source${inc.sourceCount !== 1 ? 's' : ''}</div>` : ''}
    </div>`;
  }

  function _vendorRow(v, rank) {
    const bar = Math.min(100, Math.round((v.count / Math.max(v.count, 10)) * 100));
    return `<div class="ev-vendor-row">
      <span class="ev-vendor-rank">#${rank + 1}</span>
      <div class="ev-vendor-bar-wrap">
        <span class="ev-vendor-name">${v.name}</span>
        <div class="ev-vendor-bar" style="width:${bar}%"></div>
      </div>
      <span class="ev-vendor-count">${v.count}</span>
    </div>`;
  }

  function _cveRow(c) {
    return `<div class="ev-cve-row">
      <code class="ev-cve-id">${c.cve}</code>
      ${c.kev ? `<span class="ev-chip ev-chip-kev" style="font-size:.58rem;padding:.08rem .3rem">KEV</span>` : ''}
      ${c.epss > 0 ? `<span class="ev-cve-epss">EPSS ${(c.epss * 100).toFixed(0)}%</span>` : ''}
      <span class="ev-cve-count">${c.count} art.</span>
    </div>`;
  }

  // ── Main render ────────────────────────────────────────────────────────────

  function _render() {
    const container = document.getElementById('exec-view-body');
    if (!container) return;

    const arts     = _articles;
    const posture  = _computePosture(arts);
    const wlHits   = _watchlistHits(arts);
    const vendors  = _topVendors(arts, 6);
    const cves     = _topCVEs(arts, 5);
    const incidents= _topIncidents(arts, 3);
    const summary  = _buildSummary(posture, wlHits, vendors);

    const now      = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const period   = arts.length
      ? `${arts.length} article${arts.length !== 1 ? 's' : ''} · updated ${now}`
      : 'No data in current view';

    const noData = arts.length === 0;

    container.innerHTML = `
      ${noData ? `<div class="ev-no-data">
        <span style="font-size:2rem">📭</span>
        <p>No articles in the current view.<br>
           Load feeds or widen the time filter to generate the executive summary.</p>
      </div>` : `

      <!-- ① Posture header -->
      <div class="ev-posture ev-posture-${posture.css}">
        <span class="ev-posture-icon">${posture.icon}</span>
        <div class="ev-posture-text">
          <span class="ev-posture-level">${posture.level}</span>
          <span class="ev-posture-desc">${posture.desc}</span>
        </div>
        <span class="ev-posture-period">${period}</span>
      </div>

      <!-- ② KPI row -->
      <div class="ev-kpis">
        ${_kpiTile('🔴', posture.critCount, 'Critical',     'ev-kpi-critical')}
        ${_kpiTile('🔑', posture.kevCount,  'KEV active',   'ev-kpi-kev')}
        ${_kpiTile('👁', wlHits,            'Matches you',  'ev-kpi-wl')}
        ${_kpiTile('🔍', posture.invCount,  'Investigating','ev-kpi-inv')}
      </div>

      <!-- ③ Executive summary -->
      <div class="ev-section">
        <h3 class="ev-section-title">📋 Executive Summary</h3>
        <div class="ev-summary">
          ${summary.map(l => `<p class="ev-summary-line">${l}</p>`).join('')}
        </div>
      </div>

      <!-- ④ Incidents + Vendors/CVEs (two columns) -->
      <div class="ev-cols">

        <div class="ev-col">
          <h3 class="ev-section-title">⚡ Priority Incidents</h3>
          ${incidents.length
            ? incidents.map(i => _incidentCard(i)).join('')
            : '<p class="ev-empty">No incidents clustered in current period.</p>'}
        </div>

        <div class="ev-col">
          ${vendors.length ? `
          <h3 class="ev-section-title">🏢 Most Affected Vendors</h3>
          <div class="ev-vendor-list">
            ${vendors.map((v, i) => _vendorRow(v, i)).join('')}
          </div>` : ''}

          ${cves.length ? `
          <h3 class="ev-section-title" style="margin-top:1.1rem">🔓 Top CVEs</h3>
          <div class="ev-cve-list">
            ${cves.map(c => _cveRow(c)).join('')}
          </div>` : ''}
        </div>

      </div>`}
    `;
  }

  return { init, update, open, close };
})();
