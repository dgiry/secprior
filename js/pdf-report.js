// pdf-report.js — Rapport PDF SecOps ThreatLens
//
// Zéro dépendance : génère un rapport HTML dans un div caché,
// puis utilise window.print() avec des styles @media print dédiés.
// Le navigateur propose "Enregistrer en PDF" nativement.
//
// Sections :
//   1. En-tête
//   2. Résumé exécutif  — posture, KPIs enrichis, points d'attention, top 3
//   3. Top incidents    — incidents consolidés triés par priorité
//   4. Top CVEs         — KEV-first, EPSS desc, indicateur priorityLevel
//   5. Top Vendors      — agrégation articles, KEV / watchlist / priorityLevel
//   6. MITRE ATT&CK     — colonnes ID · Tactique · Occ · Fréquence
//   7. Sources
//   8. Pied de page

const PDFReport = (() => {

  // ── Génère et imprime le rapport ─────────────────────────────────────────

  function generate(articles) {
    if (!articles || articles.length === 0) {
      if (window.UI) UI.showToast("No article available for the report.", "warning");
      return;
    }

    const since7d = Date.now() - 7 * 86_400_000;
    const week    = articles.filter(a => a.pubDate && a.pubDate.getTime() >= since7d);
    const used    = week.length >= 5 ? week : articles;

    const container = document.getElementById("pdf-report");
    if (!container) return;
    container.innerHTML = _buildHTML(used, _weekLabel());
    window.print();
  }

  // ── Construction du HTML ──────────────────────────────────────────────────

  function _buildHTML(articles, weekLabel) {
    // Incidents consolidés (module optionnel)
    const incidents = (typeof IncidentPanel !== 'undefined')
      ? IncidentPanel.buildIncidentIndex(articles)
          .sort((a, b) => (b.incidentPriorityScore || 0) - (a.incidentPriorityScore || 0))
      : [];

    return `
      ${_buildHeader(articles, weekLabel)}
      ${_buildExecSummary(articles, incidents)}
      ${_buildIncidentSection(incidents)}
      ${_buildCVESection(articles)}
      ${_buildVendorSection(articles)}
      ${_buildAttackSection(articles)}
      ${_buildSourcesSection(articles)}
      ${_buildFooter()}`;
  }

  // ── 1. En-tête ────────────────────────────────────────────────────────────

  function _buildHeader(articles, weekLabel) {
    return `
      <div class="rpt-header">
        <div class="rpt-logo">🛡️ ThreatLens</div>
        <div class="rpt-subtitle">Context-aware SecOps prioritization</div>
        <div class="rpt-title">Cybersecurity Threat Intelligence Report</div>
        <div class="rpt-period">${weekLabel}</div>
        <div class="rpt-generated">Generated on ${new Date().toLocaleString("en-US")} · ${articles.length} articles analyzed</div>
      </div>`;
  }

  // ── 2. Résumé exécutif ────────────────────────────────────────────────────

  function _buildExecSummary(articles, incidents) {
    const critCount = articles.filter(a => a.priorityLevel === "critical_now").length;
    const invCount  = articles.filter(a => a.priorityLevel === "investigate").length;
    const kevCount  = articles.filter(a => a.isKEV).length;
    const totalIoc  = articles.reduce((s, a) => s + (a.iocCount || 0), 0);
    const epssArr   = articles.map(a => a.epssScore).filter(s => s != null);
    const maxEpss   = epssArr.length ? Math.max(...epssArr) : null;

    // Posture globale
    let postureCls, postureLabel;
    if (critCount > 0) {
      postureCls = "rpt-posture-critical"; postureLabel = "CRITICAL";
    } else if (invCount > 5 || kevCount > 2) {
      postureCls = "rpt-posture-high";     postureLabel = "HIGH";
    } else if (kevCount > 0 || invCount > 0) {
      postureCls = "rpt-posture-moderate"; postureLabel = "MODERATE-HIGH";
    } else {
      postureCls = "rpt-posture-low";      postureLabel = "MODERATE";
    }

    // Points d'attention
    const attn = [];
    if (kevCount > 0)    attn.push(`<strong>${kevCount} CVE</strong> are on the CISA KEV list (active exploitation confirmed).`);
    if (critCount > 0)   attn.push(`<strong>${critCount} article(s) CRITICAL NOW</strong> require immediate action.`);
    if (invCount > 0)    attn.push(`<strong>${invCount} signal(s) to investigate</strong> detected.`);
    if (totalIoc > 0)    attn.push(`<strong>${totalIoc} IOC</strong> extracted — enrich SIEM/EDR rules.`);

    // Top 3 sujets prioritaires
    const top3 = articles
      .filter(a => a.priorityLevel === "critical_now" || a.priorityLevel === "investigate")
      .sort((a, b) => (b.priorityScore || 0) - (a.priorityScore || 0))
      .slice(0, 3);
    if (!top3.length) {
      articles
        .slice()
        .sort((a, b) => (b.priorityScore || 0) - (a.priorityScore || 0))
        .slice(0, 3)
        .forEach(a => top3.push(a));
    }

    return `
      <section class="rpt-section">
        <h2 class="rpt-section-title">📊 Executive Summary</h2>

        <div class="rpt-posture-row">
          <span class="rpt-posture-lbl">Posture globale :</span>
          <span class="rpt-posture ${postureCls}">${postureLabel}</span>
        </div>

        <div class="rpt-kpi-row">
          <div class="rpt-kpi rpt-kpi-critical">
            <div class="rpt-kpi-val">${critCount}</div>
            <div class="rpt-kpi-lbl">Critical Now</div>
          </div>
          <div class="rpt-kpi rpt-kpi-investigate">
            <div class="rpt-kpi-val">${invCount}</div>
            <div class="rpt-kpi-lbl">To investigate</div>
          </div>
          <div class="rpt-kpi rpt-kpi-kev">
            <div class="rpt-kpi-val">${kevCount}</div>
            <div class="rpt-kpi-lbl">Confirmed KEV</div>
          </div>
          <div class="rpt-kpi">
            <div class="rpt-kpi-val">${incidents.length}</div>
            <div class="rpt-kpi-lbl">Consolidated incidents</div>
          </div>
          <div class="rpt-kpi">
            <div class="rpt-kpi-val">${maxEpss !== null ? (maxEpss * 100).toFixed(0) + "%" : "—"}</div>
            <div class="rpt-kpi-lbl">EPSS max</div>
          </div>
          <div class="rpt-kpi">
            <div class="rpt-kpi-val">${totalIoc}</div>
            <div class="rpt-kpi-lbl">IOCs extraits</div>
          </div>
        </div>

        ${attn.length ? `
        <div class="rpt-summary-box">
          <strong>⚠️ Key points:</strong>
          ${attn.map(l => `<br>• ${l}`).join("")}
        </div>` : ""}

        ${top3.length ? `
        <div class="rpt-top3-box">
          <strong>🎯 Top 3 priority topics</strong>
          <ol class="rpt-top3-list">
            ${top3.map(a => `
            <li>
              <span class="rpt-badge rpt-badge-${a.priorityLevel || "watch"}">${_lvlLabel(a.priorityLevel)}</span>
              ${_esc(a.title)}
              ${a.isKEV ? `<span class="rpt-badge rpt-badge-kev">KEV</span>` : ""}
              ${(a.cves || []).slice(0, 2).map(c => `<span class="rpt-badge rpt-badge-cve">${c}</span>`).join(" ")}
            </li>`).join("")}
          </ol>
        </div>` : ""}
      </section>`;
  }

  // ── 3. Top incidents prioritaires ─────────────────────────────────────────

  function _buildIncidentSection(incidents) {
    if (!incidents.length) return "";

    const top = incidents.slice(0, 8);

    return `
      <section class="rpt-section">
        <h2 class="rpt-section-title">🚨 Top Priority Incidents</h2>
        <table class="rpt-table">
          <thead>
            <tr>
              <th>Priority</th>
              <th>Summary</th>
              <th>CVEs</th>
              <th>Signals</th>
              <th>EPSS max</th>
              <th>Art.</th>
            </tr>
          </thead>
          <tbody>
            ${top.map(inc => {
              const lvl = inc.incidentPriorityLevel || "low";
              const rowCls = lvl === "critical_now" ? "rpt-row-critical" : inc.kev ? "rpt-row-kev" : "";
              const signals = [
                inc.kev          ? `<span class="rpt-badge rpt-badge-kev">KEV</span>` : "",
                inc.maxEpss > 0  ? `<span class="rpt-badge rpt-badge-epss">EPSS ${(inc.maxEpss*100).toFixed(0)}%</span>` : "",
                inc.rawIocCount  ? `<span class="rpt-badge rpt-badge-ioc">IOC</span>` : "",
                inc.watchlistHit ? `<span class="rpt-badge rpt-badge-wl">WL</span>` : "",
              ].filter(Boolean).join(" ");
              const cveStr = (inc.cves || []).slice(0, 3).map(c => `<span class="rpt-badge rpt-badge-cve">${c}</span>`).join(" ");
              const summary = _esc((inc.summary || (inc.vendors && inc.vendors.join(", ")) || "—")).slice(0, 90);
              return `
              <tr class="${rowCls}">
                <td><span class="rpt-badge rpt-badge-${lvl}">${_lvlLabel(lvl)}</span></td>
                <td class="rpt-title-cell">${summary}</td>
                <td class="rpt-tags">${cveStr || '<span class="rpt-dim">—</span>'}</td>
                <td class="rpt-tags">${signals || '<span class="rpt-dim">—</span>'}</td>
                <td class="rpt-center">${inc.maxEpss != null ? (inc.maxEpss*100).toFixed(1)+"%" : "—"}</td>
                <td class="rpt-center">${inc.articleCount || (inc.articles ? inc.articles.length : "—")}</td>
              </tr>`;
            }).join("")}
          </tbody>
        </table>
      </section>`;
  }

  // ── 4. Top CVEs ────────────────────────────────────────────────────────────

  function _buildCVESection(articles) {
    const cveMap = {};
    articles.forEach(a => {
      (a.cves || []).forEach(cve => {
        if (!cveMap[cve]) cveMap[cve] = {
          count: 0, epss: null, isKEV: false,
          maxPriorityLevel: "low", sources: new Set(), title: ""
        };
        cveMap[cve].count++;
        cveMap[cve].sources.add(a.sourceName);
        if (a.epssScore != null && (cveMap[cve].epss == null || a.epssScore > cveMap[cve].epss))
          cveMap[cve].epss = a.epssScore;
        if (a.isKEV) cveMap[cve].isKEV = true;
        if (!cveMap[cve].title && a.title) cveMap[cve].title = a.title;
        const pOrder = { critical_now: 3, investigate: 2, watch: 1, low: 0 };
        if ((pOrder[a.priorityLevel] || 0) > (pOrder[cveMap[cve].maxPriorityLevel] || 0))
          cveMap[cve].maxPriorityLevel = a.priorityLevel;
      });
    });

    const sorted = Object.entries(cveMap)
      .sort((a, b) => {
        if (a[1].isKEV !== b[1].isKEV) return b[1].isKEV ? 1 : -1;
        if ((b[1].epss || 0) !== (a[1].epss || 0)) return (b[1].epss || 0) - (a[1].epss || 0);
        return b[1].count - a[1].count;
      })
      .slice(0, 12);

    if (!sorted.length) return "";

    return `
      <section class="rpt-section">
        <h2 class="rpt-section-title">🔍 Critical CVEs Detected</h2>
        <table class="rpt-table">
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>Priority</th>
              <th>EPSS</th>
              <th>KEV</th>
              <th>Sources</th>
              <th>Context</th>
            </tr>
          </thead>
          <tbody>
            ${sorted.map(([cve, info]) => {
              const rowCls = info.isKEV ? "rpt-row-kev" : "";
              return `
            <tr class="${rowCls}">
              <td><a href="https://nvd.nist.gov/vuln/detail/${cve}" class="rpt-cve-id">${cve}</a></td>
              <td><span class="rpt-badge rpt-badge-${info.maxPriorityLevel}">${_lvlLabel(info.maxPriorityLevel)}</span></td>
              <td class="rpt-center">${info.epss != null ? (info.epss * 100).toFixed(1) + "%" : "—"}</td>
              <td class="rpt-center">${info.isKEV ? "✅" : "—"}</td>
              <td class="rpt-center">${info.sources.size}</td>
              <td class="rpt-small">${_esc(info.title).slice(0, 75)}${info.title.length > 75 ? "…" : ""}</td>
            </tr>`;
            }).join("")}
          </tbody>
        </table>
      </section>`;
  }

  // ── 5. Top Vendors ─────────────────────────────────────────────────────────

  function _buildVendorSection(articles) {
    const vendorMap = {};
    articles.forEach(a => {
      (a.vendors || []).forEach(v => {
        if (!vendorMap[v]) vendorMap[v] = {
          count: 0, kevCount: 0, wlCount: 0, maxPriorityLevel: "low",
          cves: new Set()
        };
        vendorMap[v].count++;
        if (a.isKEV) vendorMap[v].kevCount++;
        if (a.watchlistMatches && a.watchlistMatches.length) vendorMap[v].wlCount++;
        (a.cves || []).forEach(c => vendorMap[v].cves.add(c));
        const pOrder = { critical_now: 3, investigate: 2, watch: 1, low: 0 };
        if ((pOrder[a.priorityLevel] || 0) > (pOrder[vendorMap[v].maxPriorityLevel] || 0))
          vendorMap[v].maxPriorityLevel = a.priorityLevel;
      });
    });

    const sorted = Object.entries(vendorMap)
      .sort((a, b) => {
        const pOrder = { critical_now: 3, investigate: 2, watch: 1, low: 0 };
        const pd = (pOrder[b[1].maxPriorityLevel] || 0) - (pOrder[a[1].maxPriorityLevel] || 0);
        if (pd !== 0) return pd;
        return b[1].count - a[1].count;
      })
      .slice(0, 12);

    if (!sorted.length) return "";

    return `
      <section class="rpt-section rpt-section-half">
        <h2 class="rpt-section-title">🏭 Top Exposed Vendors / Technologies</h2>
        <table class="rpt-table">
          <thead>
            <tr>
              <th>Vendor / Tech</th>
              <th>Max priority</th>
              <th>Articles</th>
              <th>CVEs</th>
              <th>KEV</th>
              <th>Watchlist</th>
            </tr>
          </thead>
          <tbody>
            ${sorted.map(([name, info]) => {
              const rowCls = info.kevCount > 0 ? "rpt-row-kev" : "";
              return `
            <tr class="${rowCls}">
              <td><strong>${_esc(name)}</strong></td>
              <td><span class="rpt-badge rpt-badge-${info.maxPriorityLevel}">${_lvlLabel(info.maxPriorityLevel)}</span></td>
              <td class="rpt-center">${info.count}</td>
              <td class="rpt-center">${info.cves.size || "—"}</td>
              <td class="rpt-center">${info.kevCount || "—"}</td>
              <td class="rpt-center">${info.wlCount ? "✅" : "—"}</td>
            </tr>`;
            }).join("")}
          </tbody>
        </table>
      </section>`;
  }

  // ── 6. MITRE ATT&CK ────────────────────────────────────────────────────────

  function _buildAttackSection(articles) {
    const tactics = {};
    articles.forEach(a => {
      (a.attackTags || []).forEach(t => {
        if (!tactics[t.label]) tactics[t.label] = { count: 0, id: t.tactic || "" };
        tactics[t.label].count++;
      });
    });

    const sorted = Object.entries(tactics).sort((a, b) => b[1].count - a[1].count).slice(0, 8);
    if (!sorted.length) return "";

    const max = sorted[0][1].count;

    return `
      <section class="rpt-section rpt-section-half">
        <h2 class="rpt-section-title">🎯 MITRE ATT&CK Tactics Detected</h2>
        <table class="rpt-table">
          <thead>
            <tr><th>ID</th><th>Technique / Tactic</th><th>Occ.</th><th>Frequency</th></tr>
          </thead>
          <tbody>
            ${sorted.map(([label, info]) => `
            <tr>
              <td class="rpt-center rpt-small">${info.id}</td>
              <td><strong>${_esc(label)}</strong></td>
              <td class="rpt-center">${info.count}</td>
              <td>
                <div class="rpt-minibar-track">
                  <div class="rpt-minibar" style="width:${Math.round(info.count / max * 100)}%"></div>
                </div>
              </td>
            </tr>`).join("")}
          </tbody>
        </table>
      </section>`;
  }

  // ── 7. Sources ─────────────────────────────────────────────────────────────

  function _buildSourcesSection(articles) {
    const counts = {};
    articles.forEach(a => { counts[a.sourceName] = (counts[a.sourceName] || 0) + 1; });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const total  = articles.length || 1;

    return `
      <section class="rpt-section">
        <h2 class="rpt-section-title">📡 Distribution by Source</h2>
        <table class="rpt-table">
          <thead>
            <tr><th>Source</th><th>Articles</th><th>%</th><th>Distribution</th></tr>
          </thead>
          <tbody>
            ${sorted.map(([name, count]) => `
            <tr>
              <td>${_esc(name)}</td>
              <td class="rpt-center">${count}</td>
              <td class="rpt-center">${(count / total * 100).toFixed(1)}%</td>
              <td>
                <div class="rpt-minibar-track">
                  <div class="rpt-minibar rpt-minibar-blue" style="width:${Math.round(count / sorted[0][1] * 100)}%"></div>
                </div>
              </td>
            </tr>`).join("")}
          </tbody>
        </table>
      </section>`;
  }

  // ── 8. Pied de page ────────────────────────────────────────────────────────

  function _buildFooter() {
    return `
      <div class="rpt-footer">
        <div>ThreatLens — Confidential report</div>
        <div>Sources: ${typeof CONFIG !== 'undefined' ? CONFIG.FEEDS.length : "?"} RSS feeds · Pipeline: Collect → Enrich → Deduplicate → Score → Contextualize</div>
        <div>${new Date().toLocaleDateString("en-US", { year:"numeric", month:"long", day:"numeric" })}</div>
      </div>`;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  function _weekLabel() {
    const now   = new Date();
    const start = new Date(now);
    start.setDate(now.getDate() - 6);
    const fmt = d => d.toLocaleDateString("en-US", { day: "2-digit", month: "long" });
    return `Semaine du ${fmt(start)} au ${fmt(now)} ${now.getFullYear()}`;
  }

  function _esc(str) {
    return (str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function _lvlLabel(level) {
    const map = { critical_now: "CRITICAL", investigate: "INVEST.", watch: "WATCH", low: "LOW" };
    return map[level] || (level || "—").toUpperCase();
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  function init() {
    document.getElementById("btn-pdf")?.addEventListener("click", () => {
      const articles = window._statsLastArticles || [];
      generate(articles);
    });
  }

  return { init, generate };
})();
