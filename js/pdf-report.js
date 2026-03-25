// pdf-report.js — Rapport PDF hebdomadaire CyberVeille Pro
//
// Zéro dépendance : génère un rapport HTML dans un div caché,
// puis utilise window.print() avec des styles @media print dédiés.
// Le navigateur propose "Enregistrer en PDF" nativement.
//
// Contenu du rapport :
//   1. En-tête   : logo, période, date de génération
//   2. Résumé    : KPIs de la semaine
//   3. TOP HIGH  : 10 articles haute criticité
//   4. CVE       : top CVEs avec CVSS / EPSS / KEV
//   5. ATT&CK    : tactiques les plus détectées
//   6. Sources   : répartition par flux RSS
//   7. Pied de page

const PDFReport = (() => {

  // ── Génère et imprime le rapport ──────────────────────────────────────────

  function generate(articles) {
    if (!articles || articles.length === 0) {
      if (window.UI) UI.showToast("Aucun article disponible pour le rapport.", "warning");
      return;
    }

    // Filtrer sur les 7 derniers jours
    const since7d  = Date.now() - 7 * 86_400_000;
    const week     = articles.filter(a => a.pubDate.getTime() >= since7d);
    const allUsed  = week.length >= 5 ? week : articles; // fallback si pas assez

    const weekLabel = _weekLabel();

    // Injecter le HTML dans le conteneur print
    const container = document.getElementById("pdf-report");
    if (!container) return;
    container.innerHTML = _buildHTML(allUsed, weekLabel);

    // Déclencher l'impression (→ "Enregistrer en PDF" dans le navigateur)
    window.print();
  }

  // ── Construction du HTML du rapport ───────────────────────────────────────

  function _buildHTML(articles, weekLabel) {
    const high    = articles.filter(a => a.criticality === "high");
    const medium  = articles.filter(a => a.criticality === "medium");
    const low     = articles.filter(a => a.criticality === "low");
    const kev     = articles.filter(a => a.isKEV);
    const trending= articles.filter(a => a.isTrending);

    const epssArr  = articles.map(a => a.epssScore).filter(s => s != null);
    const epssAvg  = epssArr.length
      ? (epssArr.reduce((a, b) => a + b, 0) / epssArr.length * 100).toFixed(1)
      : null;

    const scoreArr = articles.map(a => a.score).filter(s => s != null);
    const avgScore = scoreArr.length
      ? Math.round(scoreArr.reduce((a, b) => a + b, 0) / scoreArr.length)
      : null;

    return `
      <!-- ── EN-TÊTE ─────────────────────────────────────────────────── -->
      <div class="rpt-header">
        <div class="rpt-logo">🛡️ CyberVeille Pro</div>
        <div class="rpt-title">Rapport de Veille Cybersécurité</div>
        <div class="rpt-period">${weekLabel}</div>
        <div class="rpt-generated">Généré le ${new Date().toLocaleString("fr-FR")} · ${articles.length} articles analysés</div>
      </div>

      <!-- ── RÉSUMÉ EXÉCUTIF ────────────────────────────────────────── -->
      <section class="rpt-section">
        <h2 class="rpt-section-title">📊 Résumé Exécutif</h2>
        <div class="rpt-kpi-row">
          <div class="rpt-kpi rpt-kpi-high">
            <div class="rpt-kpi-val">${high.length}</div>
            <div class="rpt-kpi-lbl">Alertes HAUTE</div>
          </div>
          <div class="rpt-kpi rpt-kpi-medium">
            <div class="rpt-kpi-val">${medium.length}</div>
            <div class="rpt-kpi-lbl">Alertes MOYENNE</div>
          </div>
          <div class="rpt-kpi rpt-kpi-low">
            <div class="rpt-kpi-val">${low.length}</div>
            <div class="rpt-kpi-lbl">Alertes BASSE</div>
          </div>
          <div class="rpt-kpi rpt-kpi-kev">
            <div class="rpt-kpi-val">${kev.length}</div>
            <div class="rpt-kpi-lbl">Exploits actifs (KEV)</div>
          </div>
          <div class="rpt-kpi">
            <div class="rpt-kpi-val">${epssAvg !== null ? epssAvg + "%" : "—"}</div>
            <div class="rpt-kpi-lbl">EPSS moyen</div>
          </div>
          <div class="rpt-kpi">
            <div class="rpt-kpi-val">${avgScore !== null ? avgScore : "—"}</div>
            <div class="rpt-kpi-lbl">Score composite moy.</div>
          </div>
        </div>

        ${high.length > 0 ? `
        <div class="rpt-summary-box">
          <strong>⚠️ Points d'attention :</strong>
          ${kev.length > 0 ? `<br>• <strong>${kev.length} CVE</strong> figurent dans la liste CISA KEV (exploitation active confirmée).` : ""}
          ${trending.length > 0 ? `<br>• <strong>${trending.length} sujets trending</strong> couverts par plusieurs sources simultanément.` : ""}
          ${high.length > 0 ? `<br>• <strong>${high.length} articles haute criticité</strong> nécessitent une attention immédiate.` : ""}
        </div>` : ""}
      </section>

      <!-- ── TOP 10 ARTICLES HIGH ───────────────────────────────────── -->
      <section class="rpt-section">
        <h2 class="rpt-section-title">🔴 Top Alertes Haute Criticité</h2>
        ${high.length === 0
          ? `<p class="rpt-empty">Aucune alerte haute criticité sur la période.</p>`
          : `<table class="rpt-table">
              <thead>
                <tr>
                  <th>Score</th>
                  <th>Source</th>
                  <th>Date</th>
                  <th>Titre</th>
                  <th>CVE / Tags</th>
                </tr>
              </thead>
              <tbody>
                ${high
                  .sort((a, b) => (b.score || 0) - (a.score || 0))
                  .slice(0, 10)
                  .map(a => `
                  <tr>
                    <td class="rpt-score">${a.score ?? "—"}</td>
                    <td class="rpt-source">${a.sourceIcon || ""} ${a.sourceName}</td>
                    <td class="rpt-date">${a.pubDate.toLocaleDateString("fr-FR")}</td>
                    <td class="rpt-title-cell">
                      <a href="${a.link}">${_esc(a.title)}</a>
                      ${a.isKEV ? `<span class="rpt-badge rpt-badge-kev">KEV</span>` : ""}
                      ${a.isTrending ? `<span class="rpt-badge rpt-badge-trend">🔥</span>` : ""}
                    </td>
                    <td class="rpt-tags">
                      ${(a.cves || []).slice(0, 2).map(c => `<span class="rpt-badge rpt-badge-cve">${c}</span>`).join(" ")}
                      ${(a.attackTags || []).slice(0, 1).map(t => `<span class="rpt-badge rpt-badge-attack">${t.label}</span>`).join("")}
                    </td>
                  </tr>`).join("")}
              </tbody>
            </table>`
        }
      </section>

      <!-- ── TOP CVE ────────────────────────────────────────────────── -->
      ${_buildCVESection(articles)}

      <!-- ── MITRE ATT&CK ───────────────────────────────────────────── -->
      ${_buildAttackSection(articles)}

      <!-- ── SOURCES ────────────────────────────────────────────────── -->
      <section class="rpt-section">
        <h2 class="rpt-section-title">📡 Répartition par Source</h2>
        ${_buildSourcesTable(articles)}
      </section>

      <!-- ── PIED DE PAGE ───────────────────────────────────────────── -->
      <div class="rpt-footer">
        <div>CyberVeille Pro — Rapport confidentiel</div>
        <div>Sources : ${CONFIG.FEEDS.length} flux RSS · Pipeline : Collecter → Enrichir → Dédupliquer → Scorer → Contextualiser</div>
        <div>${new Date().toLocaleDateString("fr-FR", { year:"numeric", month:"long", day:"numeric" })}</div>
      </div>`;
  }

  // ── Section CVE ───────────────────────────────────────────────────────────

  function _buildCVESection(articles) {
    const cveMap = {};
    articles.forEach(a => {
      (a.cves || []).forEach(cve => {
        if (!cveMap[cve]) cveMap[cve] = {
          count: 0, epss: null, isKEV: false,
          cvss: null, sources: new Set(), titles: []
        };
        cveMap[cve].count++;
        cveMap[cve].sources.add(a.sourceName);
        if (a.epssScore != null && (cveMap[cve].epss == null || a.epssScore > cveMap[cve].epss))
          cveMap[cve].epss = a.epssScore;
        if (a.isKEV) cveMap[cve].isKEV = true;
        if (a.score  > (cveMap[cve].cvss || 0)) cveMap[cve].cvss = a.score;
        if (cveMap[cve].titles.length < 2) cveMap[cve].titles.push(a.title);
      });
    });

    const sorted = Object.entries(cveMap)
      .sort((a, b) => (b[1].epss || 0) - (a[1].epss || 0) || b[1].count - a[1].count)
      .slice(0, 12);

    if (!sorted.length) return "";

    return `
      <section class="rpt-section">
        <h2 class="rpt-section-title">🔍 CVE Critiques Détectés</h2>
        <table class="rpt-table">
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>EPSS</th>
              <th>KEV</th>
              <th>Sources</th>
              <th>Contexte</th>
            </tr>
          </thead>
          <tbody>
            ${sorted.map(([cve, info]) => `
            <tr>
              <td><a href="https://nvd.nist.gov/vuln/detail/${cve}" class="rpt-cve-id">${cve}</a></td>
              <td class="rpt-center">${info.epss != null ? (info.epss * 100).toFixed(1) + "%" : "—"}</td>
              <td class="rpt-center">${info.isKEV ? "✅" : "—"}</td>
              <td class="rpt-center">${info.sources.size}</td>
              <td class="rpt-small">${_esc(info.titles[0] || "").slice(0, 80)}${(info.titles[0] || "").length > 80 ? "…" : ""}</td>
            </tr>`).join("")}
          </tbody>
        </table>
      </section>`;
  }

  // ── Section ATT&CK ────────────────────────────────────────────────────────

  function _buildAttackSection(articles) {
    const tactics = {};
    articles.forEach(a => {
      (a.attackTags || []).forEach(t => {
        if (!tactics[t.label]) tactics[t.label] = { count: 0, tactic: t.tactic };
        tactics[t.label].count++;
      });
    });

    const sorted = Object.entries(tactics).sort((a, b) => b[1].count - a[1].count).slice(0, 8);
    if (!sorted.length) return "";

    const max = sorted[0][1].count;

    return `
      <section class="rpt-section rpt-section-half">
        <h2 class="rpt-section-title">🎯 Tactiques MITRE ATT&CK Détectées</h2>
        <table class="rpt-table">
          <thead>
            <tr><th>Tactique</th><th>ID</th><th>Occurrences</th><th>Fréquence</th></tr>
          </thead>
          <tbody>
            ${sorted.map(([label, info]) => `
            <tr>
              <td><strong>${label}</strong></td>
              <td class="rpt-center rpt-small">${info.tactic}</td>
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

  // ── Section Sources ───────────────────────────────────────────────────────

  function _buildSourcesTable(articles) {
    const counts = {};
    articles.forEach(a => { counts[a.sourceName] = (counts[a.sourceName] || 0) + 1; });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const total  = articles.length || 1;

    return `
      <table class="rpt-table">
        <thead>
          <tr><th>Source</th><th>Articles</th><th>%</th><th>Répartition</th></tr>
        </thead>
        <tbody>
          ${sorted.map(([name, count]) => `
          <tr>
            <td>${name}</td>
            <td class="rpt-center">${count}</td>
            <td class="rpt-center">${(count / total * 100).toFixed(1)}%</td>
            <td>
              <div class="rpt-minibar-track">
                <div class="rpt-minibar rpt-minibar-blue" style="width:${Math.round(count / sorted[0][1] * 100)}%"></div>
              </div>
            </td>
          </tr>`).join("")}
        </tbody>
      </table>`;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  function _weekLabel() {
    const now   = new Date();
    const start = new Date(now);
    start.setDate(now.getDate() - 6);
    const fmt = d => d.toLocaleDateString("fr-FR", { day: "2-digit", month: "long" });
    return `Semaine du ${fmt(start)} au ${fmt(now)} ${now.getFullYear()}`;
  }

  function _esc(str) {
    return (str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ── Init ───────────────────────────────────────────────────────────────────

  function init() {
    document.getElementById("btn-pdf")?.addEventListener("click", () => {
      const articles = window._statsLastArticles || [];
      generate(articles);
    });
  }

  return { init, generate };
})();
