// stats.js — Dashboard statistiques CyberVeille Pro
// Zéro dépendance externe : charts en Canvas API natif
//
// Affiche :
//   • 8 KPI cards  : total, HIGH, MEDIUM, KEV, EPSS moyen, trending, watchlist, score moy.
//   • Donut SVG    : distribution criticité
//   • Bar canvas   : articles par source
//   • Line canvas  : timeline 7 jours (total + HIGH)
//   • ATT&CK bars  : top tactiques (CSS)
//   • Top CVEs     : liste enrichie

const StatsPanel = (() => {

  // ── Vérifie si le panneau est visible (lecture DOM, pas variable closure) ──

  function _isVisible() {
    return document.getElementById("stats-panel")?.style.display !== "none";
  }

  // ── Toggle ─────────────────────────────────────────────────────────────────

  function toggle() {
    const panel = document.getElementById("stats-panel");
    const btn   = document.getElementById("btn-stats");
    if (!panel) return;

    const nowVisible = !_isVisible();
    panel.style.display = nowVisible ? "block" : "none";
    btn?.classList.toggle("active", nowVisible);

    if (nowVisible && window._statsLastArticles?.length) {
      _render(window._statsLastArticles);
    }
  }

  // ── Point d'entrée public ─────────────────────────────────────────────────

  function update(articles) {
    window._statsLastArticles = articles;
    if (!_isVisible()) return;
    _render(articles);
  }

  function _render(articles) {
    _renderKPIs(articles);
    _renderDigestKPIs(articles);
    _renderDonut(articles);
    _renderSourceBars(articles);
    _renderTimeline(articles);
    _renderAttackList(articles);
    _renderTopCVEs(articles);
  }

  // ── KPI cards ──────────────────────────────────────────────────────────────

  function _renderKPIs(articles) {
    const high    = articles.filter(a => a.criticality === "high").length;
    const medium  = articles.filter(a => a.criticality === "medium").length;
    const kev     = articles.filter(a => a.isKEV).length;
    const trending= articles.filter(a => a.isTrending).length;
    const watch   = articles.filter(a => a.watchlistMatches?.length > 0).length;
    const epssArr = articles.map(a => a.epssScore).filter(s => s != null);
    const epssAvg = epssArr.length
      ? (epssArr.reduce((a, b) => a + b, 0) / epssArr.length * 100).toFixed(1) + "%"
      : "—";
    const scoreArr  = articles.map(a => a.score).filter(s => s != null);
    const avgScore  = scoreArr.length
      ? Math.round(scoreArr.reduce((a, b) => a + b, 0) / scoreArr.length)
      : "—";

    _set("kpi-total",    articles.length);
    _set("kpi-high",     high);
    _set("kpi-medium",   medium);
    _set("kpi-kev",      kev);
    _set("kpi-epss",     epssAvg);
    _set("kpi-trending", trending);
    _set("kpi-watch",    watch);
    _set("kpi-score",    avgScore);
  }

  function _set(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  // ── KPI digest (qualité moteur) ────────────────────────────────────────────
  // Stop-words identiques à scheduled-digest.js pour des clés de sujet cohérentes
  const _DIGEST_STOP = new Set([
    "the","a","an","in","of","to","for","and","or","is","are","was","were","be",
    "with","how","new","update","patch","patches","patched","fix","fixes","fixed",
    "security","advisory","vulnerability","vulnerabilities","vuln","cve","exploit",
    "exploited","exploiting","critical","high","severe","alert","warning","report",
    "attack","attacks","threat","threats","flaw","flaws","bug","bugs","issue"
  ]);

  /**
   * Calcule les stats de topic grouping léger sur les articles front.
   * Même algorithme que scheduled-digest.js _topicKey / _groupByTopic.
   * @returns {{ unique, merged, avgSize }}
   */
  function _topicStats(articles) {
    const groups = new Map();
    for (const a of articles) {
      let key;
      const cves = a.cveIds || a.cves || [];
      if (cves.length > 0) {
        key = "cve:" + [...cves].map(c => c.toUpperCase()).sort().slice(0, 2).join("+");
      } else {
        const tokens = (a.title || "").toLowerCase()
          .replace(/[^a-z0-9 ]/g, " ").split(/\s+/)
          .filter(w => w.length >= 3 && !_DIGEST_STOP.has(w)).slice(0, 4).join("-") || "misc";
        key = "title:" + tokens;
      }
      groups.set(key, (groups.get(key) || 0) + 1);
    }
    const sizes   = [...groups.values()];
    const total   = sizes.reduce((s, v) => s + v, 0) || 1;
    const merged  = sizes.filter(s => s > 1).length;
    const avgSize = sizes.length ? (total / sizes.length).toFixed(1) : "—";
    return { unique: groups.size, merged, avgSize };
  }

  function _renderDigestKPIs(articles) {
    // Éligibles digest : articles non "low" (pool que le moteur considère)
    const eligible = articles.filter(a => a.criticality !== "low").length;

    // Topic grouping léger
    const { unique: topicUnique, merged, avgSize } = _topicStats(articles);

    // Enrichissement : au moins un signal réel (KEV, EPSS, CVSS)
    const enriched    = articles.filter(a => a.isKEV || a.epssScore != null || a.cvssScore != null).length;
    const notEnriched = articles.length - enriched;

    // CVEs uniques extraits
    const allCves = new Set();
    articles.forEach(a => (a.cveIds || a.cves || []).forEach(c => allCves.add(c.toUpperCase())));

    // Flux en erreur (via FeedManager si disponible)
    let feedErr = "—";
    try {
      if (typeof FeedManager !== "undefined") {
        feedErr = FeedManager.getAllFeeds().filter(f => f.lastStatus === "error").length;
      }
    } catch (_) {}

    _set("kpi-eligible",  eligible);
    _set("kpi-topics",    topicUnique);
    _set("kpi-grouped",   merged);
    _set("kpi-enriched",  enriched);
    _set("kpi-cves",      allCves.size);
    _set("kpi-feed-err",  feedErr);

    // Sous-labels dynamiques
    const avgEl    = document.getElementById("kpi-topics-sub");
    if (avgEl)      avgEl.textContent = avgSize !== "—" ? `moy. ${avgSize} art./sujet` : "";
    const enrichEl = document.getElementById("kpi-enriched-sub");
    if (enrichEl)   enrichEl.textContent = `${notEnriched} non enrichis`;
  }

  // ── Donut SVG (criticité) ─────────────────────────────────────────────────

  function _renderDonut(articles) {
    const el = document.getElementById("chart-crit");
    if (!el) return;

    const h = articles.filter(a => a.criticality === "high").length;
    const m = articles.filter(a => a.criticality === "medium").length;
    const l = articles.filter(a => a.criticality === "low").length;
    const total = h + m + l || 1;

    const R = 60, CX = 80, CY = 80, STROKE = 22;
    const circ = 2 * Math.PI * R;

    const segments = [
      { val: h, color: "#f85149", label: "HIGH" },
      { val: m, color: "#f0883e", label: "MEDIUM" },
      { val: l, color: "#3fb950", label: "LOW" }
    ];

    let offset = 0;
    const arcs = segments.map(seg => {
      const pct   = seg.val / total;
      const dash  = pct * circ;
      const gap   = circ - dash;
      // SVG stroke-dashoffset rotates starting point
      const arc   = `<circle cx="${CX}" cy="${CY}" r="${R}"
        fill="none" stroke="${seg.color}" stroke-width="${STROKE}"
        stroke-dasharray="${dash.toFixed(2)} ${gap.toFixed(2)}"
        stroke-dashoffset="${(-offset * circ / (2 * Math.PI * R) * circ + circ / 4).toFixed(2)}"
        transform="rotate(-90 ${CX} ${CY})"
        style="stroke-dashoffset: ${(circ / 4 - offset * circ).toFixed(2)}"
      />`;
      offset += dash;
      return arc;
    });

    // Légende
    const legend = segments.map(seg => `
      <div style="display:flex;align-items:center;gap:.3rem;font-size:.68rem;color:#8b949e">
        <span style="width:10px;height:10px;border-radius:2px;background:${seg.color};flex-shrink:0"></span>
        ${seg.label} <strong style="color:${seg.color}">${seg.val}</strong>
      </div>`).join("");

    el.innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;gap:.6rem">
        <svg width="160" height="160" viewBox="0 0 160 160">
          <circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="#21262d" stroke-width="${STROKE}"/>
          ${_donutArcs(segments, R, CX, CY, STROKE, total)}
          <text x="${CX}" y="${CY - 6}" text-anchor="middle" fill="#e6edf3" font-size="20" font-weight="700">${total}</text>
          <text x="${CX}" y="${CY + 14}" text-anchor="middle" fill="#8b949e" font-size="10">articles</text>
        </svg>
        <div style="display:flex;gap:.8rem;flex-wrap:wrap;justify-content:center">${legend}</div>
      </div>`;
  }

  function _donutArcs(segments, R, CX, CY, STROKE, total) {
    const circ = 2 * Math.PI * R;
    let startAngle = -Math.PI / 2; // start at top
    return segments.map(seg => {
      if (!seg.val) return "";
      const angle = (seg.val / total) * 2 * Math.PI;
      const x1 = CX + R * Math.cos(startAngle);
      const y1 = CY + R * Math.sin(startAngle);
      const x2 = CX + R * Math.cos(startAngle + angle);
      const y2 = CY + R * Math.sin(startAngle + angle);
      const largeArc = angle > Math.PI ? 1 : 0;
      const path = `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${R} ${R} 0 ${largeArc} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
      startAngle += angle;
      return `<path d="${path}" fill="none" stroke="${seg.color}" stroke-width="${STROKE}" stroke-linecap="butt"/>`;
    }).join("");
  }

  // ── Bar chart sources (canvas natif) ─────────────────────────────────────

  function _renderSourceBars(articles) {
    const canvas = document.getElementById("chart-source");
    if (!canvas) return;

    const counts = {};
    articles.forEach(a => { counts[a.sourceName] = (counts[a.sourceName] || 0) + 1; });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    if (!sorted.length) return;

    const W = canvas.width  = canvas.offsetWidth  || 280;
    const H = canvas.height = 160;
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, W, H);

    const padL = 10, padR = 10, padT = 10, padB = 36;
    const chartW = W - padL - padR;
    const chartH = H - padT - padB;
    const maxVal = sorted[0][1];
    const barW   = Math.floor(chartW / sorted.length) - 6;

    const feedColors = {
      "The Hacker News":       "#f85149",
      "Krebs on Security":     "#58a6ff",
      "Bleeping Computer":     "#bc8cff",
      "Zataz":                 "#f0883e",
      "CERT-FR":               "#3fb950",
      "CISA Alerts":           "#e3b341",
      "Zero Day Initiative":   "#ff6b6b",
      "Exploit-DB":            "#ff9f43",
      "Packet Storm":          "#feca57",
      "Cisco Talos":           "#1dd1a1",
      "Securelist (Kaspersky)":"#54a0ff",
      "Unit 42 (Palo Alto)":   "#5f27cd",
      "NCSC UK":               "#48dbfb"
    };

    sorted.forEach(([name, count], i) => {
      const x   = padL + i * (chartW / sorted.length) + 3;
      const barH = Math.max(2, Math.round(count / maxVal * chartH));
      const y   = padT + chartH - barH;
      const col = feedColors[name] || "#58a6ff";

      // Barre
      ctx.fillStyle = col + "cc";
      ctx.beginPath();
      ctx.roundRect(x, y, barW, barH, 3);
      ctx.fill();

      // Valeur au-dessus
      ctx.fillStyle = "#e6edf3";
      ctx.font = "bold 11px monospace";
      ctx.textAlign = "center";
      ctx.fillText(count, x + barW / 2, y - 3);

      // Label source (abrégé) en bas
      ctx.fillStyle = "#8b949e";
      ctx.font = "9px monospace";
      const shortName = name.split(" ")[0];
      ctx.fillText(shortName, x + barW / 2, H - 4);
    });

    // Ligne de base
    ctx.strokeStyle = "#30363d";
    ctx.lineWidth   = 1;
    ctx.beginPath();
    ctx.moveTo(padL, padT + chartH);
    ctx.lineTo(W - padR, padT + chartH);
    ctx.stroke();
  }

  // ── Line chart timeline 7j (canvas natif) ────────────────────────────────

  function _renderTimeline(articles) {
    const canvas = document.getElementById("chart-timeline");
    if (!canvas) return;

    // Construire 7 derniers jours
    const days   = [];
    const labels = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      days.push(d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" }));
      labels.push(i === 0 ? "Auj." : d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" }));
    }

    const all  = Object.fromEntries(days.map(d => [d, 0]));
    const high = Object.fromEntries(days.map(d => [d, 0]));
    articles.forEach(a => {
      const label = a.pubDate.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" });
      if (label in all) {
        all[label]++;
        if (a.criticality === "high") high[label]++;
      }
    });

    const allVals  = days.map(d => all[d]);
    const highVals = days.map(d => high[d]);

    const W   = canvas.width  = canvas.offsetWidth || 280;
    const H   = canvas.height = 160;
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, W, H);

    const padL = 24, padR = 10, padT = 14, padB = 22;
    const chartW = W - padL - padR;
    const chartH = H - padT - padB;
    const maxVal = Math.max(...allVals, 1);
    const step   = chartW / (days.length - 1);

    function xOf(i)   { return padL + i * step; }
    function yOf(val) { return padT + chartH - (val / maxVal * chartH); }

    // Grille horizontale
    ctx.strokeStyle = "#21262d";
    ctx.lineWidth = 1;
    [0.25, 0.5, 0.75, 1].forEach(pct => {
      const y = padT + chartH * (1 - pct);
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
      ctx.fillStyle = "#8b949e"; ctx.font = "9px monospace"; ctx.textAlign = "right";
      ctx.fillText(Math.round(maxVal * pct), padL - 3, y + 3);
    });

    // Dessiner une ligne lissée
    function drawLine(vals, color, fill) {
      ctx.beginPath();
      vals.forEach((v, i) => i === 0 ? ctx.moveTo(xOf(i), yOf(v)) : ctx.lineTo(xOf(i), yOf(v)));

      if (fill) {
        ctx.lineTo(xOf(vals.length - 1), padT + chartH);
        ctx.lineTo(xOf(0), padT + chartH);
        ctx.closePath();
        ctx.fillStyle = color + "22";
        ctx.fill();
        ctx.beginPath();
        vals.forEach((v, i) => i === 0 ? ctx.moveTo(xOf(i), yOf(v)) : ctx.lineTo(xOf(i), yOf(v)));
      }

      ctx.strokeStyle = color;
      ctx.lineWidth   = 2;
      ctx.lineJoin    = "round";
      ctx.stroke();

      // Points
      vals.forEach((v, i) => {
        ctx.beginPath();
        ctx.arc(xOf(i), yOf(v), 3, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
      });
    }

    drawLine(allVals,  "#58a6ff", true);
    drawLine(highVals, "#f85149", false);

    // Labels X
    ctx.fillStyle = "#8b949e"; ctx.font = "9px monospace"; ctx.textAlign = "center";
    days.forEach((_, i) => ctx.fillText(labels[i], xOf(i), H - 4));

    // Légende
    const legItems = [["Total", "#58a6ff"], ["HIGH", "#f85149"]];
    legItems.forEach(([lbl, col], i) => {
      const lx = padL + i * 70;
      ctx.fillStyle = col;
      ctx.fillRect(lx, 3, 12, 6);
      ctx.fillStyle = "#8b949e"; ctx.font = "9px monospace"; ctx.textAlign = "left";
      ctx.fillText(lbl, lx + 15, 10);
    });
  }

  // ── ATT&CK top tactics (CSS bars) ────────────────────────────────────────

  function _renderAttackList(articles) {
    const el = document.getElementById("attack-list");
    if (!el) return;

    const tactics = {};
    articles.forEach(a => {
      (a.attackTags || []).forEach(t => { tactics[t.label] = (tactics[t.label] || 0) + 1; });
    });

    const sorted = Object.entries(tactics).sort((a, b) => b[1] - a[1]).slice(0, 7);
    if (!sorted.length) {
      el.innerHTML = `<span style="color:var(--text2);font-size:.75rem">Aucune tactique détectée</span>`;
      return;
    }

    const max = sorted[0][1];
    el.innerHTML = sorted.map(([label, count]) => `
      <div class="attack-row">
        <span class="attack-label">${label}</span>
        <div class="attack-bar-track">
          <div class="attack-bar" style="width:${Math.round(count / max * 100)}%"></div>
        </div>
        <span class="attack-count">${count}</span>
      </div>`).join("");
  }

  // ── Top CVEs ──────────────────────────────────────────────────────────────

  function _renderTopCVEs(articles) {
    const el = document.getElementById("top-cves");
    if (!el) return;

    const cveMap = {};
    articles.forEach(a => {
      (a.cves || []).forEach(cve => {
        if (!cveMap[cve]) cveMap[cve] = { count: 0, epss: null, isKEV: false };
        cveMap[cve].count++;
        if (a.epssScore != null && (cveMap[cve].epss == null || a.epssScore > cveMap[cve].epss))
          cveMap[cve].epss = a.epssScore;
        if (a.isKEV) cveMap[cve].isKEV = true;
      });
    });

    const sorted = Object.entries(cveMap)
      .sort((a, b) => (b[1].epss || 0) - (a[1].epss || 0) || b[1].count - a[1].count)
      .slice(0, 6);

    if (!sorted.length) {
      el.innerHTML = `<span style="color:var(--text2);font-size:.75rem">Aucun CVE détecté</span>`;
      return;
    }

    el.innerHTML = sorted.map(([cve, info]) => `
      <div class="cve-row">
        <a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" class="cve-id">${cve}</a>
        ${info.isKEV ? `<span class="badge badge-kev" style="font-size:.6rem;padding:.05rem .3rem">KEV</span>` : ""}
        ${info.epss != null ? `<span class="badge badge-epss" style="font-size:.6rem;padding:.05rem .3rem">EPSS ${(info.epss*100).toFixed(1)}%</span>` : ""}
      </div>`).join("");
  }

  // ── Init ───────────────────────────────────────────────────────────────────

  function init() {
    document.getElementById("btn-stats")?.addEventListener("click", toggle);

    // Redessiner les canvas si la fenêtre est redimensionnée
    window.addEventListener("resize", () => {
      if (_isVisible() && window._statsLastArticles?.length) {
        _renderSourceBars(window._statsLastArticles);
        _renderTimeline(window._statsLastArticles);
      }
    });
  }

  return { init, toggle, update };
})();
