// vendor-panel.js — Panneau 🏢 Vendors / Assets exposés
//
// Pure front-end, no API call. Extracts vendor info from state.articles,
// computes per-vendor stats, and renders a collapsible panel.
//
// Pattern identical to health-panel.js : toggle show/hide + lazy render.

const VendorPanel = (() => {

  let _articles          = [];      // dernière liste d'articles reçue
  let _rendered          = false;   // true après le premier rendu
  let _sortBy            = "default"; // tri actif
  let _briefingAvailable = false;   // true si BriefingPanel cache chargé

  // ── Canonical vendor map : variant → canonical name ─────────────────────
  const VENDOR_MAP = [
    { canonical: "Microsoft",    variants: ["microsoft", "windows", "azure", "exchange", "active directory", "sharepoint", "outlook"] },
    { canonical: "Google",       variants: ["google", "chrome", "android", "chromium"] },
    { canonical: "Apple",        variants: ["apple", "ios", "macos", "safari", "iphone", "ipad"] },
    { canonical: "Cisco",        variants: ["cisco", "ios xe", "nx-os", "webex"] },
    { canonical: "Apache",       variants: ["apache", "log4j", "tomcat", "struts"] },
    { canonical: "VMware",       variants: ["vmware", "esxi", "vcenter"] },
    { canonical: "Fortinet",     variants: ["fortinet", "fortigate", "fortios", "forticlient"] },
    { canonical: "Palo Alto",    variants: ["palo alto", "pan-os", "prisma"] },
    { canonical: "Atlassian",    variants: ["atlassian", "confluence", "jira", "bitbucket"] },
    { canonical: "Linux",        variants: ["linux", "ubuntu", "debian", "red hat", "rhel", "kernel"] },
    { canonical: "Oracle",       variants: ["oracle", "java", "weblogic"] },
    { canonical: "Ivanti",       variants: ["ivanti", "mobileiron"] },
    { canonical: "Citrix",       variants: ["citrix", "netscaler"] },
    { canonical: "F5",           variants: ["f5", "big-ip", "nginx"] },
    { canonical: "Juniper",      variants: ["juniper", "junos"] },
    { canonical: "OpenSSL",      variants: ["openssl", "openssh"] },
    { canonical: "CrowdStrike",  variants: ["crowdstrike", "falcon"] },
    { canonical: "Veeam",        variants: ["veeam"] },
    { canonical: "ManageEngine", variants: ["manageengine"] },
    { canonical: "Sophos",       variants: ["sophos"] },
    { canonical: "Check Point",  variants: ["check point", "checkpoint"] },
    { canonical: "Barracuda",    variants: ["barracuda"] },
    { canonical: "SolarWinds",   variants: ["solarwinds"] },
    { canonical: "GitLab",       variants: ["gitlab"] },
    { canonical: "WordPress",    variants: ["wordpress"] },
    { canonical: "SAP",          variants: ["sap"] },
    { canonical: "MOVEit",       variants: ["moveit"] },
  ];

  // ── Criticality ordering ─────────────────────────────────────────────────
  const CRIT_ORDER = { high: 3, medium: 2, low: 1 };

  // ── Helpers ──────────────────────────────────────────────────────────────

  /** Replace non-alphanumeric chars with _, lowercase — for unique IDs. */
  function _slugify(s) {
    return s.toLowerCase().replace(/[^a-z0-9]+/g, "_");
  }

  /** Compute the topic key for an article (same logic as stats.js). */
  function _topicKey(a) {
    // If CVE id present in title or id, use CVE-XXXX-XXXXX as key
    const cveMatch = (a.title || "").match(/CVE-\d{4}-\d+/i);
    if (cveMatch) return cveMatch[0].toUpperCase();
    // Otherwise: first 3 significant words of title (>3 chars)
    const stopWords = new Set(["the","and","for","with","from","this","that","are","was","has","have","been","were","not","but","its","new","via","how","why","what","which","when","les","des","une","dans","sur","qui","que","est","par","aux"]);
    const words = (a.title || "")
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, " ")
      .split(/\s+/)
      .filter(w => w.length > 3 && !stopWords.has(w));
    return words.slice(0, 3).join("_") || a.id || "unknown";
  }

  /**
   * Extract vendor names from a single article.
   * Returns a Set of canonical vendor names.
   */
  function _extractVendors(a) {
    const found = new Set();

    // Priority 1: watchlistMatches
    if (Array.isArray(a.watchlistMatches) && a.watchlistMatches.length > 0) {
      for (const kw of a.watchlistMatches) {
        const kwLower = kw.toLowerCase();
        for (const { canonical, variants } of VENDOR_MAP) {
          if (variants.some(v => kwLower.includes(v) || v.includes(kwLower))) {
            found.add(canonical);
          }
        }
      }
    }

    // Priority 2: article title matching
    const titleLower = (a.title || "").toLowerCase();
    for (const { canonical, variants } of VENDOR_MAP) {
      if (variants.some(v => titleLower.includes(v))) {
        found.add(canonical);
      }
    }

    return found;
  }

  /**
   * Build per-vendor stats from articles.
   * briefingIds : Set<string> | null — IDs des articles top briefing (null = non chargé)
   * Returns array of { name, count, topics, kev, epssMax, critMax, briefingCount, articles, hasWatchlist }
   */
  function _computeVendors(articles, briefingIds) {
    const map = new Map(); // canonical name → stats object

    for (const a of articles) {
      const vendors = _extractVendors(a);
      if (vendors.size === 0) continue;

      const topicKey = _topicKey(a);
      const isWl = Array.isArray(a.watchlistMatches) && a.watchlistMatches.length > 0;

      for (const name of vendors) {
        if (!map.has(name)) {
          map.set(name, {
            name,
            count: 0,
            topics: new Set(),
            kev: 0,
            epssMax: 0,
            critMax: null,
            briefingCount: 0,
            articles: [],
            hasWatchlist: false,
          });
        }
        const s = map.get(name);
        s.count++;
        s.topics.add(topicKey);
        if (a.isKEV) s.kev++;
        if (typeof a.epssScore === "number" && a.epssScore > s.epssMax) s.epssMax = a.epssScore;
        if (a.criticality) {
          if (s.critMax === null || (CRIT_ORDER[a.criticality] || 0) > (CRIT_ORDER[s.critMax] || 0)) {
            s.critMax = a.criticality;
          }
        }
        if (isWl) s.hasWatchlist = true;
        if (briefingIds && briefingIds.has(a.id)) s.briefingCount++;
        s.articles.push(a);
      }
    }

    // Convert topics Set → count, sort articles by criticality desc
    const result = [];
    for (const s of map.values()) {
      result.push({
        name:          s.name,
        count:         s.count,
        topics:        s.topics.size,
        kev:           s.kev,
        epssMax:       s.epssMax,
        critMax:       s.critMax || "low",
        briefingCount: s.briefingCount,
        articles:      s.articles,
        hasWatchlist:  s.hasWatchlist,
      });
    }

    // Sort selon _sortBy
    result.sort((a, b) => {
      const dc = (CRIT_ORDER[b.critMax] || 0) - (CRIT_ORDER[a.critMax] || 0);
      if (_sortBy === "kev")      return b.kev - a.kev || dc || b.count - a.count;
      if (_sortBy === "epss")     return b.epssMax - a.epssMax || b.kev - a.kev || dc;
      if (_sortBy === "topics")   return b.topics - a.topics || dc || b.count - a.count;
      if (_sortBy === "briefing") return b.briefingCount - a.briefingCount || dc || b.kev - a.kev;
      // default : critMax → kev → count
      if (dc !== 0) return dc;
      if (b.kev !== a.kev) return b.kev - a.kev;
      return b.count - a.count;
    });

    return result;
  }

  // ── Visibility ────────────────────────────────────────────────────────────
  function _isVisible() {
    return document.getElementById("vendor-panel")?.style.display !== "none";
  }

  // ── Public API ────────────────────────────────────────────────────────────

  function init() { /* lazy — nothing to do */ }

  function toggle() {
    const panel = document.getElementById("vendor-panel");
    const btn   = document.getElementById("btn-vendors");
    if (!panel) return;

    const nowVisible = !_isVisible();
    panel.style.display = nowVisible ? "block" : "none";
    btn?.classList.toggle("active", nowVisible);

    if (nowVisible && !_rendered) _render();
  }

  function update(articles) {
    _articles = articles || [];
    if (_isVisible()) _render();
  }

  // ── Render ────────────────────────────────────────────────────────────────
  function _render() {
    const listEl = document.getElementById("vendor-list");
    const metaEl = document.getElementById("vendor-meta");
    if (!listEl) return;

    // Récupérer les IDs briefing (null = non chargé → fallback propre)
    const briefingIds = (typeof BriefingPanel !== "undefined" && typeof BriefingPanel.getTopIds === "function")
      ? BriefingPanel.getTopIds()
      : null;
    _briefingAvailable = briefingIds !== null;

    const vendors = _computeVendors(_articles, briefingIds);
    _rendered = true;

    if (metaEl) {
      if (!vendors.length) {
        metaEl.innerHTML = "";
      } else {
        const globalEpssMax  = vendors.reduce((m, v) => Math.max(m, v.epssMax), 0);
        const vendorsWithKev = vendors.filter(v => v.kev > 0).length;
        const briefingKpiVal = _briefingAvailable
          ? vendors.filter(v => v.briefingCount > 0).length
          : "—";
        const epssStr = globalEpssMax > 0 ? `${(globalEpssMax * 100).toFixed(0)} %` : "—";
        metaEl.innerHTML = `<div class="vp-kpi-bar">
  <span class="vp-kpi"><span class="vp-kpi-val">${vendors.length}</span><span class="vp-kpi-lbl">vendors détectés</span></span>
  <span class="vp-kpi"><span class="vp-kpi-val">${briefingKpiVal}</span><span class="vp-kpi-lbl">dans le briefing</span></span>
  <span class="vp-kpi"><span class="vp-kpi-val">${vendorsWithKev}</span><span class="vp-kpi-lbl">avec KEV</span></span>
  <span class="vp-kpi"><span class="vp-kpi-val">${epssStr}</span><span class="vp-kpi-lbl">EPSS max global</span></span>
</div>`;
      }
    }

    if (vendors.length === 0) {
      listEl.innerHTML = '<div class="vp-empty">Aucun vendor détecté dans les articles courants.</div>';
      return;
    }

    const hint = !_briefingAvailable
      ? '<span class="vp-sort-hint">Briefing non chargé — ouvre l\'onglet Briefing d\'abord</span>'
      : '';
    const sortBar = `<div class="vp-sort-bar">
  <label class="vp-sort-label">Tri :</label>
  <select id="vp-sort-select" class="vp-sort-select">
    <option value="default"  ${_sortBy==="default" ?"selected":""}>Criticité (défaut)</option>
    <option value="kev"      ${_sortBy==="kev"     ?"selected":""}>KEV</option>
    <option value="epss"     ${_sortBy==="epss"    ?"selected":""}>EPSS max</option>
    <option value="topics"   ${_sortBy==="topics"  ?"selected":""}>Sujets uniques</option>
    <option value="briefing" ${_sortBy==="briefing"?"selected":""}>Présence briefing</option>
  </select>
  ${hint}
</div>`;

    listEl.innerHTML = sortBar + vendors.map(v => _renderVendorCard(v)).join("");

    // Tri : changement de l'option
    document.getElementById("vp-sort-select")?.addEventListener("change", e => {
      _sortBy = e.target.value;
      _render();
    });

    // Attach click handlers for expand/collapse
    listEl.querySelectorAll(".vp-row").forEach(row => {
      row.addEventListener("click", () => _toggleDetail(row.dataset.slug));
    });
  }

  function _renderVendorCard(v) {
    const slug = _slugify(v.name);
    const critClass = v.critMax === "high" ? "vp-crit-high"
                    : v.critMax === "medium" ? "vp-crit-med"
                    : "vp-crit-low";
    const critLabel = v.critMax === "high"   ? '<span class="vp-crit-badge" style="color:var(--crit-high,#f87171)">🔴 HIGH</span>'
                    : v.critMax === "medium" ? '<span class="vp-crit-badge" style="color:var(--crit-med,#fbbf24)">🟡 MEDIUM</span>'
                    : '<span class="vp-crit-badge" style="color:var(--text-muted)">🟢 LOW</span>';

    const badges = [];
    if (v.kev > 0)                             badges.push(`<span class="vp-badge vp-kev">KEV ×${v.kev}</span>`);
    if (v.epssMax > 0)                         badges.push(`<span class="vp-badge vp-epss">EPSS ${(v.epssMax * 100).toFixed(0)}%</span>`);
    if (_briefingAvailable && v.briefingCount > 0) badges.push(`<span class="vp-badge vp-briefing">📬 ${v.briefingCount}</span>`);
    if (v.hasWatchlist)                        badges.push(`<span class="vp-badge vp-wl">👁 Watchlist</span>`);

    const detailHtml = _renderDetail(v, slug);

    return `
<div class="vp-card ${critClass}">
  <div class="vp-row" data-slug="${slug}">
    <span class="vp-name">${v.name}</span>
    <span class="vp-badges">${badges.join("") || ""}</span>
    <span class="vp-meta">
      <span class="vp-stat">📄 ${v.count}</span>
      <span class="vp-stat">🔑 ${v.topics}</span>
      ${critLabel}
    </span>
    <span class="vp-chevron">▶</span>
  </div>
  <div class="vp-detail" id="vp-detail-${slug}" style="display:none">
    ${detailHtml}
  </div>
</div>`;
  }

  function _renderDetail(v, slug) {
    // Sort articles by criticality desc
    const sorted = [...v.articles].sort((a, b) => {
      return (CRIT_ORDER[b.criticality] || 0) - (CRIT_ORDER[a.criticality] || 0);
    });

    return sorted.map(a => {
      const critIcon = a.criticality === "high"   ? '<span class="vp-ac" style="color:var(--crit-high,#f87171)">🔴</span>'
                     : a.criticality === "medium" ? '<span class="vp-ac" style="color:var(--crit-med,#fbbf24)">🟡</span>'
                     : '<span class="vp-ac" style="color:var(--text-muted)">🟢</span>';
      const kevBadge  = a.isKEV ? ' <span class="vp-badge vp-kev">KEV</span>' : "";
      const epssBadge = (typeof a.epssScore === "number" && a.epssScore > 0)
        ? ` <span class="vp-badge vp-epss">EPSS ${(a.epssScore * 100).toFixed(0)}%</span>` : "";
      const srcName   = a.source || a.feedName || "";

      return `<div class="vp-article">
  ${critIcon}
  <a class="vp-article-title" href="${a.link || "#"}" target="_blank" rel="noopener noreferrer">${_escHtml(a.title || "Sans titre")}</a>
  ${kevBadge}${epssBadge}
  ${srcName ? `<span class="vp-article-src">${_escHtml(srcName)}</span>` : ""}
</div>`;
    }).join("");
  }

  function _toggleDetail(slug) {
    const detailEl = document.getElementById(`vp-detail-${slug}`);
    const row = document.querySelector(`.vp-row[data-slug="${slug}"]`);
    if (!detailEl || !row) return;

    const isOpen = detailEl.style.display !== "none";
    detailEl.style.display = isOpen ? "none" : "flex";
    row.classList.toggle("vp-row-open", !isOpen);
  }

  function _escHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  return { init, toggle, update };
})();
