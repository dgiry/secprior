// incident-panel.js — Panneau 🎯 Vue Incidents Consolidés (V1)
//
// Agrège les articles en incidents via Union-Find :
//   Phase 1 — CVE-based : articles partageant une CVE → même incident
//   Phase 2 — relatedArticles : liens calculés par deduplicator.js → même incident
//
// Aucun recalcul coûteux — réutilise les métadonnées déjà produites
// par le pipeline (cves, relatedArticles, vendors, isKEV, epssScore, …)
//
// Pattern identique à cve-panel.js et vendor-panel.js.

const IncidentPanel = (() => {

  let _articles      = [];    // dernière liste d'articles reçue
  let _filterBy      = "all"; // "all"|"multi"|"kev"|"watchlist"|"exploit"|"patch"|"high"|"ioc"
  let _searchQuery   = "";    // filtre texte libre
  let _statusFilter  = "all"; // "all" | EntityStatus.VALID_STATUSES
  let _lastIncidents = [];    // cache pour export IOC au clic

  // ── Catégorisation d'angle (synchronisée avec cve-panel.js) ───────────────

  function _classifyAngle(a) {
    const text = ((a.title || "") + " " + (a.description || "")).toLowerCase();
    if (/\b(poc|proof.of.concept|proof of concept|working exploit|demo exploit)\b/.test(text))
      return "poc";
    if (/\b(exploit|actively exploit|in the wild|being exploit|mass exploit|ransomware|campaign|attack)\b/.test(text))
      return "exploitation";
    if (/\b(patch|fix|hotfix|update|upgrade|correc|mitigation|workaround|remediat)\b/.test(text))
      return "patch";
    if (/\b(advisory|warn|disclose|discloses|reveals|discover|found|announce|publishes|alert)\b/.test(text))
      return "advisory";
    return "news";
  }

  const _ANGLE_META = {
    poc:          { label: "PoC",      color: "#f85149", bg: "#2d1515" },
    exploitation: { label: "Exploit",  color: "#f85149", bg: "#2d1515" },
    patch:        { label: "Patch",    color: "#3fb950", bg: "#0d2818" },
    advisory:     { label: "Advisory", color: "#79c0ff", bg: "#0d1b2e" },
    news:         { label: "News",     color: "#8b949e", bg: "#21262d" }
  };

  function _dominantAngle(angles) {
    const order = ["exploitation", "poc", "patch", "advisory", "news"];
    return order.find(p => angles.includes(p)) || "news";
  }

  // ── Union-Find léger ──────────────────────────────────────────────────────

  function _makeUF(ids) {
    const p = new Map(ids.map(id => [id, id]));
    function find(id) {
      if (!p.has(id)) return id;
      if (p.get(id) !== id) p.set(id, find(p.get(id)));
      return p.get(id);
    }
    function union(a, b) {
      const ra = find(a), rb = find(b);
      if (ra !== rb) p.set(ra, rb);
    }
    return { find, union };
  }

  // ── Agrégation principale ─────────────────────────────────────────────────

  /**
   * buildIncidentIndex(articles) → Incident[]
   *
   * Regroupe les articles en incidents via deux signaux :
   *   1. CVE partagée       → forte confiance
   *   2. relatedArticles[]  → confiance deduplicator (same-cve-distinct-title, etc.)
   *
   * V1 prudente : on ne fusionne que sur signal explicite.
   * Les articles sans CVE ni lien restent des incidents solo.
   */
  function buildIncidentIndex(articles) {
    if (!articles.length) return [];

    const artMap = new Map(articles.map(a => [a.id, a]));
    const uf     = _makeUF(articles.map(a => a.id));

    // Phase 1 : Union par CVE partagée
    const cveFirst = new Map();
    articles.forEach(a => {
      (a.cveIds || a.cves || []).forEach(cve => {
        const key = cve.toUpperCase();
        if (cveFirst.has(key)) uf.union(a.id, cveFirst.get(key));
        else                   cveFirst.set(key, a.id);
      });
    });

    // Phase 2 : Union par relatedArticles (deduplicator.js)
    articles.forEach(a => {
      (a.relatedArticles || []).forEach(relId => {
        if (artMap.has(relId)) uf.union(a.id, relId);
      });
    });

    // Phase 3 : Union par vendor + attackTag dans une fenêtre de 7 jours
    // Cible : articles sans CVE couvrant la même surface d'attaque à courte distance.
    // Ex. : "Cisco — exploitation active" + "Patch Cisco Remote Exec." → même incident.
    // L'index est mis à jour vers l'article le plus récent pour permettre le chaînage.
    const vatIndex = new Map(); // "vendor|attacktag" → { id, date }
    articles.forEach(a => {
      if ((a.cveIds || a.cves || []).length > 0) return; // déjà traités en phase 1
      const aDate   = a.pubDate instanceof Date ? a.pubDate : new Date(a.pubDate || 0);
      const vendors = a.vendors || [];
      const attacks = (a.attackTags || []).map(t => t.label);
      vendors.forEach(v => {
        attacks.forEach(atk => {
          const key  = v.toLowerCase() + "|" + atk.toLowerCase();
          const prev = vatIndex.get(key);
          if (prev) {
            const diffDays = Math.abs(aDate - prev.date) / 86_400_000;
            if (diffDays <= 7) {
              uf.union(a.id, prev.id);
              // Avance l'index vers le plus récent pour permettre le chaînage
              if (aDate > prev.date) vatIndex.set(key, { id: a.id, date: aDate });
            }
            // Si > 7 jours : on ne fusionne pas mais on remplace l'index par cet article
            // pour ne pas bloquer les regroupements futurs sur la même clé
            else if (aDate > prev.date) {
              vatIndex.set(key, { id: a.id, date: aDate });
            }
          } else {
            vatIndex.set(key, { id: a.id, date: aDate });
          }
        });
      });
    });

    // Phase 4 : Grouper par racine Union-Find
    const groups = new Map();
    articles.forEach(a => {
      const root = uf.find(a.id);
      if (!groups.has(root)) groups.set(root, []);
      groups.get(root).push(a);
    });

    return [...groups.values()]
      .map(_makeIncident)
      .sort(_incidentSort);
  }

  function _makeIncident(arts) {
    // Timeline : plus récent en tête
    const sorted = [...arts].sort((a, b) => {
      const da = a.pubDate instanceof Date ? a.pubDate : new Date(a.pubDate || 0);
      const db = b.pubDate instanceof Date ? b.pubDate : new Date(b.pubDate || 0);
      return db - da;
    });

    const cves         = [...new Set(arts.flatMap(a => (a.cveIds || a.cves || []).map(c => c.toUpperCase())))];
    const vendors      = [...new Set(arts.flatMap(a => a.vendors || []))].slice(0, 5);
    const sources      = [...new Set(arts.map(a => a.sourceName || "?"))];
    const maxScore     = arts.reduce((m, a) => Math.max(m, a.score ?? 0), 0);
    const maxEpss      = arts.reduce((m, a) => a.epssScore != null && a.epssScore > (m ?? -1) ? a.epssScore : m, null);
    const kev          = arts.some(a => a.isKEV);
    const watchlistHit = arts.some(a => a.watchlistMatches?.length > 0);
    const trending     = arts.some(a => a.isTrending);
    const attackTags   = [...new Set(arts.flatMap(a => (a.attackTags || []).map(t => t.label)))];
    const angles       = [...new Set(arts.map(_classifyAngle))];

    const dates = arts
      .map(a => a.pubDate instanceof Date ? a.pubDate : (a.pubDate ? new Date(a.pubDate) : null))
      .filter(d => d && !isNaN(d));
    const firstSeen = dates.length ? new Date(Math.min(...dates.map(d => d.getTime()))).toISOString() : null;
    const lastSeen  = dates.length ? new Date(Math.max(...dates.map(d => d.getTime()))).toISOString() : null;

    const title = _makeTitle(cves, vendors, angles, sorted[0]);

    // ID stable : CVE principale ou vendor+date
    const slug = (cves[0] || `${vendors[0] || "unknown"}-${(lastSeen || "").slice(0, 10)}`)
      .toLowerCase().replace(/[^a-z0-9]/g, "-").replace(/-+/g, "-").slice(0, 44);
    const incidentId = `inc_${slug}`;

    // Comptage brut des IOCs (somme articles, doublons possibles — utilisé pour filtre/badge)
    const rawIocCount = arts.reduce((n, a) => n + (a.iocCount || 0), 0);

    return {
      incidentId, title,
      articleCount: arts.length, sourceCount: sources.length,
      articles: sorted, cves, vendors, sources,
      maxScore, maxEpss, kev, watchlistHit, trending, attackTags, angles,
      firstSeen, lastSeen, rawIocCount
    };
  }

  function _makeTitle(cves, vendors, angles, primaryArticle) {
    const dominant = _dominantAngle(angles);
    const angleLabel = {
      exploitation: "exploitation active",
      poc:          "PoC publié",
      patch:        "correctif disponible",
      advisory:     "advisory"
    };

    if (cves.length > 0 && vendors.length > 0) return `${vendors[0]} — ${cves[0]}`;
    if (cves.length > 0) return cves.length > 1 ? `${cves[0]} +${cves.length - 1}` : cves[0];
    if (vendors.length > 0) {
      const suffix = dominant !== "news" ? ` — ${angleLabel[dominant] || dominant}` : "";
      return vendors.length > 1 ? `${vendors[0]} / ${vendors[1]}${suffix}` : `${vendors[0]}${suffix}`;
    }
    return (primaryArticle?.title || "Incident").slice(0, 70);
  }

  function _incidentSort(a, b) {
    if (a.kev !== b.kev)                   return a.kev ? -1 : 1;
    if (b.articleCount !== a.articleCount) return b.articleCount - a.articleCount;
    if (b.maxScore !== a.maxScore)         return b.maxScore - a.maxScore;
    return new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0);
  }

  // ── Helpers UI ────────────────────────────────────────────────────────────

  function _fmtDate(iso) {
    if (!iso) return "—";
    try { return new Date(iso).toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" }); }
    catch { return "—"; }
  }

  function _fmtDateTime(pubDate) {
    const d = pubDate instanceof Date ? pubDate : (pubDate ? new Date(pubDate) : null);
    if (!d || isNaN(d)) return "—";
    return d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" })
         + " " + d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
  }

  // ── Rendu ─────────────────────────────────────────────────────────────────

  function _render() {
    const list = document.getElementById("incident-list");
    if (!list) return;

    const allIncidents = buildIncidentIndex(_articles);
    _lastIncidents = allIncidents; // cache pour export IOC
    let incidents = [...allIncidents];

    // Filtre statut analyste
    if (typeof EntityStatus !== "undefined" && _statusFilter !== "all")
      incidents = EntityStatus.filterByStatus(incidents, "incident", _statusFilter, i => i.incidentId);

    // Filtres
    if (_filterBy === "multi")     incidents = incidents.filter(i => i.articleCount > 1);
    if (_filterBy === "kev")       incidents = incidents.filter(i => i.kev);
    if (_filterBy === "watchlist") incidents = incidents.filter(i => i.watchlistHit);
    if (_filterBy === "exploit")   incidents = incidents.filter(i => i.angles.includes("exploitation"));
    if (_filterBy === "patch")     incidents = incidents.filter(i => i.angles.includes("patch"));
    if (_filterBy === "high")      incidents = incidents.filter(i => i.maxScore >= 70);
    if (_filterBy === "ioc")       incidents = incidents.filter(i => i.rawIocCount > 0);

    // Filtre texte
    if (_searchQuery) {
      const q = _searchQuery.toLowerCase();
      incidents = incidents.filter(i =>
        i.title.toLowerCase().includes(q) ||
        i.cves.some(c  => c.toLowerCase().includes(q)) ||
        i.vendors.some(v => v.toLowerCase().includes(q)) ||
        i.articles.some(a => (a.title || "").toLowerCase().includes(q))
      );
    }

    // Meta
    const meta = document.getElementById("incident-meta");
    if (meta) {
      const kc = allIncidents.filter(i => i.kev).length;
      const multiCount = allIncidents.filter(i => i.articleCount > 1).length;
      meta.textContent = (incidents.length === allIncidents.length)
        ? `${allIncidents.length} incident${allIncidents.length !== 1 ? "s" : ""} · ${multiCount} multi-source · ${kc} KEV`
        : `${incidents.length} / ${allIncidents.length} incident${allIncidents.length !== 1 ? "s" : ""}`;
    }

    list.innerHTML = `
      ${_controlsHTML()}
      ${incidents.length === 0
        ? `<p class="ip-empty">Aucun incident correspondant${_searchQuery ? ` à "${_searchQuery}"` : ""}.</p>`
        : `<table class="ip-table">
            <thead>
              <tr class="ip-thead">
                <th>Incident</th>
                <th class="ip-th-num">Art.</th>
                <th class="ip-th-num">Score</th>
                <th class="ip-th-num">EPSS</th>
                <th>Signaux</th>
                <th>CVE / Angles</th>
                <th class="ip-th-num">Vu le</th>
              </tr>
            </thead>
            <tbody>
              ${incidents.map(i => _rowHTML(i)).join("")}
            </tbody>
           </table>`
      }`;

    // Filtres
    list.querySelectorAll(".ip-filter-btn").forEach(btn => {
      btn.addEventListener("click", () => { _filterBy = btn.dataset.filter; _render(); });
    });

    // Filtres statut analyste
    list.querySelectorAll(".ip-status-btn").forEach(btn => {
      btn.addEventListener("click", () => { _statusFilter = btn.dataset.status; _render(); });
    });

    // Statut analyste — changement select (mise à jour badge ciblée, pas de re-render)
    if (typeof EntityStatus !== "undefined") {
      list.querySelectorAll(".es-block .es-select").forEach(sel => {
        sel.addEventListener("change", e => {
          const block   = e.target.closest(".es-block");
          const eid     = block.dataset.eid;
          const safeEid = block.dataset.safeEid;
          EntityStatus.setStatus("incident", eid, e.target.value);
          const slot = document.getElementById("es-slot-incident-" + safeEid);
          if (slot) slot.innerHTML = EntityStatus.badgeHTML("incident", eid);
        });
      });
      list.querySelectorAll(".es-block .es-note-input").forEach(inp => {
        inp.addEventListener("blur", e => {
          const block = e.target.closest(".es-block");
          EntityStatus.updateNote("incident", block.dataset.eid, e.target.value);
        });
        inp.addEventListener("keydown", e => { if (e.key === "Enter") e.target.blur(); });
      });
    }

    // Recherche — restaure curseur (évite l'inversion de saisie)
    const searchInput = list.querySelector(".ip-search-input");
    if (searchInput) {
      searchInput.value = _searchQuery;
      searchInput.addEventListener("input", e => {
        const pos = e.target.selectionStart;
        _searchQuery = e.target.value;
        _render();
        requestAnimationFrame(() => {
          const inp = document.querySelector(".ip-search-input");
          if (inp) { inp.focus(); inp.setSelectionRange(pos, pos); }
        });
      });
    }

    // ── IOC — copier un indicateur individuel ───────────────────────────────
    list.querySelectorAll(".ioc-copy-one").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        if (typeof IOCUtils !== "undefined")
          IOCUtils.copyOne(btn.dataset.iocType, btn.dataset.iocVal);
      });
    });

    // ── IOC — copier un groupe ou tout copier ────────────────────────────────
    list.querySelectorAll(".ioc-copy-group, .ioc-copy-all").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        if (typeof IOCUtils === "undefined") return;
        const vals  = (btn.dataset.iocVals || "").split("||").filter(Boolean);
        const label = btn.dataset.iocLabel || "IOC";
        IOCUtils.copyGroup(label, vals);
      });
    });

    // ── IOC — export JSON / TXT ──────────────────────────────────────────────
    list.querySelectorAll(".ioc-export-json, .ioc-export-txt").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        if (typeof IOCUtils === "undefined") return;
        const iid      = btn.dataset.iid;
        const incident = _lastIncidents.find(i => i.incidentId === iid);
        if (!incident) return;
        const iocs = IOCUtils.aggregateIOCs(incident.articles);
        const fmt  = btn.classList.contains("ioc-export-json") ? "json" : "txt";
        IOCUtils.exportIOC(iocs, fmt, incident.title);
      });
    });

    // Toggle détail sur clic ligne
    list.querySelectorAll(".ip-row").forEach(row => {
      row.addEventListener("click", () => {
        const iid    = row.dataset.iid;
        const detail = document.getElementById(`ip-detail-${iid}`);
        if (!detail) return;
        const isOpen = detail.style.display !== "none";
        list.querySelectorAll(".ip-detail-row").forEach(d => { d.style.display = "none"; });
        list.querySelectorAll(".ip-row").forEach(r => r.classList.remove("ip-row-open"));
        if (!isOpen) {
          detail.style.display = "table-row";
          row.classList.add("ip-row-open");
        }
      });
    });
  }

  function _controlsHTML() {
    const f  = _filterBy;
    const sf = _statusFilter;

    let statusBarHTML = "";
    if (typeof EntityStatus !== "undefined") {
      const btns = ["all", ...EntityStatus.VALID_STATUSES].map(s => {
        const m     = EntityStatus.STATUS_META[s];
        const label = s === "all" ? "Tous statuts" : m.emoji + "\u00a0" + m.label;
        return `<button class="ip-status-btn${sf === s ? " active" : ""}" data-status="${s}">${label}</button>`;
      }).join("");
      statusBarHTML = `<div class="ip-status-bar">${btns}</div>`;
    }

    return `
      <div class="ip-controls">
        <div class="ip-search-bar">
          <input type="search" class="ip-search-input"
                 placeholder="🔎 Rechercher incident, CVE, vendor, produit..."
                 value="${_searchQuery.replace(/"/g, "&quot;")}">
        </div>
        <div class="ip-filter-bar">
          <button class="ip-filter-btn${f==="all"       ?" active":""}" data-filter="all">Tous</button>
          <button class="ip-filter-btn${f==="multi"     ?" active":""}" data-filter="multi">📎 Multi-source</button>
          <button class="ip-filter-btn${f==="kev"       ?" active":""}" data-filter="kev">🚨 KEV</button>
          <button class="ip-filter-btn${f==="watchlist" ?" active":""}" data-filter="watchlist">👁 Watchlist</button>
          <button class="ip-filter-btn${f==="exploit"   ?" active":""}" data-filter="exploit">💀 Exploit</button>
          <button class="ip-filter-btn${f==="patch"     ?" active":""}" data-filter="patch">🩹 Patch</button>
          <button class="ip-filter-btn${f==="high"      ?" active":""}" data-filter="high">🔴 Score ≥ 70</button>
          <button class="ip-filter-btn${f==="ioc"       ?" active":""}" data-filter="ioc">🔗 Avec IOC${(() => { const n = _lastIncidents.filter(i => i.rawIocCount > 0).length; return n ? ` (${n})` : ""; })()}</button>
        </div>
        ${statusBarHTML}
      </div>`;
  }

  function _rowHTML(i) {
    const safeId   = i.incidentId.replace(/[^a-z0-9\-_]/g, "-");
    const epssStr  = i.maxEpss != null ? `${Math.round(i.maxEpss * 100)}%` : "—";
    const scoreStr = i.maxScore > 0    ? i.maxScore : "—";

    // Agrégation dédupliquée (une seule fois — sert au badge + au détail)
    let iocTotal   = 0;
    let iocSection = "";
    if (typeof IOCUtils !== "undefined") {
      const iocs = IOCUtils.aggregateIOCs(i.articles);
      iocTotal   = IOCUtils.total(iocs);
      iocSection = iocTotal > 0
        ? IOCUtils.iocBlockHTML(iocs, i.incidentId)
        : `<p class="ip-ioc-empty">🔗 Aucun IOC détecté pour cet incident.</p>`;
    }

    const signals = [
      i.kev          ? `<span class="ip-badge ip-kev">🚨 KEV</span>`              : "",
      i.watchlistHit ? `<span class="ip-badge ip-wl">👁 WL</span>`               : "",
      i.trending     ? `<span class="ip-badge ip-tr">🔥</span>`                   : "",
      iocTotal > 0   ? `<span class="ip-badge ip-ioc">🔗 ${iocTotal} IOC</span>` : ""
    ].filter(Boolean).join(" ");

    const cveHTML = i.cves.slice(0, 2).map(c =>
      `<code class="ip-cve-code">${c}</code>`).join(" ")
      + (i.cves.length > 2 ? ` <span class="ip-dim">+${i.cves.length - 2}</span>` : "");

    const anglesHTML = i.angles
      .filter(g => g !== "news" || i.angles.length === 1).slice(0, 3)
      .map(g => {
        const m = _ANGLE_META[g];
        return `<span class="ip-badge" style="color:${m.color};background:${m.bg}">${m.label}</span>`;
      }).join(" ");

    const cveCellHTML = [cveHTML, anglesHTML].filter(Boolean).join(" ");

    return `
      <tr class="ip-row" data-iid="${safeId}" title="Cliquer pour voir la timeline">
        <td class="ip-title-cell">
          <span id="es-slot-incident-${safeId}" class="es-badge-slot">${typeof EntityStatus !== "undefined" ? EntityStatus.badgeHTML("incident", i.incidentId) : ""}</span>
          <span class="ip-title">${i.title}</span>
          ${i.vendors.length
            ? `<span class="ip-dim ip-vendors-sub">${i.vendors.slice(0, 3).join(" · ")}</span>` : ""}
        </td>
        <td class="ip-num">${i.articleCount}</td>
        <td class="ip-num">${scoreStr}</td>
        <td class="ip-num">${epssStr}</td>
        <td>${signals || '<span class="ip-dim">—</span>'}</td>
        <td class="ip-cve-cell">${cveCellHTML || '<span class="ip-dim">—</span>'}</td>
        <td class="ip-num ip-dim">${_fmtDate(i.lastSeen)}</td>
      </tr>
      <tr class="ip-detail-row" id="ip-detail-${safeId}" style="display:none">
        <td colspan="7">
          <div class="ip-detail-inner">
            ${_detailHeaderHTML(i)}
            ${typeof EntityStatus !== "undefined" ? EntityStatus.statusBlockHTML("incident", i.incidentId) : ""}
            ${iocSection}
            <div class="ip-timeline">
              ${i.articles.map(a => _timelineRowHTML(a)).join("")}
            </div>
          </div>
        </td>
      </tr>`;
  }

  function _detailHeaderHTML(i) {
    const parts = [
      i.cves.length  ? `<strong>${i.cves.join("  ·  ")}</strong>` : "",
      `${i.articleCount} art. · ${i.sourceCount} src`,
      i.maxScore > 0    ? `score max <strong>${i.maxScore}</strong>` : "",
      i.maxEpss != null ? `EPSS max <strong>${Math.round(i.maxEpss * 100)}%</strong>` : "",
      i.kev ? `<span class="ip-badge ip-kev" style="font-size:.65rem">🚨 KEV</span>` : "",
      i.attackTags.length
        ? `<span class="ip-dim">${i.attackTags.slice(0, 3).join(" · ")}</span>` : "",
      i.firstSeen && i.lastSeen && i.firstSeen !== i.lastSeen
        ? `${_fmtDate(i.firstSeen)} → ${_fmtDate(i.lastSeen)}` : ""
    ].filter(Boolean).join(" &nbsp;·&nbsp; ");
    return `<p class="ip-detail-head">${parts}</p>`;
  }

  function _timelineRowHTML(a) {
    const angle = _classifyAngle(a);
    const m     = _ANGLE_META[angle];
    const criBadge = a.criticality === "high"
      ? `<span style="color:#f85149">🔴</span>`
      : `<span style="color:#f0883e">🟠</span>`;

    const badges = [
      `<span class="ip-badge" style="color:${m.color};background:${m.bg};min-width:4.2rem;text-align:center">${m.label}</span>`,
      a.isKEV                        ? `<span class="ip-badge ip-kev">KEV</span>`  : "",
      a.epssScore != null            ? `<span class="ip-badge ip-epss">EPSS ${Math.round(a.epssScore * 100)}%</span>` : "",
      a.watchlistMatches?.length > 0 ? `<span class="ip-badge ip-wl">WL</span>`   : "",
      (a.score ?? 0) > 0             ? `<span class="ip-badge ip-score">⚡${a.score}</span>` : ""
    ].filter(Boolean).join(" ");

    const href = a.link ? `href="${a.link}" target="_blank" rel="noopener noreferrer"` : "";

    return `
      <div class="ip-tl-row">
        <span class="ip-tl-date ip-dim">${_fmtDateTime(a.pubDate)}</span>
        <span class="ip-tl-cri">${criBadge}</span>
        <span class="ip-tl-src ip-dim">${a.sourceName || "?"}</span>
        <span class="ip-tl-badges">${badges}</span>
        <a ${href} class="ip-tl-title">${a.title || "(sans titre)"}</a>
      </div>`;
  }

  // ── API publique ──────────────────────────────────────────────────────────

  function init() {
    document.getElementById("btn-incidents")?.addEventListener("click", toggle);
  }

  function toggle() {
    const panel = document.getElementById("incident-panel");
    const btn   = document.getElementById("btn-incidents");
    if (!panel) return;
    const nowVisible = panel.style.display === "none";
    panel.style.display = nowVisible ? "block" : "none";
    btn?.classList.toggle("active", nowVisible);
    if (nowVisible) _render();
  }

  function update(articles) {
    _articles = articles;
    const panel = document.getElementById("incident-panel");
    if (panel?.style.display !== "none") _render();
  }

  // ── API publique filtres (pour SavedFilters) ──────────────────────────────
  function getFilters() {
    return { filterBy: _filterBy, searchQuery: _searchQuery, statusFilter: _statusFilter };
  }
  function setFilters(f) {
    if (f.filterBy     !== undefined) _filterBy     = f.filterBy;
    if (f.searchQuery  !== undefined) _searchQuery  = f.searchQuery;
    if (f.statusFilter !== undefined) _statusFilter = f.statusFilter;
    _render();
  }

  return { init, toggle, update, buildIncidentIndex, getFilters, setFilters };
})();
