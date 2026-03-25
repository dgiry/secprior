// ui.js — Rendu DOM, filtres, export CSV, notifications

const UI = (() => {
  // ─── Éléments DOM ──────────────────────────────────────────────────────────
  const $feed    = () => document.getElementById("feed-grid");
  const $count   = () => document.getElementById("article-count");
  const $spinner = () => document.getElementById("spinner");
  const $toasts  = () => document.getElementById("toast-area");
  const $lastUp  = () => document.getElementById("last-update");

  // ─── Temps relatif ─────────────────────────────────────────────────────────
  function timeAgo(date) {
    const diff = Math.floor((Date.now() - date) / 1000);
    if (diff < 60)   return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff/60)}min`;
    if (diff < 86400)return `${Math.floor(diff/3600)}h`;
    return `${Math.floor(diff/86400)}j`;
  }

  // ─── Rendu d'une carte article ─────────────────────────────────────────────
  function cardHTML(article) {
    const m = getCriticalityMeta(article.criticality);
    const age = timeAgo(article.pubDate);
    const starred = article.starred || Storage.isFavorite(article.id);
    const desc = article.description
      ? article.description.slice(0, 160) + (article.description.length > 160 ? "…" : "")
      : "";

    // ── Badges pipeline ──────────────────────────────────────────────────────
    const kevBadge = article.isKEV
      ? `<span class="badge badge-kev" title="CISA KEV — Exploité activement en production">⚠ KEV</span>`
      : "";

    const epssBadge = article.epssScore !== null && article.epssScore !== undefined
      ? `<span class="badge badge-epss" title="EPSS : probabilité d'exploitation dans 30j (${((article.epssPercentile ?? 0) * 100).toFixed(0)}e centile)">EPSS ${(article.epssScore * 100).toFixed(1)}%</span>`
      : "";

    const trendingBadge = article.isTrending
      ? `<span class="badge badge-trending" title="${article.trendingCount} sources couvrent ce sujet">🔥 Trending×${article.trendingCount}</span>`
      : (article.sourceCount > 1
          ? `<span class="badge badge-sources" title="${article.sourceCount} sources couvrent ce sujet">×${article.sourceCount} sources</span>`
          : "");

    const watchlistBadge = article.watchlistMatches?.length > 0
      ? `<span class="badge badge-watchlist" title="Watchlist : ${article.watchlistMatches.join(', ')}">👁 Vous concerne</span>`
      : "";

    const attackBadges = (article.attackTags || []).slice(0, 2).map(t =>
      `<span class="badge badge-attack" title="MITRE ATT&CK ${t.tactic}">${t.label}</span>`
    ).join("");

    // ── Barre de score composite ─────────────────────────────────────────────
    const scoreBar = article.score !== undefined
      ? `<div class="score-bar-wrap" title="Score composite : ${article.score}/100">
           <div class="score-bar ${scoreBarClass(article.score)}" style="width:${article.score}%"></div>
           <span class="score-label">${article.score}</span>
         </div>`
      : "";

    const extraBadges = [kevBadge, epssBadge, trendingBadge, watchlistBadge, attackBadges]
      .filter(Boolean).join("");

    // ── Badges IOCs (max 3 sur la carte, click-to-copy) ──────────────────────
    const iocBadges = _buildIOCBadges(article.iocs, article.iocCount);

    return `
      <article class="card crit-${article.criticality}" data-id="${article.id}"
               title="Cliquer pour voir les détails complets">
        <header class="card-header">
          <span class="badge ${m.cssClass}">${m.icon} ${m.label}</span>
          <span class="badge badge-source">${article.sourceIcon} ${article.sourceName}</span>
          <time class="card-time" title="${article.pubDate.toLocaleString()}">${age}</time>
          <button class="btn-star ${starred ? 'starred' : ''}"
                  onclick="UI.toggleFav('${article.id}')"
                  title="${starred ? 'Retirer des favoris' : 'Ajouter aux favoris'}">
            ${starred ? '★' : '☆'}
          </button>
        </header>
        ${scoreBar}
        <h3 class="card-title">
          <a href="${article.link}" target="_blank" rel="noopener noreferrer">
            ${article.title}
          </a>
        </h3>
        ${desc ? `<p class="card-desc">${desc}</p>` : ""}
        ${extraBadges ? `<div class="card-tags">${extraBadges}</div>` : ""}
        ${iocBadges   ? `<div class="card-iocs">${iocBadges}</div>`   : ""}
        <div class="card-nvd" id="nvd-${article.id}"></div>
      </article>`.trim();
  }

  // ─── Badges IOCs compacts pour les cartes ─────────────────────────────────
  function _buildIOCBadges(iocs, iocCount) {
    if (!iocs || !iocCount) return "";

    const badges = [];
    const MAX_CARD = 3; // max badges visibles sur la carte

    // Priorité d'affichage : hashes > IPs > domaines > urls
    const addBadge = (type, icon, cssType, value, displayVal, copyVal) => {
      if (badges.length >= MAX_CARD) return;
      const escaped = (displayVal || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
      const copyEsc = (copyVal || '').replace(/'/g, "\\'");
      badges.push(
        `<span class="badge badge-ioc badge-ioc-${cssType}"
              onclick="event.stopPropagation();IOCExtractor.copyIOC('${type}','${copyEsc}')"
              title="${type} — Cliquer pour copier&#10;${copyVal}">
           ${icon} ${escaped}
         </span>`
      );
    };

    // Hashes
    for (const h of (iocs.hashes || [])) {
      const display = IOCExtractor.formatForDisplay(h.type, h.value);
      addBadge(h.type, '🔑', 'hash', h.value, display, h.value);
    }
    // IPs
    for (const ip of (iocs.ips || [])) {
      addBadge('IP', '🌐', 'ip', ip, ip, ip);
    }
    // Domaines
    for (const d of (iocs.domains || [])) {
      addBadge('Domain', '🔗', 'domain', d, d, d);
    }

    if (!badges.length) return "";

    const more = iocCount - badges.length;
    const moreBadge = more > 0
      ? `<span class="badge badge-ioc badge-ioc-more" title="${more} IOC(s) supplémentaires — Ouvrir les détails">+${more} IOC${more > 1 ? 's' : ''}</span>`
      : "";

    return badges.join("") + moreBadge;
  }

  // ─── Rendu de la grille ────────────────────────────────────────────────────
  function renderCards(articles) {
    const container = $feed();
    if (!container) return;

    if (articles.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🔍</div>
          <p>Aucun article ne correspond à vos filtres.</p>
        </div>`;
    } else {
      container.innerHTML = articles.map(cardHTML).join("");
    }

    const countEl = $count();
    if (countEl) countEl.textContent = articles.length;
  }

  // ─── Filtrage ──────────────────────────────────────────────────────────────
  function applyFilters(articles, state) {
    let filtered = [...articles];

    // Filtre favoris
    if (state.showFavOnly) {
      const favs = Storage.getFavorites();
      filtered = filtered.filter(a => favs.has(a.id));
    }

    // Recherche keyword (title + description + CVEs + IOC domains)
    if (state.query) {
      const q = state.query.toLowerCase();
      filtered = filtered.filter(a =>
        a.title.toLowerCase().includes(q) ||
        (a.description && a.description.toLowerCase().includes(q)) ||
        (a.cves || []).some(c => c.toLowerCase().includes(q)) ||
        (a.iocs?.domains || []).some(d => d.includes(q))
      );
    }

    // Filtre criticité
    if (state.criticality && state.criticality !== "all") {
      filtered = filtered.filter(a => a.criticality === state.criticality);
    }

    // Filtre source
    if (state.source && state.source !== "all") {
      filtered = filtered.filter(a => a.source === state.source);
    }

    // Filtre date
    if (state.date && state.date !== "all") {
      const now = Date.now();
      const windows = { "24h": 86400000, "7d": 604800000, "30d": 2592000000 };
      const win = windows[state.date];
      if (win) filtered = filtered.filter(a => (now - a.pubDate.getTime()) <= win);
    }

    // ── Filtres risque opérationnel (combinés en AND) ─────────────────────────
    const { active: riskActive, epssThreshold } = state.riskFilters || { active: new Set(), epssThreshold: 0.10 };

    if (riskActive.has('kev')) {
      filtered = filtered.filter(a => a.isKEV);
    }

    if (riskActive.has('epss')) {
      filtered = filtered.filter(a =>
        a.epssScore != null && a.epssScore >= epssThreshold
      );
    }

    if (riskActive.has('watchlist')) {
      filtered = filtered.filter(a => a.watchlistMatches?.length > 0);
    }

    if (riskActive.has('trending')) {
      filtered = filtered.filter(a => a.isTrending);
    }

    if (riskActive.has('ioc')) {
      filtered = filtered.filter(a => (a.iocCount || 0) > 0);
    }

    if (riskActive.has('zero_day')) {
      filtered = filtered.filter(a =>
        a.attackTags?.some(t => t.label === '0-Day') ||
        /zero.?day|0day/i.test(a.title)
      );
    }

    return filtered;
  }

  // ─── Spinner / état loading ─────────────────────────────────────────────────
  function showSpinner(visible) {
    const el = $spinner();
    if (el) el.style.display = visible ? "flex" : "none";
  }

  // ─── Toast notifications ───────────────────────────────────────────────────
  function showToast(message, type = "info") {
    const container = $toasts();
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span>${message}</span><button onclick="this.parentElement.remove()">✕</button>`;
    container.appendChild(toast);

    // Auto-dismiss après 5s
    setTimeout(() => toast.remove(), 5000);
  }

  // ─── Mise à jour timestamp ─────────────────────────────────────────────────
  function updateTimestamp() {
    const el = $lastUp();
    if (el) el.textContent = new Date().toLocaleTimeString("fr-FR");
  }

  // ─── Export CSV ────────────────────────────────────────────────────────────
  function exportCSV(articles) {
    const header = ["Titre", "Source", "Criticité", "Date", "Lien"].join(";");
    const rows = articles.map(a => [
      `"${(a.title || "").replace(/"/g, '""')}"`,
      `"${a.sourceName}"`,
      a.criticality,
      a.pubDate.toISOString(),
      `"${a.link}"`
    ].join(";"));

    const csv = "\uFEFF" + [header, ...rows].join("\n"); // BOM pour Excel UTF-8
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyberveille_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Export CSV : ${articles.length} articles`, "success");
  }

  // ─── Notifications browser ─────────────────────────────────────────────────
  const notifiedIds = new Set();

  async function requestNotificationPermission() {
    if ("Notification" in window && Notification.permission === "default") {
      await Notification.requestPermission();
    }
  }

  function notifyCritical(articles) {
    if (!("Notification" in window) || Notification.permission !== "granted") return;

    const newCritical = articles.filter(
      a => a.criticality === "high" && !notifiedIds.has(a.id)
    );

    newCritical.forEach(a => {
      notifiedIds.add(a.id);
      const n = new Notification(`🔴 Alerte Haute — ${a.sourceName}`, {
        body: a.title.slice(0, 100),
        icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>",
        tag: a.id
      });
      n.onclick = () => { window.open(a.link, "_blank"); n.close(); };
    });
  }

  // ─── Toggle favori depuis les cartes ───────────────────────────────────────
  function toggleFav(id) {
    const isNowStarred = Storage.toggleFavorite(id);
    const card = document.querySelector(`.card[data-id="${id}"]`);
    if (card) {
      const btn = card.querySelector(".btn-star");
      if (btn) {
        btn.classList.toggle("starred", isNowStarred);
        btn.textContent = isNowStarred ? "★" : "☆";
        btn.title = isNowStarred ? "Retirer des favoris" : "Ajouter aux favoris";
      }
    }
    // Mettre à jour le compteur favoris
    const favCount = document.getElementById("fav-count");
    if (favCount) favCount.textContent = Storage.getFavoriteCount();
    return isNowStarred;
  }

  // ─── Injecter les données NVD dans une carte existante ────────────────────
  // Appelé par le callback NVD.enrichArticles() — pas de re-render complet
  function updateCardCVSS(articleId, cveData) {
    const slot = document.getElementById(`nvd-${articleId}`);
    if (!slot || !cveData) return;

    const score   = cveData.score;
    const cls     = NVD.cvssClass(score);
    const label   = score !== null ? `CVSS ${score.toFixed(1)}` : "CVSS N/A";
    const severity= cveData.severity ?? "";
    const vector  = cveData.vector  ? `title="${cveData.vector}"` : "";
    const cweTag  = cveData.cwe     ? `<span class="badge badge-cwe">${cveData.cwe}</span>` : "";
    const nvdLink = `https://nvd.nist.gov/vuln/detail/${cveData.cveId}`;

    slot.innerHTML = `
      <div class="nvd-row">
        <span class="badge ${cls}" ${vector}>${label}</span>
        ${severity ? `<span class="badge badge-severity">${severity}</span>` : ""}
        ${cweTag}
        <a class="nvd-link" href="${nvdLink}" target="_blank" rel="noopener">
          NVD ↗
        </a>
      </div>`.trim();
  }

  // ─── Export CSV enrichi (avec CVSS) ───────────────────────────────────────
  function exportCSVEnriched(articles, nvdMap) {
    const header = ["Titre", "Source", "Criticité", "CVSS Score", "CVE ID", "Date", "Lien"].join(";");
    const rows = articles.map(a => {
      const nvd   = nvdMap[a.id];
      const score = nvd?.score ?? "";
      const cveId = nvd?.cveId ?? NVD.extractCVEIds(a.title + " " + (a.description ?? ""))[0] ?? "";
      return [
        `"${(a.title || "").replace(/"/g, '""')}"`,
        `"${a.sourceName}"`,
        a.criticality,
        score,
        cveId,
        a.pubDate.toISOString(),
        `"${a.link}"`
      ].join(";");
    });

    const csv = "\uFEFF" + [header, ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url  = URL.createObjectURL(blob);
    const el   = document.createElement("a");
    el.href = url;
    el.download = `cyberveille_${new Date().toISOString().slice(0,10)}.csv`;
    el.click();
    URL.revokeObjectURL(url);
    showToast(`Export CSV : ${articles.length} articles (CVSS inclus)`, "success");
  }

  // ─── Initialiser le sélecteur de sources ──────────────────────────────────
  function initSourceFilter() {
    const sel = document.getElementById("filter-source");
    if (!sel) return;
    // FeedManager.getAllFeeds() inclut les flux custom en plus des défauts
    sel.innerHTML = `<option value="all">Toutes les sources</option>` +
      FeedManager.getAllFeeds().map(f =>
        `<option value="${f.id}">${f.icon} ${f.name}</option>`
      ).join("");
  }

  return {
    renderCards,
    applyFilters,
    showSpinner,
    showToast,
    updateTimestamp,
    exportCSV,
    exportCSVEnriched,
    updateCardCVSS,
    requestNotificationPermission,
    notifyCritical,
    toggleFav,
    initSourceFilter
  };
})();
