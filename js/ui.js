// ui.js — Rendu DOM, filtres, export CSV, notifications

const UI = (() => {
  // ─── Éléments DOM ──────────────────────────────────────────────────────────
  const $feed    = () => document.getElementById("feed-grid");
  const $count   = () => document.getElementById("article-count");
  const $spinner = () => document.getElementById("spinner");
  const $toasts  = () => document.getElementById("toast-area");
  const $lastUp  = () => document.getElementById("last-update");

  // ─── Parser recherche avancée ──────────────────────────────────────────────
  // Parse query strings like: "ransomware -phishing source:cisa vendor:microsoft cve:CVE-2025- status:new priority:critical_now kev trending"
  // Returns: { plainTerms[], excludeTerms[], sourceFilter?, vendorFilter?, cveFilter?, statusFilter?, priorityFilter?, onlyKEV, onlyTrending }
  function _parseSearchQuery(query) {
    const result = {
      plainTerms:      [],
      excludeTerms:    [],
      sourceFilter:    null,
      vendorFilter:    null,
      cveFilter:       null,
      statusFilter:    null,
      priorityFilter:  null,
      onlyKEV:         false,
      onlyTrending:    false
    };

    const terms = query.trim().split(/\s+/);

    terms.forEach(term => {
      if (!term) return;

      if (term.startsWith('-') && term.length > 1) {
        // Exclusion: -keyword
        result.excludeTerms.push(term.slice(1).toLowerCase());
      } else if (term.includes(':')) {
        // Operator: key:value
        const colonIdx = term.indexOf(':');
        const op = term.slice(0, colonIdx).toLowerCase();
        const value = term.slice(colonIdx + 1);

        if (value) {
          switch (op) {
            case 'source':
              result.sourceFilter = value.toLowerCase();
              break;
            case 'vendor':
              result.vendorFilter = value.toLowerCase();
              break;
            case 'cve':
              result.cveFilter = value.toLowerCase();
              break;
            case 'status':
              result.statusFilter = value.toLowerCase();
              break;
            case 'priority':
              result.priorityFilter = value.toLowerCase();
              break;
            default:
              // Unknown operator: treat as plain text
              result.plainTerms.push(term.toLowerCase());
          }
        } else {
          // Malformed: operator with no value
          result.plainTerms.push(term.toLowerCase());
        }
      } else if (term.toLowerCase() === 'kev') {
        // Shorthand: kev
        result.onlyKEV = true;
      } else if (term.toLowerCase() === 'trending') {
        // Shorthand: trending
        result.onlyTrending = true;
      } else {
        // Plain text term
        result.plainTerms.push(term.toLowerCase());
      }
    });

    return result;
  }

  // ─── Temps relatif ─────────────────────────────────────────────────────────
  function timeAgo(date) {
    const diff = Math.floor((Date.now() - date) / 1000);
    if (diff < 60)   return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff/60)}min`;
    if (diff < 86400)return `${Math.floor(diff/3600)}h`;
    return `${Math.floor(diff/86400)}d`;
  }

  // ─── Mise à jour périodique des temps relatifs (card-time) ──────────────────
  // Problème : les labels de temps relatif ("1h", "2d", etc.) sont calculés UNE FOIS
  // au rendu et deviennent statiques. Ils deviennent stales rapidement.
  // Solution : actualiser tous les labels visibles toutes les 60 secondes.
  let _timeUpdateTimer = null;

  function _updateCardTimes() {
    const timeElements = document.querySelectorAll('.card-time');
    timeElements.forEach(el => {
      // Lire la date ISO depuis data-pubdate (machine-safe, non locale-dependent)
      const isoStr = el.getAttribute('data-pubdate');
      if (!isoStr) return;
      const pubDate = new Date(isoStr);
      if (!isNaN(pubDate.getTime())) {
        el.textContent = timeAgo(pubDate);
      }
    });
  }

  function _startCardTimeUpdater() {
    if (_timeUpdateTimer) clearInterval(_timeUpdateTimer);
    // Mettre à jour toutes les 60 secondes pour garder les temps relatifs frais
    _timeUpdateTimer = setInterval(_updateCardTimes, 60000);
  }

  function _stopCardTimeUpdater() {
    if (_timeUpdateTimer) {
      clearInterval(_timeUpdateTimer);
      _timeUpdateTimer = null;
    }
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
      ? `<span class="badge badge-kev" title="CISA KEV — Actively exploited in production">⚠ KEV</span>`
      : "";

    const epssBadge = article.epssScore !== null && article.epssScore !== undefined
      ? `<span class="badge badge-epss" title="EPSS: exploitation probability in 30d (${((article.epssPercentile ?? 0) * 100).toFixed(0)}th percentile)">EPSS ${(article.epssScore * 100).toFixed(1)}%</span>`
      : "";

    const trendingBadge = article.isTrending
      ? `<span class="badge badge-trending" title="${article.trendingCount} sources cover this topic">🔥 Trending×${article.trendingCount}</span>`
      : (article.sourceCount > 1
          ? `<span class="badge badge-sources" title="${article.sourceCount} sources cover this topic">×${article.sourceCount} sources</span>`
          : "");

    const watchlistBadge = article.watchlistMatches?.length > 0
      ? `<span class="badge badge-watchlist" title="Watchlist: ${article.watchlistMatches.join(', ')}">👁 Matches you</span>`
      : "";

    const attackBadges = (article.attackTags || []).slice(0, 2).map(t =>
      `<span class="badge badge-attack" title="MITRE ATT&CK ${t.tactic}">${t.label}</span>`
    ).join("");

    // ── Barre de score composite ─────────────────────────────────────────────
    const scoreBar = article.score !== undefined
      ? `<div class="score-bar-wrap" title="Composite score: ${article.score}/100">
           <div class="score-bar ${scoreBarClass(article.score)}" style="width:${article.score}%"></div>
           <span class="score-label">${article.score}</span>
         </div>`
      : "";

    // ── Signal chips — explainability visuelle sur la carte ─────────────────
    // Remplace la priorityLine texte par des chips colorés scannables.
    // Affichés dès qu'il y a au moins un signal, même pour les articles "low".
    let priorityLine = "";
    (function() {
      const sig  = article.prioritySignals || {};
      const lvl  = article.priorityLevel;
      const chips = [];

      // ① Niveau de priorité + tooltip score breakdown (toujours en premier si non-low)
      if (lvl && lvl !== "low") {
        const pm = (typeof getPriorityMeta === 'function') ? getPriorityMeta(lvl) : null;
        if (pm) {
          // ── Construire le tooltip score breakdown ──────────────────────────
          const bd  = article.scoreBreakdown || {};
          const ps  = article.priorityScore  || 0;
          const base = article.score         || sig.baseScore || 0;

          // Contributeurs base (scoreBreakdown) — labels lisibles, triés desc
          const baseRows = [
            bd.kev     > 0 ? { label: 'KEV exploit',       pts: bd.kev     } : null,
            bd.epss    > 0 ? { label: `EPSS ${sig.epss != null ? sig.epss + '%' : ''}`, pts: bd.epss } : null,
            bd.cvss    > 0 ? { label: 'CVSS severity',     pts: bd.cvss    } : null,
            bd.sources > 0 ? { label: 'Source coverage',   pts: bd.sources } : null,
            bd.ioc     > 0 ? { label: 'IOC indicators',    pts: bd.ioc     } : null,
          ].filter(Boolean).sort((a, b) => b.pts - a.pts).slice(0, 4);

          // Bonus priorité (signaux non couverts par le score base)
          const bonusRows = [];
          if (sig.watchlistBonus > 0) bonusRows.push({ label: 'Watchlist match', pts: sig.watchlistBonus });
          if (sig.isZeroDay)           bonusRows.push({ label: '0-Day',          pts: 15 });
          if (sig.trending)            bonusRows.push({ label: 'Trending',        pts: 8  });

          // Construire les lignes HTML du tooltip
          const tipRows = [
            `<span class="stp-head">Score ${base}/100</span>`,
            ...baseRows.map(r =>
              `<span class="stp-row"><span class="stp-lbl">${r.label}</span><span class="stp-pts">+${r.pts}</span></span>`
            ),
          ];
          if (bonusRows.length) {
            bonusRows.sort((a, b) => b.pts - a.pts).slice(0, 2).forEach(r =>
              tipRows.push(`<span class="stp-row stp-bonus"><span class="stp-lbl">${r.label}</span><span class="stp-pts">+${r.pts}</span></span>`)
            );
          }
          // N'afficher le tooltip que si on a des données réelles
          const scoreTip = (base > 0 || bonusRows.length)
            ? `<span class="score-tip-popup">${tipRows.join('')}</span>`
            : '';

          chips.push(
            `<span class="sig-chip sig-chip-level sig-chip-${pm.css}${scoreTip ? ' has-score-tip' : ''}">`
            + `${pm.icon} ${pm.label}`
            + scoreTip
            + `</span>`
          );
        }
      }

      // ② KEV — exploitation confirmée CISA
      if (sig.kev)
        chips.push(`<span class="sig-chip sig-chip-kev" title="CISA KEV: active exploitation confirmed">🔑 KEV</span>`);

      // ③ EPSS — probabilité d'exploitation
      if (sig.epss !== null && sig.epss !== undefined && sig.epss > 0) {
        const cls = sig.epssHigh ? 'sig-chip-epss-high' : sig.epssMed ? 'sig-chip-epss-med' : 'sig-chip-epss-low';
        chips.push(`<span class="sig-chip ${cls}" title="EPSS: ${sig.epss}% probability of exploitation in 30 days">📊 EPSS ${sig.epss}%</span>`);
      }

      // ④ 0-Day
      if (sig.isZeroDay)
        chips.push(`<span class="sig-chip sig-chip-zeroday" title="Zero-day: no patch available">⚡ 0-Day</span>`);

      // ⑤ Watchlist
      if (sig.watchlist > 0) {
        const wlLabel = sig.watchlistItems?.length
          ? sig.watchlistItems[0].label || 'Watchlist'
          : 'Watchlist';
        chips.push(`<span class="sig-chip sig-chip-watchlist" title="Watchlist match: ${wlLabel}">👁 ${wlLabel}</span>`);
      }

      // ⑥ ATT&CK tactics (max 2)
      const tactics = (article.attackTags || []).slice(0, 2);
      tactics.forEach(t =>
        chips.push(`<span class="sig-chip sig-chip-attack" title="ATT&CK tactic: ${t.label}">🎯 ${t.label}</span>`)
      );

      // ⑦ Multi-source / Trending
      if (sig.trending)
        chips.push(`<span class="sig-chip sig-chip-sources" title="${sig.sources} concurrent sources">📡 ${sig.sources} src</span>`);
      else if (sig.sources > 1)
        chips.push(`<span class="sig-chip sig-chip-sources sig-chip-sources-dim" title="${sig.sources} sources">📡 ${sig.sources} src</span>`);

      // ⑧ IOCs — indicateurs concrets
      if (sig.iocCount > 0)
        chips.push(`<span class="sig-chip sig-chip-ioc" title="${sig.iocCount} IOC(s): IPs, domains, hashes">🔗 ${sig.iocCount} IOC</span>`);

      if (chips.length > 0)
        priorityLine = `<div class="card-signal-chips">${chips.join('')}</div>`;
    })();

    // Badge résumé IOC — compteur rapide dans la rangée principale des signaux
    const iocSummaryBadge = (article.iocCount || 0) > 0
      ? `<span class="badge badge-ioc-summary"
               title="Detected IOCs: ${article.iocCount} indicator${article.iocCount > 1 ? 's' : ''} (IPs, domains, hashes, URLs)">🔗 ${article.iocCount} IOC</span>`
      : "";

    const extraBadges = [kevBadge, epssBadge, trendingBadge, watchlistBadge, attackBadges, iocSummaryBadge]
      .filter(Boolean).join("");

    // ── Badges IOCs (max 3 sur la carte, click-to-copy) ──────────────────────
    const iocBadges = _buildIOCBadges(article.iocs, article.iocCount);

    // Badge "Nouveau depuis la dernière visite" — affiché dans le header
    const newBadge = article._isNew
      ? `<span class="badge badge-new" title="Published since your last visit">🆕 New</span>`
      : "";

    // ── Badge de statut analyste (inline, cycle au clic) ─────────────────────
    const _STATUS_CYCLE = ['new', 'acknowledged', 'investigating', 'mitigated'];
    const _STATUS_DISPLAY = {
      new:          { label: '· New',           color: '#8b949e', bg: 'transparent' },
      acknowledged: { label: '📥 ACK',          color: '#f0883e', bg: '#2d1a00' },
      investigating:{ label: '🔍 Investigating', color: '#79c0ff', bg: '#0d1b2e' },
      mitigated:    { label: '✅ Mitigated',     color: '#3fb950', bg: '#0d2818' },
      ignored:      { label: '🚫 Ignored',       color: '#484f58', bg: '#161b22' }
    };
    const curStatus = (typeof EntityStatus !== 'undefined')
      ? EntityStatus.getEffectiveStatus('article', article.id)
      : 'new';
    const sd = _STATUS_DISPLAY[curStatus] || _STATUS_DISPLAY.new;
    const statusBadge = `<button class="card-status-btn card-status-${curStatus}"
      style="color:${sd.color};background:${sd.bg}"
      onclick="event.stopPropagation();UI.cycleStatus('${article.id}')"
      title="Status: ${curStatus} — click to advance">${sd.label}</button>`;

    const isRead     = (typeof Storage !== 'undefined') ? Storage.isRead(article.id)     : false;
    const isReviewed = (typeof Storage !== 'undefined') ? Storage.isReviewed(article.id) : false;
    return `
      <article class="card crit-${article.criticality}${article._isNew ? " card-new" : ""}${isRead ? " card-read" : ""}${isReviewed ? " card-reviewed" : ""}" data-id="${article.id}"
               title="Click to see full details">
        <header class="card-header">
          <span class="badge ${m.cssClass}">${m.icon} ${m.label}</span>
          ${newBadge}
          <span class="badge badge-source">${article.sourceIcon} ${article.sourceName}</span>
          <time class="card-time" data-pubdate="${article.pubDate.toISOString()}" title="${article.pubDate.toLocaleString()}">${age}</time>
          ${statusBadge}
          <button class="btn-reviewed ${isReviewed ? 'reviewed' : ''}"
                  onclick="event.stopPropagation();UI.toggleReviewed('${article.id}')"
                  title="${isReviewed ? 'Reviewed — click to unmark' : 'Mark as reviewed'}">
            ${isReviewed ? '✓' : '○'}
          </button>
          <button class="btn-star ${starred ? 'starred' : ''}"
                  onclick="UI.toggleFav('${article.id}')"
                  title="${starred ? 'Remove from favorites' : 'Add to favorites'}">
            ${starred ? '★' : '☆'}
          </button>
        </header>
        ${scoreBar}
        ${priorityLine}
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
              title="${type} — Click to copy&#10;${copyVal}">
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
      ? `<span class="badge badge-ioc badge-ioc-more" title="${more} more IOC(s) — Open details">+${more} IOC${more > 1 ? 's' : ''}</span>`
      : "";

    return badges.join("") + moreBadge;
  }

  // ─── Rendu de la grille ────────────────────────────────────────────────────
  function renderCards(articles) {
    const container = $feed();
    if (!container) return;

    if (articles.length === 0) {
      container.innerHTML = _buildEmptyState();
    } else {
      container.innerHTML = articles.map(cardHTML).join("");
    }

    const countEl = $count();
    if (countEl) countEl.textContent = articles.length;

    // Recalculer immédiatement les temps relatifs (évite d'attendre 60s)
    _updateCardTimes();
    // Démarrer la mise à jour périodique des temps relatifs
    _startCardTimeUpdater();
  }

  // ─── Empty state contextuel ────────────────────────────────────────────────
  function _buildEmptyState() {
    // Lire l'état des filtres depuis le DOM (lecture seule — pas d'effet de bord)
    const query      = document.getElementById('search-input')?.value?.trim() || '';
    const crit       = document.getElementById('filter-criticality')?.value   || 'all';
    const prio       = document.getElementById('filter-priority-level')?.value || 'all';
    const status     = document.getElementById('filter-status')?.value         || 'all';
    const dateVal    = document.getElementById('filter-date')?.value            || 'all';
    const showFavs   = document.getElementById('btn-favs')?.classList.contains('active') || false;

    let icon  = '🔍';
    let title = 'No matching articles';
    let hint  = 'Try widening your filters or use a business view.';
    let cta   = '';

    const _resetBtn = (targetId, label, eventType = 'change', value = 'all') =>
      `<button class="btn ob-reset-btn"
               onclick="(function(){var el=document.getElementById('${targetId}');if(!el)return;el.value='${value}';el.dispatchEvent(new Event('${eventType}'));})()">
         ${label}
       </button>`;

    if (dateVal === 'lastvisit') {
      icon  = '🆕';
      title = 'No new articles since your last visit';
      hint  = 'All caught up! Nothing was published since you last opened ThreatLens.';
      cta   = _resetBtn('filter-date', 'See all articles');
    } else if (showFavs) {
      icon  = '⭐';
      title = 'No favorites yet';
      hint  = 'Click ⭐ on an article card to add it to your favorites.';
      cta   = `<button class="btn ob-reset-btn"
                       onclick="document.getElementById('btn-favs').click()">
                 See all articles
               </button>`;
    } else if (query) {
      icon  = '🔎';
      title = `No results for «${_escHtmlShort(query)}»`;
      hint  = 'Try a shorter term, without quotes, or use a business view.';
      cta   = `<button class="btn ob-reset-btn"
                       onclick="(function(){var el=document.getElementById('search-input');if(!el)return;el.value='';el.dispatchEvent(new Event('input'));})()">
                 Clear search
               </button>`;
    } else if (status !== 'all') {
      icon  = '📋';
      title = 'No articles with this analyst status';
      hint  = 'Change the status or show all articles to continue.';
      cta   = _resetBtn('filter-status', 'Reset status');
    } else if (crit === 'high') {
      icon  = '🔴';
      title = 'No HIGH alert at the moment';
      hint  = 'HIGH severity can be rare. Show all severities to see current threats.';
      cta   = _resetBtn('filter-criticality', 'See all severities');
    } else if (prio !== 'all') {
      icon  = '🎯';
      title = 'No articles with this priority';
      hint  = 'Widen the priority level or use a business view for guided selection.';
      cta   = _resetBtn('filter-priority-level', 'All priorities');
    } else {
      icon  = '📡';
      title = 'No articles available';
      hint  = 'Feeds are loading from your RSS sources. Refresh or start with a business view.';
      cta   = `<button class="btn ob-reset-btn"
                       onclick="document.getElementById('btn-refresh').click()">
                 ↻ Refresh feeds
               </button>`;
    }

    const personaHint = typeof PersonaPresets !== 'undefined'
      ? `<button class="btn ob-reset-btn ob-reset-persona"
                 onclick="document.querySelector('[data-pid=\\'today\\']')?.click()"
                 title="See critical threats from the last 24h">
           🚨 Top priorities
         </button>`
      : '';

    return `
      <div class="empty-state empty-state-rich">
        <div class="empty-icon">${icon}</div>
        <p class="empty-title">${title}</p>
        <p class="empty-hint">${hint}</p>
        <div class="empty-actions">
          ${cta}
          ${personaHint}
        </div>
      </div>`;
  }

  // Helper d'échappement minimal pour l'empty state
  function _escHtmlShort(s) {
    return (s || '').slice(0, 40)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ─── Filtrage ──────────────────────────────────────────────────────────────
  function applyFilters(articles, state) {
    let filtered = [...articles];

    // Filtre favoris
    if (state.showFavOnly) {
      const favs = Storage.getFavorites();
      filtered = filtered.filter(a => favs.has(a.id));
    }

    // Filtre non-lu seulement
    if (state.showUnreadOnly) {
      const read = Storage.getRead();
      filtered = filtered.filter(a => !read.has(a.id));
    }

    // Masquer les articles revus (triage)
    if (state.hideReviewed) {
      const reviewed = Storage.getReviewed();
      filtered = filtered.filter(a => !reviewed.has(a.id));
    }

    // Recherche avancée (plain text + operators: source:, vendor:, cve:, status:, priority:, kev, trending, -keyword)
    if (state.query) {
      const parsed = _parseSearchQuery(state.query);

      filtered = filtered.filter(a => {
        // 1. Exclusions : ANY matching term = exclude article
        for (const excludeTerm of parsed.excludeTerms) {
          const textMatch = a.title.toLowerCase().includes(excludeTerm) ||
            (a.description && a.description.toLowerCase().includes(excludeTerm));
          const cveMatch = (a.cves || []).some(c => c.toLowerCase().includes(excludeTerm));
          const iocMatch = (a.iocs?.domains || []).some(d => d.includes(excludeTerm));

          if (textMatch || cveMatch || iocMatch) return false;
        }

        // 2. source: filter
        if (parsed.sourceFilter) {
          if (!a.source || !a.source.toLowerCase().includes(parsed.sourceFilter)) {
            return false;
          }
        }

        // 3. vendor: filter (check title, description, or enriched vendors if available)
        if (parsed.vendorFilter) {
          const vendorMatch = a.title.toLowerCase().includes(parsed.vendorFilter) ||
            (a.description && a.description.toLowerCase().includes(parsed.vendorFilter)) ||
            (a.vendors && a.vendors.some(v => v.toLowerCase().includes(parsed.vendorFilter)));
          if (!vendorMatch) return false;
        }

        // 4. cve: filter
        if (parsed.cveFilter) {
          const cveMatch = (a.cves || []).some(c => c.toLowerCase().includes(parsed.cveFilter));
          if (!cveMatch) return false;
        }

        // 5. status: filter (analyst workflow status)
        if (parsed.statusFilter && typeof EntityStatus !== 'undefined') {
          const status = EntityStatus.getStatus('article', a.id);
          if (!status || !status.toLowerCase().includes(parsed.statusFilter)) {
            return false;
          }
        }

        // 6. priority: filter
        if (parsed.priorityFilter) {
          if (!a.priorityLevel || !a.priorityLevel.toLowerCase().includes(parsed.priorityFilter)) {
            return false;
          }
        }

        // 7. kev shorthand (KEV articles only)
        if (parsed.onlyKEV && !a.isKEV) {
          return false;
        }

        // 8. trending shorthand (trending articles only)
        if (parsed.onlyTrending && !a.isTrending) {
          return false;
        }

        // 9. Plain text: ANY plain term matching = include
        if (parsed.plainTerms.length > 0) {
          const plainMatch = parsed.plainTerms.some(term =>
            a.title.toLowerCase().includes(term) ||
            (a.description && a.description.toLowerCase().includes(term)) ||
            (a.cves || []).some(c => c.toLowerCase().includes(term)) ||
            (a.iocs?.domains || []).some(d => d.includes(term))
          );
          if (!plainMatch) return false;
        }

        return true;
      });
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
    // ── Important: Skip time filter for critical/investigate articles ─────────
    // Critical vulnerabilities remain critical regardless of age. Applying the
    // "Last 24h" filter would hide important enriched articles (e.g., CVE-2026-5281
    // marked critical_now but published > 24h ago). Time filter still applies to
    // 'watch' and 'low' priority articles for recency focus.
    const isCriticalOrInvestigate = state.priorityLevel === 'critical_now' || state.priorityLevel === 'investigate';

    if (state.date && state.date !== "all" && !isCriticalOrInvestigate) {
      if (state.date === "lastvisit" && state.lastVisitTs) {
        // Articles publiés après le début de la session précédente
        filtered = filtered.filter(a => a.pubDate.getTime() > state.lastVisitTs);
      } else {
        const now = Date.now();
        const windows = { "24h": 86400000, "7d": 604800000, "30d": 2592000000 };
        const win = windows[state.date];
        if (win) filtered = filtered.filter(a => (now - a.pubDate.getTime()) <= win);
      }
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

    // Filtre niveau de priorité explicable
    if (state.priorityLevel && state.priorityLevel !== "all") {
      filtered = filtered.filter(a => a.priorityLevel === state.priorityLevel);
    }

    // Filtre statut analyste
    if (state.statusFilter && state.statusFilter !== "all" && typeof EntityStatus !== "undefined") {
      filtered = EntityStatus.filterByStatus(filtered, "article", state.statusFilter, a => a.id);
    }

    // Tri par priorityScore (articles sans priorityScore traités comme 0)
    if (state.sortBy === "priority") {
      filtered = filtered.slice().sort((a, b) =>
        (b.priorityScore ?? 0) - (a.priorityScore ?? 0)
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
    if (el) el.textContent = new Date().toLocaleTimeString("en-US");
  }

  // ─── Export CSV ────────────────────────────────────────────────────────────
  function exportCSV(articles) {
    const header = ["Title", "Source", "Severity", "Date", "Link"].join(";");
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
    showToast(`CSV Export: ${articles.length} articles`, "success");
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
      const n = new Notification(`🔴 High Alert — ${a.sourceName}`, {
        body: a.title.slice(0, 100),
        icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>",
        tag: a.id
      });
      n.onclick = () => { window.open(a.link, "_blank"); n.close(); };
    });
  }

  // ─── Cycle statut analyste depuis les cartes ─────────────────────────────
  function cycleStatus(id) {
    if (typeof EntityStatus === 'undefined') return;
    const CYCLE = ['new', 'acknowledged', 'investigating', 'mitigated'];
    const STATUS_DISPLAY = {
      new:          { label: '· New',           color: '#8b949e', bg: 'transparent' },
      acknowledged: { label: '📥 ACK',          color: '#f0883e', bg: '#2d1a00' },
      investigating:{ label: '🔍 Investigating', color: '#79c0ff', bg: '#0d1b2e' },
      mitigated:    { label: '✅ Mitigated',     color: '#3fb950', bg: '#0d2818' },
      ignored:      { label: '🚫 Ignored',       color: '#484f58', bg: '#161b22' }
    };
    const cur  = EntityStatus.getEffectiveStatus('article', id);
    const idx  = CYCLE.indexOf(cur);
    const next = CYCLE[(idx + 1) % CYCLE.length];
    EntityStatus.setStatus('article', id, next);

    // Mettre à jour le badge dans la carte sans re-render complet
    const card = document.querySelector(`.card[data-id="${id}"]`);
    if (card) {
      const btn = card.querySelector('.card-status-btn');
      if (btn) {
        const sd = STATUS_DISPLAY[next] || STATUS_DISPLAY.new;
        btn.textContent = sd.label;
        btn.style.color = sd.color;
        btn.style.background = sd.bg;
        btn.className = `card-status-btn card-status-${next}`;
        btn.title = `Status: ${next} — click to advance`;
        // Refléter le statut sur la carte (pour filtre par statut)
        card.setAttribute('data-status', next);
      }
    }
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
        btn.title = isNowStarred ? "Remove from favorites" : "Add to favorites";
      }
    }
    // Mettre à jour le compteur favoris
    const favCount = document.getElementById("fav-count");
    if (favCount) favCount.textContent = Storage.getFavoriteCount();
    return isNowStarred;
  }

  // ─── Toggle "Reviewed" depuis les cartes ──────────────────────────────────
  function toggleReviewed(id) {
    const isNowReviewed = Storage.toggleReviewed(id);
    const card = document.querySelector(`.card[data-id="${id}"]`);
    if (card) {
      card.classList.toggle('card-reviewed', isNowReviewed);
      const btn = card.querySelector('.btn-reviewed');
      if (btn) {
        btn.classList.toggle('reviewed', isNowReviewed);
        btn.textContent = isNowReviewed ? '✓' : '○';
        btn.title = isNowReviewed ? 'Reviewed — click to unmark' : 'Mark as reviewed';
      }
    }
    // Mettre à jour le compteur dans le bouton navbar
    const reviewedCount = document.getElementById('reviewed-count');
    if (reviewedCount) reviewedCount.textContent = Storage.getReviewedCount();
    return isNowReviewed;
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

    // Age badge — "📅 Xd ago" (disclosed date from NVD)
    let ageHTML = "";
    if (cveData.published) {
      try {
        const days  = Math.max(0, Math.floor((Date.now() - new Date(cveData.published).getTime()) / 86_400_000));
        const ageCls = days > 30 ? "nvd-age-old" : days > 7 ? "nvd-age-med" : "nvd-age-fresh";
        ageHTML = `<span class="nvd-age ${ageCls}" title="Disclosed ${new Date(cveData.published).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'})}">📅 ${days}d ago</span>`;
      } catch {}
    }

    slot.innerHTML = `
      <div class="nvd-row">
        <span class="badge ${cls}" ${vector}>${label}</span>
        ${severity ? `<span class="badge badge-severity">${severity}</span>` : ""}
        ${cweTag}
        <a class="nvd-link" href="${nvdLink}" target="_blank" rel="noopener">
          NVD ↗
        </a>
        ${ageHTML}
      </div>`.trim();
  }

  // ─── Export CSV enrichi (avec CVSS) ───────────────────────────────────────
  function exportCSVEnriched(articles, nvdMap) {
    const header = ["Title", "Source", "Severity", "CVSS Score", "CVE ID", "Date", "Link"].join(";");
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
    showToast(`CSV Export: ${articles.length} articles (with CVSS)`, "success");
  }

  // ─── Initialiser le sélecteur de sources ──────────────────────────────────
  function initSourceFilter() {
    const sel = document.getElementById("filter-source");
    if (!sel) return;
    // FeedManager.getAllFeeds() inclut les flux custom en plus des défauts
    sel.innerHTML = `<option value="all">All sources</option>` +
      FeedManager.getAllFeeds().map(f =>
        `<option value="${f.id}">${f.icon} ${f.name}</option>`
      ).join("");
  }

  // ── Score-tip viewport positioning ────────────────────────────────────────
  // Runs once at module load. Delegated on document so it survives card
  // re-renders without needing re-attachment after each renderCards() call.
  //
  // Strategy: the popup uses visibility:hidden (not display:none) so it is
  // always in the render tree and measurable. On mouseover the chip we read
  // its bounding rect, compare against viewport, and inject inline-style
  // overrides + CSS modifier classes before the hover opacity transition fires.
  // On mouseout we reset everything so the next hover starts from defaults.
  (function _initScoreTipPositioning() {
    const MARGIN = 10; // min clearance from any viewport edge (px)

    document.addEventListener('mouseover', e => {
      const chip = e.target.closest('.has-score-tip');
      if (!chip) return;
      const popup = chip.querySelector('.score-tip-popup');
      if (!popup) return;

      // Reset overrides from any previous hover so we measure from default position
      popup.style.cssText = '';
      popup.classList.remove('tip-above', 'tip-right');

      const chipR  = chip.getBoundingClientRect();
      const popupR = popup.getBoundingClientRect(); // accurate: always display:flex
      const vw     = window.innerWidth;
      const vh     = window.innerHeight;

      // ── Vertical: open above if not enough room below ──────────────────────
      if (vh - chipR.bottom < popupR.height + MARGIN) {
        popup.style.top    = 'auto';
        popup.style.bottom = 'calc(100% + 7px)';
        popup.classList.add('tip-above');
      }

      // ── Horizontal: right-align when tooltip would overflow right edge ──────
      if (chipR.left + popupR.width > vw - MARGIN) {
        popup.style.left  = 'auto';
        popup.style.right = '0';
        popup.classList.add('tip-right');
      }
    });

    document.addEventListener('mouseout', e => {
      const chip = e.target.closest('.has-score-tip');
      if (!chip || chip.contains(e.relatedTarget)) return; // still inside chip
      const popup = chip.querySelector('.score-tip-popup');
      if (!popup) return;
      popup.style.cssText = '';
      popup.classList.remove('tip-above', 'tip-right');
    });
  })();

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
    toggleReviewed,
    cycleStatus,
    initSourceFilter,
    timeAgo
  };
})();
