// article-modal.js — Modal de détail article ThreatLens
//
// Clic sur une carte → overlay pleine page avec :
//   • Score composite + CVSS (NVD) + jauge EPSS + KEV
//   • CVEs avec liens NVD
//   • Tactiques MITRE ATT&CK détectées
//   • Watchlist matches
//   • Description complète
//   • Articles similaires (algo CVE + mots-clés)
//   • Bouton "Copier IOCs" (CVEs, URL, ATT&CK, IPs, domaines)
//   • Bouton favoris + lien "Ouvrir l'article"

const ArticleModal = (() => {

  let _articles = [];   // Référence aux articles (pour la recherche de similaires)
  let _nvdMap   = {};   // Données NVD enrichies { articleId: cveData }

  // ─── API publique ──────────────────────────────────────────────────────────

  function setArticles(articles, nvdMap = {}) {
    _articles = articles;
    _nvdMap   = nvdMap;
  }

  function openById(id) {
    const article = _articles.find(a => a.id === id);
    if (article) open(article);
  }

  function open(article) {
    const modal   = document.getElementById('modal-article');
    const content = document.getElementById('art-modal-content');
    if (!modal || !content) return;

    // Marquer l'article comme lu
    if (typeof Storage !== 'undefined') Storage.markRead(article.id);

    content.innerHTML = _buildContent(article);

    // Bind des boutons footer (injectés dynamiquement)
    document.getElementById('art-modal-copy-ioc')
      ?.addEventListener('click', () => _copyIOCs(article));

    // Actions rapides — résumés analyste / exécutif
    if (typeof QuickActions !== 'undefined')
      QuickActions.bindArticle(article, _nvdMap[article.id] || null);

    document.getElementById('art-modal-fav')
      ?.addEventListener('click', () => {
        const isNow = UI.toggleFav(article.id);
        const btn   = document.getElementById('art-modal-fav');
        if (!btn) return;
        btn.classList.toggle('active', isNow);
        btn.innerHTML = isNow ? '★ Favorite' : '☆ Favorite';
        btn.title     = isNow ? 'Remove from favorites' : 'Add to favorites';
      });

    // Workflow analyste — statut, note, owner
    if (typeof EntityStatus !== 'undefined') {
      content.querySelectorAll('.es-block .es-select').forEach(sel => {
        sel.addEventListener('change', e => {
          EntityStatus.setStatus('article', article.id, e.target.value);
        });
      });
      content.querySelectorAll('.es-block .es-note-input').forEach(inp => {
        inp.addEventListener('blur', e => {
          EntityStatus.updateNote('article', article.id, e.target.value);
        });
        inp.addEventListener('keydown', e => { if (e.key === 'Enter') e.target.blur(); });
      });
      content.querySelectorAll('.es-block .es-owner-input').forEach(inp => {
        inp.addEventListener('blur', e => {
          EntityStatus.updateOwner('article', article.id, e.target.value);
        });
        inp.addEventListener('keydown', e => { if (e.key === 'Enter') e.target.blur(); });
      });
      content.querySelectorAll('.es-block .es-actor-input').forEach(inp => {
        inp.addEventListener('blur', e => {
          EntityStatus.updateThreatActor('article', article.id, e.target.value);
        });
        inp.addEventListener('keydown', e => { if (e.key === 'Enter') e.target.blur(); });
      });
    }

    // Deep IOC scan — only on Vercel (USE_API=true), where /api/article-body is available
    if (typeof CONFIG !== 'undefined' && CONFIG.USE_API) {
      document.getElementById('art-ioc-deep-btn')
        ?.addEventListener('click', () => _fetchDeepIOCs(article));
    }

    modal.style.display = 'flex';
    document.body.classList.add('modal-open');
    content.scrollTop = 0;
  }

  function close() {
    const modal = document.getElementById('modal-article');
    if (modal) modal.style.display = 'none';
    document.body.classList.remove('modal-open');
  }

  // ─── Construction du contenu ───────────────────────────────────────────────

  function _buildContent(article) {
    const m       = _critMeta(article.criticality);
    const nvd     = _nvdMap[article.id] || null;
    const similar = _findSimilar(article);
    const isFav   = Storage.isFavorite(article.id);
    const dateStr = article.pubDate.toLocaleDateString('en-US', {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
    });

    return `
      <!-- ── EN-TÊTE ─────────────────────────────────────────────────── -->
      <div class="art-modal-head">
        <div class="art-modal-badges">
          <span class="badge ${m.cssClass}">${m.icon} ${m.label}</span>
          <span class="badge badge-source">${article.sourceIcon || ''} ${_esc(article.sourceName)}</span>
          ${article.isKEV      ? `<span class="badge badge-kev">⚠ KEV</span>` : ''}
          ${article.isTrending ? `<span class="badge badge-trending">🔥 Trending×${article.trendingCount}</span>` : ''}
          ${article.watchlistMatches?.length ? `<span class="badge badge-watchlist">👁 Watchlist</span>` : ''}
        </div>
        <h2 class="art-modal-title">${_esc(article.title)}</h2>
        <div class="art-modal-sub">
          <span>📅 ${dateStr}</span>
          ${article.score != null ? `<span>⚡ Score : <strong>${article.score}/100</strong></span>` : ''}
        </div>
      </div>

      <!-- ── CORPS ──────────────────────────────────────────────────── -->
      <div class="art-modal-body">

        <!-- Colonne gauche : priorité, métriques, CVEs, ATT&CK -->
        <div class="art-modal-left">

          ${_renderPriorityBlock(article)}

          <div class="art-modal-section">
            <h4 class="art-modal-section-title">📊 Security metrics</h4>
            ${_renderMetrics(article, nvd)}
          </div>

          ${(article.cves || []).length ? `
          <div class="art-modal-section">
            <h4 class="art-modal-section-title">🔍 Detected CVEs (${article.cves.length})</h4>
            ${_renderCVEs(article.cves, nvd)}
          </div>` : ''}

          ${(article.attackTags || []).length ? `
          <div class="art-modal-section">
            <h4 class="art-modal-section-title">🎯 MITRE ATT&CK</h4>
            ${_renderAttack(article.attackTags)}
          </div>` : ''}

          ${article.watchlistMatches?.length ? `
          <div class="art-modal-section">
            <h4 class="art-modal-section-title">👁 Watchlist — matched terms</h4>
            <div class="art-watchlist-matches">
              ${article.watchlistMatches.map(w =>
                `<span class="badge badge-watchlist">${_esc(w)}</span>`
              ).join(' ')}
            </div>
          </div>` : ''}

          <div class="art-modal-section" id="art-ioc-section">
            <h4 class="art-modal-section-title">🔬 Extracted IOCs${article.iocCount > 0 ? ` (${article.iocCount})` : ''}</h4>
            ${article.iocCount > 0
              ? _renderIOCPanel(article.iocs)
              : '<p class="art-metric-na">No IOC detected in RSS summary.</p>'}
            ${(typeof CONFIG !== 'undefined' && CONFIG.USE_API) ? `
            <button id="art-ioc-deep-btn" class="btn art-ioc-deep-btn"
                    title="Fetch full article body and re-scan for IOCs (server-side)">
              🔍 Deep IOC scan
            </button>` : ''}
          </div>

        </div>

        <!-- Colonne droite : description, similaires -->
        <div class="art-modal-right">

          ${article.description ? `
          <div class="art-modal-section">
            <h4 class="art-modal-section-title">📝 Description</h4>
            <p class="art-modal-desc">${_esc(article.description)}</p>
          </div>` : ''}

          ${similar.length ? `
          <div class="art-modal-section">
            <h4 class="art-modal-section-title">🔗 Similar articles</h4>
            <div class="art-similar-list">
              ${similar.map(a => {
                const sm = _critMeta(a.criticality);
                return `
                  <div class="art-similar-item" data-id="${a.id}" role="button" tabindex="0"
                       title="Open this article">
                    <div class="art-similar-meta">
                      <span class="badge ${sm.cssClass} art-badge-xs">${sm.icon}</span>
                      <span class="art-similar-source">${_esc(a.sourceName)}</span>
                      <span class="art-similar-date">${a.pubDate.toLocaleDateString('en-US')}</span>
                    </div>
                    <div class="art-similar-title">${_esc(a.title)}</div>
                  </div>`;
              }).join('')}
            </div>
          </div>` : ''}

        </div>
      </div>

      <!-- ── RECOMMANDATIONS ──────────────────────────────────────────── -->
      ${typeof Recommender !== 'undefined' ? Recommender.renderHTML(article, 'article') : ''}

      <!-- ── WORKFLOW ANALYSTE ─────────────────────────────────────────── -->
      ${typeof EntityStatus !== 'undefined' ? `
      <div class="art-modal-section art-workflow-section">
        <h4 class="art-modal-section-title">📋 Analyst workflow</h4>
        ${EntityStatus.statusBlockHTML('article', article.id)}
      </div>` : ''}

      <!-- ── TREND SEARCH RESULTS (populated on demand) ────────────────── -->
      <div id="art-trend-search-result" class="art-trend-search-result" style="display:none"></div>

      <!-- ── PIED DE PAGE ────────────────────────────────────────────── -->
      <!-- Sprint 23 : footer rationalisé — 3 éléments : Favoris · ⚡ Actions · ↗ Ouvrir -->
      <!-- Le bouton IOC (art-modal-copy-ioc) est désormais dans le dropdown ⚡ Actions   -->
      <div class="art-modal-footer">
        <button id="art-modal-fav" class="btn ${isFav ? 'active' : ''}"
                title="${isFav ? 'Remove from favorites' : 'Add to favorites'}">
          ${isFav ? '★ Favorite' : '☆ Favorite'}
        </button>
        ${typeof QuickActions !== 'undefined'
          ? QuickActions.articleButtonsHTML({
              showIoc: (article.iocCount || 0) > 0,
              articleId: article.id,
              showTrendSearch: typeof TrendSearch !== 'undefined' && TrendSearch.hasIndicators(article)
            })
          : ''}
        <a href="${article.link}" target="_blank" rel="noopener noreferrer"
           class="btn btn-primary art-modal-open-btn">
          ↗ Open article
        </a>
      </div>`;
  }

  // ─── Bloc priorité explicable ──────────────────────────────────────────────

  function _renderPriorityBlock(article) {
    // Tolère l'absence de priorityLevel (cache ancien, mode démo)
    if (!article.priorityLevel) return '';

    const pm      = typeof getPriorityMeta === 'function'
                    ? getPriorityMeta(article.priorityLevel)
                    : { icon: '⚪', label: article.priorityLevel, css: 'low' };
    const reasons = article.priorityReasons || [];
    const signals = article.prioritySignals || {};

    // Tableau de signaux complémentaires (données brutes, lisibles)
    const sigRows = [];
    if (signals.kev)
      sigRows.push(['CISA KEV',  '✅ Exploitation confirmed']);
    if (signals.epss !== null && signals.epss !== undefined)
      sigRows.push(['EPSS',      `${signals.epss}% exploitation probability (30d)`]);
    if (signals.isZeroDay)
      sigRows.push(['0-Day',     'No official patch available']);
    if (signals.watchlist)
      sigRows.push(['Watchlist', 'Watchlist term matched']);
    if (signals.trending)
      sigRows.push(['Trending',  `${signals.sources} concurrent sources`]);
    if (signals.iocCount > 0)
      sigRows.push(['IOCs',      `${signals.iocCount} indicator${signals.iocCount > 1 ? 's' : ''} extracted`]);
    if (signals.baseScore != null)
      sigRows.push(['Score',     `${signals.baseScore}/100`]);

    return `
      <div class="art-modal-section">
        <h4 class="art-modal-section-title">🎯 Why this priority?</h4>
        <div class="art-priority-block">
          <div class="art-priority-level-badge prio-${pm.css}">
            ${pm.icon} ${pm.label}
          </div>
          ${reasons.length ? `
          <ul class="art-priority-reasons">
            ${reasons.map(r => `<li>${_esc(r)}</li>`).join('')}
          </ul>` : `<p class="art-priority-no-reason">No significant signal detected.</p>`}
          ${sigRows.length ? `
          <table class="art-priority-signals">
            ${sigRows.map(([k, v]) => `
              <tr>
                <td class="art-psig-key">${_esc(k)}</td>
                <td class="art-psig-val">${_esc(v)}</td>
              </tr>`).join('')}
          </table>` : ''}
        </div>
      </div>`;
  }

  // ─── Bloc métriques ────────────────────────────────────────────────────────

  function _renderMetrics(article, nvd) {
    const rows = [];

    // Score composite
    if (article.score != null) {
      const colorCls = article.score >= 70 ? 'err' : article.score >= 40 ? 'warn' : 'ok';
      rows.push(`
        <div class="art-metric-row">
          <span class="art-metric-label">Composite score</span>
          <div class="art-metric-bar-wrap" title="${article.score}/100">
            <div class="art-metric-bar art-bar-${colorCls}" style="width:${article.score}%"></div>
          </div>
          <span class="art-metric-val">${article.score}/100</span>
        </div>`);
    }

    // CVSS (NVD)
    if (nvd?.score != null) {
      const cls = _cvssClass(nvd.score);
      rows.push(`
        <div class="art-metric-row">
          <span class="art-metric-label">CVSS v3.1</span>
          <span class="badge ${cls}" title="${nvd.vector || 'CVSS vector'}">
            ${nvd.score.toFixed(1)} ${nvd.severity || ''}
          </span>
          ${nvd.cwe ? `<span class="badge badge-cwe" title="CWE">${nvd.cwe}</span>` : ''}
          ${nvd.vector
            ? `<span class="art-metric-vector" title="${nvd.vector}">${nvd.vector.slice(0,30)}…</span>`
            : ''}
        </div>`);
    } else {
      rows.push(`
        <div class="art-metric-row">
          <span class="art-metric-label">CVSS v3.1</span>
          <span class="art-metric-na">— Pending NVD enrichment</span>
        </div>`);
    }

    // EPSS avec jauge
    if (article.epssScore != null) {
      const pct   = (article.epssScore * 100).toFixed(1);
      const perc  = article.epssPercentile != null
        ? `(${(article.epssPercentile * 100).toFixed(0)}th percentile)`
        : '';
      // Normalisation visuelle : 50% EPSS = 100% barre
      const barW  = Math.min(article.epssScore * 200, 100);
      const barCls = article.epssScore >= 0.5 ? 'err' : article.epssScore >= 0.1 ? 'warn' : 'ok';
      rows.push(`
        <div class="art-metric-row">
          <span class="art-metric-label">EPSS</span>
          <div class="art-metric-bar-wrap" title="EPSS: ${pct}% ${perc}">
            <div class="art-metric-bar art-bar-${barCls}" style="width:${barW}%"></div>
          </div>
          <span class="art-metric-val">${pct}% <small>${perc}</small></span>
        </div>
        <p class="art-metric-hint">Exploitation probability in the next 30 days (FIRST.org)</p>`);
    }

    // KEV
    rows.push(`
      <div class="art-metric-row">
        <span class="art-metric-label">CISA KEV</span>
        ${article.isKEV
          ? `<span class="badge badge-kev">✅ Active exploitation confirmed</span>`
          : `<span class="art-metric-na">— Not listed</span>`}
      </div>`);

    return `<div class="art-metrics">${rows.join('')}</div>`;
  }

  // ─── Bloc CVEs ─────────────────────────────────────────────────────────────

  function _renderCVEs(cves, nvd) {
    return `<div class="art-cve-list">
      ${cves.map(cve => {
        const isEnriched = nvd?.cveId === cve;
        return `
          <div class="art-cve-row">
            <a href="https://nvd.nist.gov/vuln/detail/${cve}"
               target="_blank" rel="noopener" class="art-cve-id">
              ${cve} ↗
            </a>
            ${isEnriched && nvd.score != null
              ? `<span class="badge ${_cvssClass(nvd.score)}" title="${nvd.vector || ''}">
                   CVSS ${nvd.score.toFixed(1)}
                 </span>
                 ${nvd.cwe ? `<span class="badge badge-cwe">${nvd.cwe}</span>` : ''}`
              : ''}
          </div>`;
      }).join('')}
    </div>`;
  }

  // ─── Bloc ATT&CK ──────────────────────────────────────────────────────────

  function _renderAttack(tags) {
    // Grouper par tactique
    const byTactic = {};
    tags.forEach(t => {
      if (!byTactic[t.tactic]) byTactic[t.tactic] = [];
      byTactic[t.tactic].push(t);
    });

    return `<div class="art-attack-list">
      ${Object.entries(byTactic).map(([tactic, techniques]) => `
        <div class="art-attack-group">
          <div class="art-attack-tactic-label">${tactic}</div>
          <div class="art-attack-techniques">
            ${techniques.map(t =>
              `<span class="badge badge-attack" title="Tactique : ${t.tactic}">${t.label}</span>`
            ).join('')}
          </div>
        </div>`).join('')}
    </div>`;
  }

  // ─── Panneau IOCs complet (modal) ─────────────────────────────────────────

  function _renderIOCPanel(iocs) {
    if (!iocs) return '<p class="art-metric-na">No IOC detected.</p>';

    const { ips = [], hashes = [], domains = [], urls = [] } = iocs;
    const sections = [];

    const _iocRow = (type, icon, cssType, value, displayVal) => {
      const copyEsc = (value || '').replace(/'/g, "\\'");
      const shortDisplay = displayVal || value;
      return `
        <div class="art-ioc-row">
          <span class="art-ioc-type art-ioc-${cssType}">${icon} ${type}</span>
          <code class="art-ioc-val" title="${_esc(value)}">${_esc(shortDisplay)}</code>
          <button class="art-ioc-copy-btn"
                  onclick="IOCExtractor.copyIOC('${type}','${copyEsc}')"
                  title="Copy">📋</button>
        </div>`;
    };

    if (hashes.length) {
      sections.push(`<div class="art-ioc-group">
        <div class="art-ioc-group-label">🔑 Hashes (${hashes.length})</div>
        ${hashes.map(h => _iocRow(h.type, '🔑', 'hash',
          h.value,
          h.value.slice(0, 16) + '…' + h.value.slice(-8)
        )).join('')}
      </div>`);
    }

    if (ips.length) {
      sections.push(`<div class="art-ioc-group">
        <div class="art-ioc-group-label">🌐 IP Addresses (${ips.length})</div>
        ${ips.map(ip => _iocRow('IP', '🌐', 'ip', ip, ip)).join('')}
      </div>`);
    }

    if (domains.length) {
      sections.push(`<div class="art-ioc-group">
        <div class="art-ioc-group-label">🔗 Domains (${domains.length})</div>
        ${domains.map(d => _iocRow('Domain', '🔗', 'domain', d, d)).join('')}
      </div>`);
    }

    if (urls.length) {
      sections.push(`<div class="art-ioc-group">
        <div class="art-ioc-group-label">🕸 URLs (${urls.length})</div>
        ${urls.map(u => _iocRow('URL', '🕸', 'url', u,
          u.length > 48 ? u.slice(0, 45) + '…' : u
        )).join('')}
      </div>`);
    }

    return sections.length
      ? `<div class="art-ioc-panel">${sections.join('')}</div>`
      : '<p class="art-metric-na">No IOC detected in this text.</p>';
  }

  // ─── Deep IOC scan (Option B — fetch corps complet via backend) ───────────
  //
  // Appelle /api/article-body?url=<encoded> pour récupérer le texte brut de l'article
  // complet, puis relance IOCExtractor.enrichArticle() avec ce texte supplémentaire.
  // Met à jour le panneau IOC dans le modal sans rechargement.

  async function _fetchDeepIOCs(article) {
    const btn   = document.getElementById('art-ioc-deep-btn');
    const panel = document.getElementById('art-ioc-section');
    if (!btn || !panel) return;

    btn.disabled    = true;
    btn.textContent = '⏳ Scanning…';

    try {
      const resp = await fetch(`/api/article-body?url=${encodeURIComponent(article.link)}`, {
        signal: AbortSignal.timeout(15_000)
      });
      if (!resp.ok) {
        const { error } = await resp.json().catch(() => ({}));
        throw new Error(error || `HTTP ${resp.status}`);
      }
      const { text, chars } = await resp.json();

      // Re-run extraction with full article body
      if (typeof IOCExtractor === 'undefined') throw new Error('IOCExtractor not loaded');
      const enriched = IOCExtractor.enrichArticle(article, text);

      // Update article in place so _copyIOCs() picks up the new IOCs
      article.iocs     = enriched.iocs;
      article.iocCount = enriched.iocCount;

      // Re-render the IOC section
      const note = `<p class="art-ioc-deep-note">📄 ${(chars || 0).toLocaleString()} chars scanned from full article</p>`;
      if (enriched.iocCount > 0) {
        panel.innerHTML = `
          <h4 class="art-modal-section-title">🔬 Extracted IOCs (${enriched.iocCount}) <span class="badge badge-new">Full scan</span></h4>
          ${_renderIOCPanel(enriched.iocs)}
          ${note}`;
      } else {
        panel.innerHTML = `
          <h4 class="art-modal-section-title">🔬 Extracted IOCs</h4>
          <p class="art-metric-na">No IOC detected after full article scan.</p>
          ${note}`;
      }

      if (window.UI) UI.showToast(
        `🔬 Deep scan: ${enriched.iocCount} IOC${enriched.iocCount !== 1 ? 's' : ''} found`,
        enriched.iocCount > 0 ? 'success' : 'info'
      );

    } catch (err) {
      btn.disabled    = false;
      btn.textContent = '🔍 Deep IOC scan';
      if (window.UI) UI.showToast(`⚠ Deep scan failed: ${err.message}`, 'error');
    }
  }

  // ─── Algorithme articles similaires ───────────────────────────────────────

  function _findSimilar(article) {
    if (!_articles.length) return [];

    const STOPWORDS = new Set([
      'the','a','an','in','of','on','for','with','and','or','is','to','by','are','has','new',
      'le','la','les','de','du','des','en','et','ou','un','une','sur','par','dans','une',
      'via','using','how','its','that','this','from','was','use','used','exploit','zero'
    ]);

    const cveSet   = new Set(article.cves || []);
    const titleW   = new Set(
      article.title.toLowerCase().split(/\W+/).filter(w => w.length > 3 && !STOPWORDS.has(w))
    );

    const score = (a) => {
      // CVEs partagés (poids 4 chacun)
      const cveScore = (a.cves || []).filter(c => cveSet.has(c)).length * 4;
      // Mots-clés titre partagés (poids 1 chacun)
      const words    = a.title.toLowerCase().split(/\W+/).filter(w => w.length > 3 && !STOPWORDS.has(w));
      const wScore   = words.filter(w => titleW.has(w)).length;
      // ATT&CK partagés (poids 2 chacun)
      const atkSet   = new Set((article.attackTags || []).map(t => t.label));
      const atkScore = (a.attackTags || []).filter(t => atkSet.has(t.label)).length * 2;
      return cveScore + wScore + atkScore;
    };

    return _articles
      .filter(a => a.id !== article.id)
      .map(a => ({ a, s: score(a) }))
      .filter(({ s }) => s >= 2)
      .sort((x, y) => y.s - x.s)
      .slice(0, 4)
      .map(({ a }) => a);
  }

  // ─── Copier IOCs ──────────────────────────────────────────────────────────

  async function _copyIOCs(article) {
    const lines = [
      `# ThreatLens — IOCs`,
      `# Titre   : ${article.title}`,
      `# Source  : ${article.sourceName}`,
      `# Date    : ${article.pubDate.toLocaleDateString('en-US')}`,
      `# URL     : ${article.link}`,
      ''
    ];

    // CVEs (enrichisseur RSS)
    if (article.cves?.length) {
      lines.push('## CVE IDs', ...article.cves, '');
    }

    // ATT&CK
    if (article.attackTags?.length) {
      lines.push('## MITRE ATT&CK');
      article.attackTags.forEach(t => lines.push(`${t.label}  [${t.tactic}]`));
      lines.push('');
    }

    // IOCs extraits par le pipeline (ioc-extractor.js)
    const iocs = article.iocs || {};
    if (iocs.hashes?.length) {
      lines.push('## Hashes');
      iocs.hashes.forEach(h => lines.push(`${h.type}:${h.value}`));
      lines.push('');
    }
    if (iocs.ips?.length) {
      lines.push('## IP Addresses', ...iocs.ips, '');
    }
    if (iocs.domains?.length) {
      lines.push('## Domains', ...iocs.domains, '');
    }
    if (iocs.urls?.length) {
      lines.push('## URLs', ...iocs.urls, '');
    }

    const payload = lines.join('\n');
    const total   = (article.cves?.length || 0) + (article.attackTags?.length || 0)
                  + (article.iocCount || 0);

    try {
      await navigator.clipboard.writeText(payload);
    } catch {
      const ta = Object.assign(document.createElement('textarea'), {
        value: payload, style: 'position:fixed;top:-9999px;opacity:0'
      });
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }

    if (window.UI) UI.showToast(`📋 ${total} IOC${total > 1 ? 's' : ''} copied (CVEs, hashes, IPs, domains)`, 'success');
  }

  // ─── Initialisation ────────────────────────────────────────────────────────

  function init() {
    _injectModalDOM();
    _bindGlobalEvents();
    _bindCardClickDelegation();
  }

  function _injectModalDOM() {
    if (document.getElementById('modal-article')) return;
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div id="modal-article" class="art-modal-overlay" style="display:none"
           onclick="if(event.target===this)ArticleModal.close()">
        <div class="art-modal-box">
          <button class="modal-close art-modal-close-btn"
                  onclick="ArticleModal.close()" title="Close (Esc)">✕</button>
          <div id="art-modal-content" class="art-modal-scroll"></div>
        </div>
      </div>`;
    document.body.appendChild(wrap.firstElementChild);
  }

  function _bindGlobalEvents() {
    // Fermer avec Échap
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') close();
    });

    // Navigation article similaire (délégation globale)
    document.addEventListener('click', e => {
      const similar = e.target.closest('.art-similar-item');
      if (!similar) return;
      const id = similar.dataset.id;
      if (id) openById(id);
    });

    // Keyboard nav sur les similaires (accessibilité)
    document.addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      const similar = e.target.closest('.art-similar-item');
      if (!similar) return;
      const id = similar.dataset.id;
      if (id) openById(id);
    });
  }

  function _bindCardClickDelegation() {
    // Délégation sur la grille — ouvrir le modal au clic (hors liens et étoile)
    const grid = document.getElementById('feed-grid');
    if (!grid) return;

    grid.addEventListener('click', e => {
      if (e.target.closest('.btn-star')) return;  // bouton favori
      if (e.target.closest('a'))         return;  // liens (titre)
      if (e.target.closest('[onclick]'))  return;  // onclick explicites

      const card = e.target.closest('.card[data-id]');
      if (!card) return;
      openById(card.dataset.id);
    });
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  function _critMeta(c) {
    if (c === 'high')   return { cssClass: 'badge-high',   icon: '🔴', label: 'HIGH'    };
    if (c === 'medium') return { cssClass: 'badge-medium', icon: '🟠', label: 'MEDIUM'  };
    return                     { cssClass: 'badge-low',    icon: '🟢', label: 'LOW'     };
  }

  function _cvssClass(s) {
    if (s >= 9) return 'badge-cvss-critical';
    if (s >= 7) return 'badge-cvss-high';
    if (s >= 4) return 'badge-cvss-medium';
    return 'badge-cvss-low';
  }

  function _esc(str) {
    return (str || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  return { init, open, openById, close, setArticles };
})();
