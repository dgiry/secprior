// quick-actions.js — Actions rapides de sortie opérationnelle CyberVeille Pro
//
// Fournit, sans backend ni dépendance externe :
//   • Résumé analyste (article / incident) — format texte détaillé, orienté action
//   • Résumé exécutif (article / incident) — format texte court, orienté risque/impact
//   • Payload incident enrichi (JSON structuré, réutilisable, stub ticket intégré)
//   • Ticket prêt à créer (texte éditable + JSON exportable) — Sprint 18
//   • Partage court Slack/Teams — 5-7 lignes, copie en un clic — Sprint 22
//   • Brief email interne — format structuré avec ligne Objet — Sprint 22
//   • Copie presse-papiers fiable (Clipboard API + fallback execCommand)
//   • HTML des boutons d'action rapide à injecter dans la modal et le panneau incident
//
// Intégration :
//   • article-modal.js → QuickActions.articleButtonsHTML() dans le footer
//                        QuickActions.bindArticle(article, nvd) dans open()
//   • incident-panel.js → QuickActions.incidentButtonsHTML(id) dans _rowHTML()
//                         QuickActions.bindIncidentPanel(container, cache) dans _render()
//
// Stub ticket (_ticketStub dans le payload JSON) :
//   Structure prête pour une future intégration ITSM (Jira, ServiceNow, etc.)
//   Les champs externalId / externalUrl / syncedAt sont réservés pour la sync.
//
// Sprint 18 — Ticket-Ready Output :
//   • _ticketDraftText(entity, sourceType, nvdData) — ticket texte éditable
//   • ticketDraftJSON(entity, sourceType, nvdData)  — JSON structuré (API publique)
//   • _showTicketModal(entity, sourceType, nvdData) — modal de prévisualisation
//   Le format ticket est distinct du résumé analyste (opérationnel complet)
//   et du résumé exécutif (court, orienté risque). Le ticket est orienté ITSM :
//   structuré, champs nommés, prêt à coller dans Jira / ServiceNow / email.
//
// Sprint 22 — Partage enrichi :
//   • _shareShortArticle(article)   — format court Slack/Teams (plain text)
//   • _shareShortIncident(incident) — idem pour incidents
//   • _emailBriefArticle(article)   — brief email interne avec ligne Objet
//   • _emailBriefIncident(incident) — idem pour incidents
//   • _shareMarkdown*(entity)       — markdown enrichi pour webhooks Slack-compat
//   • _showShareModal(entity, type) — modal compact avec onglets Slack / Email
//   Les payloads JSON (ticket + incident) sont enrichis d'un bloc _share :
//     { shortText, markdownText, emailSubject, emailText }

const QuickActions = (() => {

  // ── Helpers internes ──────────────────────────────────────────────────────

  function _fmt(date) {
    if (!date) return '—';
    try {
      return (date instanceof Date ? date : new Date(date))
        .toLocaleString('en-US', {
          day: '2-digit', month: '2-digit', year: 'numeric',
          hour: '2-digit', minute: '2-digit'
        });
    } catch { return String(date); }
  }

  function _pct(val) {
    if (val == null) return null;
    return `${(val * 100).toFixed(1)}%`;
  }

  function _prioLabel(level) {
    const map = {
      critical_now: 'CRITICAL — Immediate action',
      investigate:  'HIGH — Investigation required',
      watch:        'MEDIUM — Enhanced monitoring',
      low:          'LOW — Standard monitoring'
    };
    return map[level] || level || '—';
  }

  function _critLabel(c) {
    if (c === 'high')   return 'HIGH 🔴';
    if (c === 'medium') return 'MEDIUM 🟠';
    return 'LOW 🟢';
  }

  function _actionFromLevel(level) {
    if (level === 'critical_now')
      return 'Immediate patch required — escalate to CISO and infrastructure teams.';
    if (level === 'investigate')
      return 'Investigation recommended — analyze exposed systems and confirm scope.';
    if (level === 'watch')
      return 'Enhanced monitoring — track indicators and prepare a response plan.';
    return 'Standard monitoring — include in the next periodic report.';
  }

  function _now() {
    return new Date().toLocaleString('en-US', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  }

  function _ticketPriority(level) {
    const map = { critical_now: 'P1', investigate: 'P2', watch: 'P3', low: 'P4' };
    return map[level] || 'P3';
  }

  function _ticketSeverity(level) {
    const map = { critical_now: 'critical', investigate: 'high', watch: 'medium', low: 'low' };
    return map[level] || 'medium';
  }

  // Emoji de niveau priorité — utilisé dans les formats de partage (Sprint 22)
  function _prioEmoji(level) {
    const map = { critical_now: '🔴', investigate: '🟠', watch: '🟡', low: '🟢' };
    return map[level] || '⚪';
  }

  // ── Helpers de lisibilité (Sprint 19) ────────────────────────────────────

  // Troncature propre avec indicateur "…"
  function _truncate(text, max) {
    if (!text) return '';
    const t = text.trim().replace(/\s+/g, ' ');
    return t.length <= max ? t : t.slice(0, max - 1) + '…';
  }

  // Filtre les raisons de priorité qui doublent des signaux déjà explicitement affichés.
  // coveredKw : tableau de mots-clés bas-de-casse déjà présents dans les highlights.
  // Règle prudente : on ne supprime que si la raison CONTIENT un des mots-clés couverts
  // ET que son information est redondante (pas de suppression si raison plus riche).
  function _dedupeReasons(reasons, coveredKw) {
    if (!reasons.length || !coveredKw.length) return reasons;
    const kwLc = coveredKw.map(k => k.toLowerCase());
    return reasons.filter(r => {
      const rl = r.toLowerCase();
      // Supprimer seulement si la raison est entièrement couverte (contient le mot-clé
      // couvert ET est courte = pas d'info supplémentaire significative)
      return !kwLc.some(kw => rl.includes(kw) && r.length < 80);
    });
  }

  // Actions recommandées contextuelles selon niveau + signaux disponibles
  // Sprint 19 : suppression de la ligne CVE (déjà dans SIGNAUX DÉCLENCHEURS du ticket),
  //             IOCs seulement si >= 2, max 4 actions au total.
  function _ticketActions(entity, sourceType) {
    const level = sourceType === 'incident'
      ? entity.incidentPriorityLevel : entity.priorityLevel;
    const acts = [];
    if (level === 'critical_now') {
      acts.push('Apply available patch urgently — max delay 24h.');
      acts.push('Isolate exposed systems if patch not yet available.');
      acts.push('Escalate to CISO and infrastructure teams.');
    } else if (level === 'investigate') {
      acts.push('Analyze potentially exposed systems.');
      acts.push('Confirm impact scope before remediation.');
      acts.push('Prepare a remediation plan and activate within 72h.');
    } else if (level === 'watch') {
      acts.push('Monitor indicators over the next 7 days.');
      acts.push('Prepare a response plan if escalation detected.');
    } else {
      acts.push('Include in the next periodic monitoring report.');
    }
    // IOCs : seulement si >= 2 (1 seul IOC ne justifie pas une action dédiée)
    const iocCnt = entity.iocCount || entity.rawIocCount || 0;
    if (iocCnt >= 2)
      acts.push(`Analyze the ${iocCnt} extracted IOCs.`);
    // CVEs intentionnellement omis : déjà listés dans SIGNAUX DÉCLENCHEURS du ticket
    return acts.slice(0, 4); // max 4 actions
  }

  // ── Ticket-ready — texte formaté (éditable) ──────────────────────────────
  //
  // Distinct de :
  //   • Résumé analyste : opérationnel complet, multi-section, verbose
  //   • Résumé exécutif : court, orienté risque/décision RSSI
  //   • ticketDraftText : orienté ITSM — titre, sévérité, scope, actions, refs

  function _ticketDraftText(entity, sourceType, nvdData) {
    const isInc = sourceType === 'incident';
    const level = isInc ? entity.incidentPriorityLevel : entity.priorityLevel;
    const prio  = _ticketPriority(level);
    const sep   = '═'.repeat(52);
    const sep2  = '─'.repeat(52);
    const lines = [sep, 'SECURITY TICKET — CyberVeille Pro', sep, ''];

    lines.push(`[${prio}] ${entity.title || '—'}`);
    lines.push(`Type      : ${isInc ? 'incident' : 'vulnerability'}`);
    lines.push(`Severity  : ${_prioLabel(level)} (${prio})`);
    lines.push('');

    // Résumé opérationnel — limité à 280 caractères pour rester concis
    const summary = _truncate(entity.summary || entity.description || '', 280);
    if (summary) {
      lines.push('OPERATIONAL SUMMARY');
      lines.push(`  ${summary}`);
      lines.push('');
    }

    // Signaux déclencheurs — uniquement les signaux positifs ou à valeur significative
    const sigLines = [];
    const isKEV = isInc ? entity.kev : entity.isKEV;
    if (isKEV)
      sigLines.push(`  • CISA KEV  : YES — active exploitation confirmed`);
    const epss = isInc ? entity.maxEpss : entity.epssScore;
    if (epss != null)
      sigLines.push(`  • EPSS      : ${_pct(epss)} exploitation probability (30d)`);
    if (nvdData?.score != null)
      sigLines.push(`  • CVSS 3.1  : ${nvdData.score.toFixed(1)} (${nvdData.severity || '?'})`);
    const cves = entity.cves || entity.cveIds || [];
    if (cves.length)
      sigLines.push(`  • CVEs      : ${cves.join(', ')}`);
    const atkTags = (entity.attackTags || [])
      .map(t => typeof t === 'string' ? t : `${t.label} [${t.tactic}]`).slice(0, 4);
    if (atkTags.length)
      sigLines.push(`  • ATT&CK    : ${atkTags.join(', ')}`);
    const sc = isInc ? entity.incidentPriorityScore : entity.priorityScore;
    if (sc != null)
      sigLines.push(`  • Score     : ${sc}/100`);
    if (sigLines.length) {
      lines.push('TRIGGERING SIGNALS');
      sigLines.forEach(s => lines.push(s));
    }
    lines.push('');

    // Périmètre et exposition
    lines.push('SCOPE & EXPOSURE');
    if (isInc) {
      lines.push(`  Articles  : ${entity.articleCount || 0} (${entity.sourceCount || 0} source(s))`);
      if ((entity.vendors || []).length)
        lines.push(`  Vendors   : ${entity.vendors.join(', ')}`);
      if (entity.firstSeen || entity.lastSeen)
        lines.push(`  Timeline  : ${_fmt(entity.firstSeen)} → ${_fmt(entity.lastSeen)}`);
    } else {
      lines.push(`  Source    : ${entity.sourceName || '—'}`);
      lines.push(`  URL       : ${entity.link || '—'}`);
    }

    // Contexte profil actif
    if (typeof ProfileManager !== 'undefined') {
      const p = ProfileManager.getActiveProfile();
      if (p) lines.push(`  Profile   : ${p.badge ? p.badge + ' ' : ''}${p.name}`);
    }
    const wl = entity.watchlistMatches || [];
    if (wl.length)
      lines.push(`  Watchlist : ${wl.join(', ')}`);
    lines.push('');

    // Actions recommandées
    const actions = _ticketActions(entity, sourceType);
    lines.push('RECOMMENDED ACTIONS');
    actions.forEach((a, i) => lines.push(`  ${i + 1}. ${a}`));
    lines.push('');

    // Statut analyste si disponible
    const wsType = isInc ? 'incident' : 'article';
    const wsId   = isInc ? entity.incidentId : entity.id;
    const ws = typeof EntityStatus !== 'undefined'
      ? EntityStatus.getStatus(wsType, wsId) : null;
    if (ws && ws.status) {
      lines.push('ANALYST STATUS');
      lines.push(`  Status      : ${ws.status}`);
      if (ws.owner) lines.push(`  Owner       : ${ws.owner}`);
      if (ws.note)  lines.push(`  Note        : ${ws.note}`);
      lines.push('');
    }

    lines.push('REFERENCES');
    if (!isInc && entity.link) lines.push(`  • ${entity.link}`);
    if (isInc && entity.incidentId) lines.push(`  • Incident ID : ${entity.incidentId}`);
    lines.push(`  • Generated on ${_now()} · CyberVeille Pro`);
    lines.push('');
    lines.push(sep2);

    return lines.join('\n');
  }

  // ── Ticket-ready — JSON structuré (API publique) ──────────────────────────
  //
  // Format cyberveille_ticket_v1 :
  //   Compatible avec les champs standards Jira / ServiceNow.
  //   _itsm : champs à mapper selon l'ITSM cible.
  //   externalId / externalUrl / syncedAt : réservés pour la future sync.

  function ticketDraftJSON(entity, sourceType, nvdData) {
    const isInc = sourceType === 'incident';
    const level = isInc ? entity.incidentPriorityLevel : entity.priorityLevel;
    const cves  = entity.cves || entity.cveIds || [];
    const isKEV = isInc ? entity.kev : entity.isKEV;
    const epss  = isInc ? entity.maxEpss : entity.epssScore;

    const ws = typeof EntityStatus !== 'undefined'
      ? EntityStatus.getStatus(
          isInc ? 'incident' : 'article',
          isInc ? entity.incidentId : entity.id
        ) : null;

    let profileContext = null;
    if (typeof ProfileManager !== 'undefined') {
      const p = ProfileManager.getActiveProfile();
      if (p) profileContext = {
        profileId:    p.id,
        profileName:  p.name,
        profileBadge: p.badge || null,
        watchlistHits: entity.watchlistMatches || []
      };
    }

    const atkTags = (entity.attackTags || [])
      .map(t => typeof t === 'string' ? t : `${t.label} [${t.tactic}]`);

    return {
      schema:      'cyberveille_ticket_v1',
      generatedAt: new Date().toISOString(),
      sourceType,
      ticket: {
        title:    `[SEC] ${entity.title || '—'}`,
        severity: _ticketSeverity(level),
        priority: _ticketPriority(level),
        type:     isInc ? 'incident' : 'vulnerability',
        summary:  (entity.summary || entity.description || entity.title || null),
        scope: {
          cves,
          vendors:      entity.vendors || [],
          attackTags:   atkTags,
          iocCount:     entity.iocCount || entity.rawIocCount || 0,
          articleCount: isInc ? (entity.articleCount || 0) : 1,
          sourceCount:  isInc ? (entity.sourceCount  || 0) : 1,
          sourceRef:    !isInc ? (entity.link || null) : null
        },
        signals: {
          kev:          isKEV || false,
          epss:         epss != null ? parseFloat((epss * 100).toFixed(2)) : null,
          cvssScore:    nvdData?.score    ?? null,
          cvssSeverity: nvdData?.severity ?? null,
          trending:     entity.isTrending || entity.trending || false,
          score:        isInc ? (entity.incidentPriorityScore || null)
                              : (entity.priorityScore || null),
          priorityReasons: entity.priorityReasons || []
        },
        recommendedActions: _ticketActions(entity, sourceType),
        profileContext,
        workflowState: ws ? {
          status:    ws.status    || null,
          owner:     ws.owner     || null,
          note:      ws.note      || null,
          updatedAt: ws.updatedAt || null
        } : null,
        references: isInc ? {
          incidentId: entity.incidentId,
          firstSeen:  entity.firstSeen || null,
          lastSeen:   entity.lastSeen  || null
        } : {
          url:     entity.link       || null,
          source:  entity.sourceName || null,
          pubDate: entity.pubDate
            ? (entity.pubDate instanceof Date
                ? entity.pubDate.toISOString()
                : new Date(entity.pubDate).toISOString())
            : null
        },
        _itsm: {
          _note:      'Adapt to your ITSM (Jira, ServiceNow…). Fill externalId/externalUrl after creation.',
          labels:     ['security', 'cyberveille', ...cves.slice(0, 3)],
          components: (entity.vendors || []).slice(0, 3),
          assignee:   ws?.owner || null,
          externalId:  null,
          externalUrl: null,
          syncedAt:    null
        }
      },
      // ── Sprint 22 — Formats de diffusion enrichis ─────────────────────────
      // Prêts à être utilisés dans des webhooks Slack/Teams/email sortants.
      _share: {
        _note:         'Pre-generated sharing formats. shortText = Slack/Teams. markdownText = Slack-markdown. emailSubject + emailText = internal email.',
        shortText:     isInc ? _shareShortIncident(entity)    : _shareShortArticle(entity),
        markdownText:  isInc ? _shareMarkdownIncident(entity) : _shareMarkdownArticle(entity),
        emailSubject:  (() => {
          const lvl   = isInc ? entity.incidentPriorityLevel : entity.priorityLevel;
          const emoji  = _prioEmoji(lvl);
          const pShort = _prioLabel(lvl).split(' — ')[0] || '—';
          return `[Security Alert] ${emoji} ${pShort} — ${_truncate(entity.title || '', 68)}`;
        })(),
        emailText:     isInc ? _emailBriefIncident(entity)    : _emailBriefArticle(entity)
      }
    };
  }

  // ── Modal ticket-ready ────────────────────────────────────────────────────

  function _injectTicketModalDOM() {
    if (document.getElementById('qa-ticket-modal')) return;
    const el = document.createElement('div');
    el.id        = 'qa-ticket-modal';
    el.className = 'qa-ticket-modal';
    el.style.display = 'none';
    el.innerHTML = `
      <div class="qa-ticket-box">
        <div class="qa-ticket-header">
          <div class="qa-ticket-header-left">
            <span class="qa-ticket-title">🎫 Ticket ready to create</span>
            <span id="qa-ticket-meta" class="qa-ticket-meta"></span>
          </div>
          <button id="qa-ticket-close" class="qa-ticket-close" title="Close">✕</button>
        </div>
        <textarea id="qa-ticket-text" class="qa-ticket-textarea" spellcheck="false"></textarea>
        <div class="qa-ticket-footer">
          <button id="qa-ticket-copy-text" class="btn btn-primary">📋 Copy ticket</button>
          <button id="qa-ticket-copy-json" class="btn">📤 Copy JSON</button>
          <button id="qa-ticket-close-btn" class="btn">Close</button>
        </div>
      </div>`;
    document.body.appendChild(el);
    el.querySelector('#qa-ticket-close')
      .addEventListener('click', _hideTicketModal);
    el.querySelector('#qa-ticket-close-btn')
      .addEventListener('click', _hideTicketModal);
    el.addEventListener('click', e => { if (e.target === el) _hideTicketModal(); });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && document.getElementById('qa-ticket-modal')?.style.display !== 'none')
        _hideTicketModal();
    });
  }

  function _hideTicketModal() {
    const m = document.getElementById('qa-ticket-modal');
    if (m) m.style.display = 'none';
  }

  function _showTicketModal(entity, sourceType, nvdData) {
    _injectTicketModalDOM();
    const modal = document.getElementById('qa-ticket-modal');
    if (!modal) return;

    const level = sourceType === 'incident'
      ? entity.incidentPriorityLevel : entity.priorityLevel;
    const prio  = _ticketPriority(level);
    const text  = _ticketDraftText(entity, sourceType, nvdData || null);
    const json  = ticketDraftJSON(entity, sourceType, nvdData || null);

    // En-tête meta
    const metaEl = document.getElementById('qa-ticket-meta');
    if (metaEl) {
      const sevLabel = _prioLabel(level).split(' — ')[0];
      metaEl.textContent = `${prio} · ${sevLabel}`;
      metaEl.className = `qa-ticket-meta qa-ticket-meta-${_ticketSeverity(level)}`;
    }

    // Textarea éditable
    const ta = document.getElementById('qa-ticket-text');
    if (ta) ta.value = text;

    // Re-bind boutons (cloneNode évite les écouteurs en double)
    const btnText = document.getElementById('qa-ticket-copy-text');
    const btnJson = document.getElementById('qa-ticket-copy-json');
    if (btnText && btnJson) {
      const newBtnText = btnText.cloneNode(true);
      const newBtnJson = btnJson.cloneNode(true);
      btnText.replaceWith(newBtnText);
      btnJson.replaceWith(newBtnJson);
      newBtnText.addEventListener('click', () => {
        const cur = document.getElementById('qa-ticket-text');
        _copy(cur ? cur.value : text, 'Ticket');
      });
      newBtnJson.addEventListener('click', () => {
        _copy(JSON.stringify(json, null, 2), 'Ticket JSON');
      });
    }

    modal.style.display = 'flex';
    if (ta) ta.scrollTop = 0;
  }

  // ── Sprint 22 — Modal de partage (Slack/Teams · Email interne) ──────────

  function _injectShareModalDOM() {
    if (document.getElementById('qa-share-modal')) return;
    const el = document.createElement('div');
    el.id        = 'qa-share-modal';
    el.className = 'qa-share-modal';
    el.style.display = 'none';
    el.innerHTML = `
      <div class="qa-share-box">
        <div class="qa-share-header">
          <span class="qa-share-title">📤 Share</span>
          <div class="qa-share-tabs">
            <button class="qa-share-tab qa-share-tab-active" id="qa-share-tab-slack">
              💬 Slack / Teams
            </button>
            <button class="qa-share-tab" id="qa-share-tab-email">
              ✉️ Internal email
            </button>
          </div>
          <button id="qa-share-close" class="qa-share-close" title="Close">✕</button>
        </div>
        <pre id="qa-share-preview" class="qa-share-preview"></pre>
        <div class="qa-share-footer">
          <button id="qa-share-copy" class="btn btn-primary">📋 Copy</button>
          <button id="qa-share-close-btn" class="btn">Close</button>
        </div>
      </div>`;
    document.body.appendChild(el);
    el.querySelector('#qa-share-close')
      .addEventListener('click', _hideShareModal);
    el.querySelector('#qa-share-close-btn')
      .addEventListener('click', _hideShareModal);
    el.addEventListener('click', e => { if (e.target === el) _hideShareModal(); });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' &&
          document.getElementById('qa-share-modal')?.style.display !== 'none')
        _hideShareModal();
    });
  }

  function _hideShareModal() {
    const m = document.getElementById('qa-share-modal');
    if (m) m.style.display = 'none';
  }

  function _showShareModal(entity, sourceType) {
    _injectShareModalDOM();
    const modal = document.getElementById('qa-share-modal');
    if (!modal) return;

    const isInc   = sourceType === 'incident';
    const slackTx = isInc ? _shareShortIncident(entity)   : _shareShortArticle(entity);
    const emailTx = isInc ? _emailBriefIncident(entity)   : _emailBriefArticle(entity);

    let _currentText = slackTx;

    // Aperçu initial
    const preview = document.getElementById('qa-share-preview');
    if (preview) preview.textContent = slackTx;

    // Onglets — re-bind via cloneNode pour éviter les doublons
    const tabSlack = document.getElementById('qa-share-tab-slack');
    const tabEmail = document.getElementById('qa-share-tab-email');

    const newTabSlack = tabSlack.cloneNode(true);
    const newTabEmail = tabEmail.cloneNode(true);
    tabSlack.replaceWith(newTabSlack);
    tabEmail.replaceWith(newTabEmail);

    newTabSlack.classList.add('qa-share-tab-active');
    newTabEmail.classList.remove('qa-share-tab-active');

    newTabSlack.addEventListener('click', () => {
      _currentText = slackTx;
      if (preview) preview.textContent = slackTx;
      newTabSlack.classList.add('qa-share-tab-active');
      newTabEmail.classList.remove('qa-share-tab-active');
    });
    newTabEmail.addEventListener('click', () => {
      _currentText = emailTx;
      if (preview) preview.textContent = emailTx;
      newTabEmail.classList.add('qa-share-tab-active');
      newTabSlack.classList.remove('qa-share-tab-active');
    });

    // Bouton copier — re-bind
    const btnCopy = document.getElementById('qa-share-copy');
    const newBtnCopy = btnCopy.cloneNode(true);
    btnCopy.replaceWith(newBtnCopy);
    newBtnCopy.addEventListener('click', () => _copy(_currentText, 'Message'));

    modal.style.display = 'flex';
  }

  // ── Résumé analyste — article ─────────────────────────────────────────────

  function _analystSummaryArticle(article, nvdData) {
    const sep  = '═'.repeat(48);
    const sep2 = '─'.repeat(48);
    const lines = [sep, 'ANALYST SUMMARY — CyberVeille Pro', sep, ''];

    lines.push(`Title        : ${article.title || '—'}`);
    lines.push(`Source       : ${article.sourceName || '—'}`);
    lines.push(`Date         : ${_fmt(article.pubDate)}`);
    lines.push(`URL          : ${article.link || '—'}`);
    lines.push('');
    lines.push(`Severity     : ${_critLabel(article.criticality)}`);
    if (article.priorityLevel)
      lines.push(`Priority     : ${_prioLabel(article.priorityLevel)}` +
        (article.priorityScore != null ? ` (score ${article.priorityScore})` : ''));
    lines.push('');

    // Signaux clés
    lines.push('KEY SIGNALS');
    lines.push(`  ▸ KEV CISA : ${article.isKEV
      ? 'YES — active exploitation confirmed (CISA KEV)' : 'No'}`);
    if (article.epssScore != null) {
      const perc = article.epssPercentile != null
        ? ` · ${(article.epssPercentile * 100).toFixed(0)}th percentile` : '';
      lines.push(`  ▸ EPSS     : ${_pct(article.epssScore)} exploitation probability (30d)${perc}`);
    }
    if (nvdData?.score != null)
      lines.push(`  ▸ CVSS 3.1 : ${nvdData.score.toFixed(1)} ${nvdData.severity || ''}` +
        (nvdData.cwe ? ` · ${nvdData.cwe}` : ''));
    const cves = article.cves || article.cveIds || [];
    if (cves.length)
      lines.push(`  ▸ CVEs     : ${cves.join(', ')}`);
    if (article.vendors?.length)
      lines.push(`  ▸ Vendors  : ${article.vendors.join(', ')}`);
    if (article.iocCount > 0)
      lines.push(`  ▸ IOCs     : ${article.iocCount} extracted`);
    if (article.attackTags?.length)
      lines.push(`  ▸ ATT&CK   : ${article.attackTags.map(t => `${t.label} [${t.tactic}]`).join(', ')}`);
    if (article.watchlistMatches?.length)
      lines.push(`  ▸ Watchlist: ${article.watchlistMatches.join(', ')}`);
    if (article.isTrending)
      lines.push(`  ▸ Trending : Yes — ${article.trendingCount || '?'} concurrent sources`);
    lines.push('');

    // Raisons de priorité — dédupliquées par rapport aux signaux déjà affichés
    const _analystKw = [];
    if (article.isKEV)               _analystKw.push('kev', 'cisa', 'exploitation active');
    if (article.epssScore != null)   _analystKw.push('epss');
    (article.cves || article.cveIds || []).forEach(c => _analystKw.push(c.toLowerCase()));
    const reasons = _dedupeReasons(article.priorityReasons || [], _analystKw);
    if (reasons.length) {
      lines.push('PRIORITY REASONS');
      reasons.forEach(r => lines.push(`  ▸ ${r}`));
      lines.push('');
    }

    // Description — limitée à 600 caractères pour éviter les très longs blocs
    if (article.description) {
      lines.push('SUMMARY');
      lines.push(`  ${_truncate(article.description, 600)}`);
      lines.push('');
    }

    // Workflow analyste
    const ws = typeof EntityStatus !== 'undefined'
      ? EntityStatus.getStatus('article', article.id) : null;
    if (ws) {
      lines.push('ANALYST WORKFLOW');
      lines.push(`  Status      : ${ws.status || '—'}`);
      if (ws.owner)     lines.push(`  Owner       : ${ws.owner}`);
      if (ws.note)      lines.push(`  Note        : ${ws.note}`);
      if (ws.updatedAt) lines.push(`  Updated     : ${_fmt(ws.updatedAt)}`);
      lines.push('');
    }

    lines.push(sep2);
    lines.push(`Generated on ${_now()} · CyberVeille Pro`);

    return lines.join('\n');
  }

  // ── Résumé exécutif — article ─────────────────────────────────────────────
  // Sprint 19 : restructuré pour public non-technique (manager / RSSI).
  // Structure : titre → niveau de risque → contexte court → signaux critiques → décision.
  // Suppression des métadonnées techniques (source, date d'article) non pertinentes ici.

  function _execSummaryArticle(article) {
    const sep  = '─'.repeat(44);
    const lines = ['🛡 EXECUTIVE SUMMARY', sep, ''];

    // Titre et niveau
    lines.push(article.title || '—');
    lines.push('');
    const prioShort = _prioLabel(article.priorityLevel).split(' — ')[0] || '—';
    const critStr   = article.criticality === 'high' ? 'HIGH'
                    : article.criticality === 'medium' ? 'MEDIUM' : 'LOW';
    lines.push(`Severity ${critStr}  ·  Priority ${prioShort}`
      + (article.priorityScore != null ? `  ·  Score ${article.priorityScore}/100` : ''));

    // Description courte si disponible (150 chars max — résumé en une phrase)
    const desc = _truncate(article.description || '', 150);
    if (desc) {
      lines.push('');
      lines.push(`  ${desc}`);
    }
    lines.push('');

    // Signaux critiques — uniquement ceux à valeur pour un manager
    const highlights  = [];
    const coveredKw   = []; // pour déduplication des raisons
    if (article.isKEV) {
      highlights.push('⚠ KEV CISA — active exploitation confirmed');
      coveredKw.push('kev', 'cisa', 'exploitation active');
    }
    if (article.epssScore != null && article.epssScore >= 0.05) {
      highlights.push(`⚡ EPSS ${_pct(article.epssScore)} — high exploitation probability`);
      coveredKw.push('epss');
    }
    const cves = article.cves || article.cveIds || [];
    if (cves.length) {
      highlights.push(`🔍 ${cves.slice(0, 4).join(', ')}${cves.length > 4 ? ` + ${cves.length - 4} more` : ''}`);
      cves.forEach(c => coveredKw.push(c.toLowerCase()));
    }
    // Raisons dédupliquées — max 2, courtes, sans répéter KEV/EPSS/CVEs
    const dedupedReasons = _dedupeReasons(article.priorityReasons || [], coveredKw);
    dedupedReasons.slice(0, 2).forEach(r => highlights.push(`▸ ${r}`));

    if (highlights.length) {
      lines.push('CRITICAL SIGNALS');
      highlights.forEach(h => lines.push(`  ${h}`));
      lines.push('');
    }

    // Décision — phrase unique, directe
    lines.push('DECISION');
    lines.push(`  ${_actionFromLevel(article.priorityLevel)}`);
    lines.push('');

    // Footer compact
    lines.push(sep);
    if (article.link) lines.push(article.link);
    lines.push(`CyberVeille Pro · ${_now()}`);

    return lines.join('\n');
  }

  // ── Résumé analyste — incident ────────────────────────────────────────────

  function _analystSummaryIncident(incident) {
    const sep  = '═'.repeat(48);
    const sep2 = '─'.repeat(48);
    const lines = [sep, 'INCIDENT REPORT — CyberVeille Pro', sep, ''];

    lines.push(`Incident     : ${incident.title || '—'}`);
    lines.push(`ID           : ${incident.incidentId || '—'}`);
    lines.push(`Priority     : ${_prioLabel(incident.incidentPriorityLevel)}` +
      (incident.incidentPriorityScore > 0 ? ` (score ${incident.incidentPriorityScore})` : ''));
    lines.push('');

    lines.push('SCOPE');
    lines.push(`  Articles   : ${incident.articleCount || 0}` +
      ` (${incident.sourceCount || 0} source${incident.sourceCount > 1 ? 's' : ''})`);
    if (incident.cves?.length)
      lines.push(`  CVEs       : ${incident.cves.join(', ')}`);
    if (incident.vendors?.length)
      lines.push(`  Vendors    : ${incident.vendors.join(', ')}`);
    if (incident.attackTags?.length)
      lines.push(`  ATT&CK     : ${incident.attackTags.slice(0, 5).join(', ')}`);
    if (incident.angles?.length)
      lines.push(`  Angles     : ${incident.angles.join(', ')}`);
    if (incident.rawIocCount > 0)
      lines.push(`  IOCs       : ${incident.rawIocCount} extracted`);
    lines.push('');

    // Signaux — uniquement les positifs (évite les lignes "Non" sans valeur)
    const _incSigLines = [];
    if (incident.kev)
      _incSigLines.push(`  ▸ KEV      : YES — active exploitation confirmed`);
    if (incident.maxEpss != null)
      _incSigLines.push(`  ▸ EPSS max : ${_pct(incident.maxEpss)}`);
    if (incident.watchlistHit)
      _incSigLines.push(`  ▸ Watchlist: YES — watchlist term matched`);
    if (incident.trending)
      _incSigLines.push(`  ▸ Trending : YES — covered by multiple sources`);
    if (_incSigLines.length) {
      lines.push('SIGNALS');
      _incSigLines.forEach(s => lines.push(s));
      lines.push('');
    }

    if (incident.firstSeen || incident.lastSeen) {
      lines.push('TIMELINE');
      if (incident.firstSeen) lines.push(`  First seen         : ${_fmt(incident.firstSeen)}`);
      if (incident.lastSeen)  lines.push(`  Last activity      : ${_fmt(incident.lastSeen)}`);
      lines.push('');
    }

    // Raisons de priorité — dédupliquées par rapport aux signaux et CVEs affichés
    const _incReasonKw = [];
    if (incident.kev)               _incReasonKw.push('kev', 'cisa', 'exploitation active');
    if (incident.maxEpss != null)   _incReasonKw.push('epss');
    (incident.cves || []).forEach(c => _incReasonKw.push(c.toLowerCase()));
    const reasons = _dedupeReasons(incident.priorityReasons || [], _incReasonKw);
    if (reasons.length) {
      lines.push('PRIORITY REASONS');
      reasons.forEach(r => lines.push(`  ▸ ${r}`));
      lines.push('');
    }

    // Résumé — limité à 400 caractères
    if (incident.summary) {
      lines.push('SUMMARY');
      lines.push(`  ${_truncate(incident.summary, 400)}`);
      lines.push('');
    }

    // Workflow analyste
    const ws = typeof EntityStatus !== 'undefined'
      ? EntityStatus.getStatus('incident', incident.incidentId) : null;
    if (ws) {
      lines.push('ANALYST WORKFLOW');
      lines.push(`  Status      : ${ws.status || '—'}`);
      if (ws.owner)     lines.push(`  Owner       : ${ws.owner}`);
      if (ws.note)      lines.push(`  Note        : ${ws.note}`);
      if (ws.updatedAt) lines.push(`  Updated     : ${_fmt(ws.updatedAt)}`);
      lines.push('');
    }

    lines.push(sep2);
    lines.push(`Generated on ${_now()} · CyberVeille Pro`);

    return lines.join('\n');
  }

  // ── Résumé exécutif — incident ────────────────────────────────────────────
  // Sprint 19 : restructuré pour public non-technique (manager / RSSI).
  // Structure : titre → niveau → contexte court → signaux critiques → décision.

  function _execSummaryIncident(incident) {
    const sep  = '─'.repeat(44);
    const lines = ['🛡 EXECUTIVE SUMMARY — INCIDENT', sep, ''];

    // Titre et niveau
    lines.push(incident.title || '—');
    lines.push('');
    const prioShort = _prioLabel(incident.incidentPriorityLevel).split(' — ')[0] || '—';
    const nbSrc = incident.sourceCount || 0;
    lines.push(`Priority ${prioShort}` +
      (incident.incidentPriorityScore > 0 ? `  ·  Score ${incident.incidentPriorityScore}/100` : ''));

    // Ampleur — utile pour contextualiser auprès d'un manager
    const artCnt = incident.articleCount || 0;
    if (artCnt > 1 || nbSrc > 1)
      lines.push(`${artCnt} article${artCnt > 1 ? 's' : ''} · ${nbSrc} source${nbSrc > 1 ? 's' : ''}`);

    // Résumé textuel court si disponible
    const sumShort = _truncate(incident.summary || '', 150);
    if (sumShort) {
      lines.push('');
      lines.push(`  ${sumShort}`);
    }
    lines.push('');

    // Signaux critiques
    const highlights = [];
    const coveredKw  = [];
    if (incident.kev) {
      highlights.push('⚠ KEV CISA — active exploitation confirmed');
      coveredKw.push('kev', 'cisa', 'exploitation active');
    }
    if (incident.maxEpss != null && incident.maxEpss >= 0.05) {
      highlights.push(`⚡ EPSS max ${_pct(incident.maxEpss)}`);
      coveredKw.push('epss');
    }
    if (incident.cves?.length) {
      highlights.push(`🔍 ${incident.cves.slice(0, 3).join(', ')}` +
        (incident.cves.length > 3 ? ` + ${incident.cves.length - 3} more` : ''));
      incident.cves.forEach(c => coveredKw.push(c.toLowerCase()));
    }
    // Raisons dédupliquées — max 2
    const dedupedReasons = _dedupeReasons(incident.priorityReasons || [], coveredKw);
    dedupedReasons.slice(0, 2).forEach(r => highlights.push(`▸ ${r}`));

    if (highlights.length) {
      lines.push('CRITICAL SIGNALS');
      highlights.forEach(h => lines.push(`  ${h}`));
      lines.push('');
    }

    // Décision
    lines.push('DECISION');
    lines.push(`  ${_actionFromLevel(incident.incidentPriorityLevel)}`);
    lines.push('');
    lines.push(sep);
    lines.push(`CyberVeille Pro · ${_now()}`);

    return lines.join('\n');
  }

  // ── Sprint 22 — Formats de partage enrichi ───────────────────────────────
  //
  // Quatre fonctions couvrant deux canaux (Slack/Teams · Email interne) et
  // deux types d'entité (article · incident). Robustes aux données partielles.
  // Distinctes des résumés analyste/exécutif et du ticket ITSM.

  // Partage court article — Slack/Teams (plain text, ~6 lignes)
  function _shareShortArticle(article) {
    const level    = article.priorityLevel;
    const emoji    = _prioEmoji(level);
    const prioShort = _prioLabel(level).split(' — ')[0] || '—';
    const lines    = [];

    lines.push(`${emoji} [${prioShort}] ${_truncate(article.title || '—', 90)}`);

    // Source + date sur une ligne
    const src = article.sourceName || '';
    const d   = article.pubDate
      ? (article.pubDate instanceof Date
          ? article.pubDate.toLocaleDateString('en-US')
          : String(article.pubDate).split('T')[0])
      : '';
    if (src || d) lines.push([src, d].filter(Boolean).join(' · '));

    // Signaux sur une ligne (only significant ones)
    const sigs = [];
    if (article.isKEV)                              sigs.push('⚠ KEV CISA');
    if ((article.epssScore ?? 0) >= 0.05)           sigs.push(`EPSS ${_pct(article.epssScore)}`);
    const cves = (article.cves || article.cveIds || []).slice(0, 2);
    if (cves.length)                                sigs.push(cves.join(', '));
    if ((article.watchlistMatches || []).length > 0)
      sigs.push(`👁 ${article.watchlistMatches.slice(0, 2).join(', ')}`);
    if (sigs.length) lines.push(sigs.join(' · '));

    lines.push(`→ ${_actionFromLevel(level)}`);
    if (article.link) lines.push(article.link);
    lines.push('— CyberVeille Pro');

    return lines.join('\n');
  }

  // Partage court incident — Slack/Teams (plain text)
  function _shareShortIncident(incident) {
    const level     = incident.incidentPriorityLevel;
    const emoji     = _prioEmoji(level);
    const prioShort = _prioLabel(level).split(' — ')[0] || '—';
    const lines     = [];

    lines.push(`${emoji} [${prioShort}] ${_truncate(incident.title || '—', 90)}`);

    // Couverture + date
    const artCnt = incident.articleCount || 0;
    const srcCnt = incident.sourceCount  || 0;
    const parts  = [];
    if (artCnt > 0) parts.push(`${artCnt} article${artCnt > 1 ? 's' : ''}`);
    if (srcCnt > 0) parts.push(`${srcCnt} source${srcCnt > 1 ? 's' : ''}`);
    if (incident.lastSeen) {
      const d = incident.lastSeen instanceof Date
        ? incident.lastSeen.toLocaleDateString('en-US')
        : String(incident.lastSeen).split('T')[0];
      parts.push(d);
    }
    if (parts.length) lines.push(parts.join(' · '));

    const sigs = [];
    if (incident.kev)                            sigs.push('⚠ KEV CISA');
    if ((incident.maxEpss ?? 0) >= 0.05)         sigs.push(`EPSS max ${_pct(incident.maxEpss)}`);
    const cves = (incident.cves || []).slice(0, 2);
    if (cves.length)                             sigs.push(cves.join(', '));
    if (incident.watchlistHit)                   sigs.push('👁 Watchlist');
    if (sigs.length) lines.push(sigs.join(' · '));

    lines.push(`→ ${_actionFromLevel(level)}`);
    lines.push('— CyberVeille Pro');

    return lines.join('\n');
  }

  // Brief email interne article — prêt à coller dans un client email
  function _emailBriefArticle(article) {
    const level     = article.priorityLevel;
    const emoji     = _prioEmoji(level);
    const prioLabel = _prioLabel(level);
    const sep       = '─'.repeat(50);
    const lines     = [];

    // Ligne objet (à copier dans le champ Objet du client mail)
    lines.push(`Subject: [Security Alert] ${emoji} ${prioLabel.split(' — ')[0]} — ${_truncate(article.title || '', 68)}`);
    lines.push('');
    lines.push(sep);
    lines.push('');

    lines.push(article.title || '—');
    lines.push('');

    // Métadonnées de source
    if (article.sourceName) lines.push(`Source           : ${article.sourceName}`);
    const d = article.pubDate
      ? (article.pubDate instanceof Date
          ? article.pubDate.toLocaleDateString('en-US')
          : String(article.pubDate).split('T')[0])
      : null;
    if (d) lines.push(`Detected on     : ${d}`);
    if (article.link) lines.push(`Source URL      : ${article.link}`);
    lines.push('');

    // Évaluation du risque
    lines.push('RISK ASSESSMENT');
    lines.push(`  Niveau     : ${prioLabel}`);
    const sigs = [];
    if (article.isKEV)
      sigs.push("CISA KEV — active exploitation confirmed");
    if ((article.epssScore ?? 0) >= 0.05)
      sigs.push(`EPSS ${_pct(article.epssScore)} — exploitation probability`);
    const cves = (article.cves || article.cveIds || []).slice(0, 3);
    if (cves.length)
      sigs.push(`CVEs : ${cves.join(', ')}`);
    if ((article.watchlistMatches || []).length > 0)
      sigs.push(`Watchlist : ${article.watchlistMatches.slice(0, 2).join(', ')}`);
    sigs.forEach(s => lines.push(`  • ${s}`));
    lines.push('');

    // Contexte court si disponible
    const desc = _truncate(article.description || '', 200);
    if (desc) {
      lines.push('CONTEXT');
      lines.push(`  ${desc}`);
      lines.push('');
    }

    // Recommandation
    const actions = _ticketActions(article, 'article');
    lines.push('RECOMMENDATION');
    actions.forEach(a => lines.push(`  • ${a}`));
    lines.push('');

    // Profil actif si disponible
    if (typeof ProfileManager !== 'undefined') {
      const p = ProfileManager.getActiveProfile();
      if (p) {
        lines.push(`Exposure profile: ${p.badge ? p.badge + '\u00a0' : ''}${p.name}`);
        lines.push('');
      }
    }

    lines.push(sep);
    lines.push(`Auto-generated by CyberVeille Pro · ${_now()}`);

    return lines.join('\n');
  }

  // Brief email interne incident — prêt à coller dans un client email
  function _emailBriefIncident(incident) {
    const level     = incident.incidentPriorityLevel;
    const emoji     = _prioEmoji(level);
    const prioLabel = _prioLabel(level);
    const sep       = '─'.repeat(50);
    const lines     = [];

    lines.push(`Subject: [Security Alert] ${emoji} ${prioLabel.split(' — ')[0]} — ${_truncate(incident.title || '', 68)}`);
    lines.push('');
    lines.push(sep);
    lines.push('');

    lines.push(incident.title || '—');
    lines.push('');

    // Couverture
    const artCnt = incident.articleCount || 0;
    const srcCnt = incident.sourceCount  || 0;
    lines.push(`Coverage        : ${artCnt} article${artCnt > 1 ? 's' : ''} · ${srcCnt} source${srcCnt > 1 ? 's' : ''}`);
    if (incident.firstSeen || incident.lastSeen)
      lines.push(`Period          : ${_fmt(incident.firstSeen)} → ${_fmt(incident.lastSeen)}`);
    lines.push('');

    // Évaluation
    lines.push('RISK ASSESSMENT');
    lines.push(`  Niveau     : ${prioLabel}`);
    const sigs = [];
    if (incident.kev)
      sigs.push('CISA KEV — active exploitation confirmed');
    if ((incident.maxEpss ?? 0) >= 0.05)
      sigs.push(`EPSS max ${_pct(incident.maxEpss)} — high exploitation probability`);
    const cves = (incident.cves || []).slice(0, 3);
    if (cves.length)
      sigs.push(`CVEs : ${cves.join(', ')}`);
    if (incident.watchlistHit)
      sigs.push('Watchlist term matched');
    if (incident.trending)
      sigs.push(`High media coverage (${artCnt} articles)`);
    sigs.forEach(s => lines.push(`  • ${s}`));
    lines.push('');

    // Résumé textuel
    const sum = _truncate(incident.summary || '', 200);
    if (sum) {
      lines.push('CONTEXT');
      lines.push(`  ${sum}`);
      lines.push('');
    }

    // Recommandation
    const actions = _ticketActions(incident, 'incident');
    lines.push('RECOMMENDATION');
    actions.forEach(a => lines.push(`  • ${a}`));
    lines.push('');

    if (typeof ProfileManager !== 'undefined') {
      const p = ProfileManager.getActiveProfile();
      if (p) {
        lines.push(`Exposure profile: ${p.badge ? p.badge + '\u00a0' : ''}${p.name}`);
        lines.push('');
      }
    }

    lines.push(sep);
    lines.push(`Auto-generated by CyberVeille Pro · ${_now()}`);

    return lines.join('\n');
  }

  // Markdown Slack-compatible — utilisé dans les payloads JSON webhook (Sprint 22)
  function _shareMarkdownArticle(article) {
    const emoji     = _prioEmoji(article.priorityLevel);
    const prioShort = _prioLabel(article.priorityLevel).split(' — ')[0] || '—';
    const sigs      = [];
    if (article.isKEV)                    sigs.push('**⚠ KEV CISA**');
    if ((article.epssScore ?? 0) >= 0.05) sigs.push(`EPSS ${_pct(article.epssScore)}`);
    const cves = (article.cves || article.cveIds || []).slice(0, 2);
    if (cves.length)                      sigs.push('`' + cves.join('`, `') + '`');
    return [
      `**${emoji} [${prioShort}] ${_truncate(article.title || '—', 90)}**`,
      sigs.length ? sigs.join(' · ') : null,
      `→ ${_actionFromLevel(article.priorityLevel)}`,
      article.link || null,
      '_CyberVeille Pro_'
    ].filter(Boolean).join('\n');
  }

  function _shareMarkdownIncident(incident) {
    const emoji     = _prioEmoji(incident.incidentPriorityLevel);
    const prioShort = _prioLabel(incident.incidentPriorityLevel).split(' — ')[0] || '—';
    const sigs      = [];
    if (incident.kev)                       sigs.push('**⚠ KEV CISA**');
    if ((incident.maxEpss ?? 0) >= 0.05)    sigs.push(`EPSS max ${_pct(incident.maxEpss)}`);
    const cves = (incident.cves || []).slice(0, 2);
    if (cves.length)                        sigs.push('`' + cves.join('`, `') + '`');
    return [
      `**${emoji} [${prioShort}] ${_truncate(incident.title || '—', 90)}**`,
      `${incident.articleCount || 0} articles · ${incident.sourceCount || 0} sources`,
      sigs.length ? sigs.join(' · ') : null,
      `→ ${_actionFromLevel(incident.incidentPriorityLevel)}`,
      '_CyberVeille Pro_'
    ].filter(Boolean).join('\n');
  }

  // ── Payload enrichi exportable ────────────────────────────────────────────
  //
  // Format réutilisable pour :
  //   • Copie JSON dans un ticket ITSM manuellement
  //   • Future API "Créer un ticket" (Jira, ServiceNow, etc.)
  //   • Archivage / audit trail
  //   • Enrichissement webhook sortant
  //
  // _ticketStub : stub non implémenté, prêt pour un sprint futur.

  function enrichedIncidentPayload(incident) {
    const ws = typeof EntityStatus !== 'undefined'
      ? EntityStatus.getStatus('incident', incident.incidentId) : null;

    return {
      schema:      'cyberveille_incident_v1',
      generatedAt: new Date().toISOString(),
      incident: {
        id:      incident.incidentId,
        title:   incident.title,
        summary: incident.summary || null,
        priority: {
          level:   incident.incidentPriorityLevel || null,
          score:   incident.incidentPriorityScore || null,
          reasons: incident.priorityReasons || []
        },
        signals: {
          kev:          incident.kev         || false,
          epssMax:      incident.maxEpss != null
            ? parseFloat((incident.maxEpss * 100).toFixed(2)) : null,
          watchlistHit: incident.watchlistHit || false,
          iocCount:     incident.rawIocCount  || 0,
          trending:     incident.trending     || false,
          maxScore:     incident.maxScore     || null
        },
        scope: {
          cves:         incident.cves         || [],
          vendors:      incident.vendors      || [],
          sources:      incident.sources      || [],
          attackTags:   incident.attackTags   || [],
          angles:       incident.angles       || [],
          articleCount: incident.articleCount || 0,
          sourceCount:  incident.sourceCount  || 0
        },
        timeline: {
          firstSeen: incident.firstSeen || null,
          lastSeen:  incident.lastSeen  || null
        },
        workflow: ws ? {
          status:    ws.status    || null,
          owner:     ws.owner     || null,
          note:      ws.note      || null,
          updatedAt: ws.updatedAt || null
        } : null
      },
      // ── Sprint 22 — Formats de diffusion enrichis ─────────────────────────
      _share: {
        _note:        'Pre-generated sharing formats for Slack/Teams/email webhooks.',
        shortText:    _shareShortIncident(incident),
        markdownText: _shareMarkdownIncident(incident),
        emailSubject: (() => {
          const emoji  = _prioEmoji(incident.incidentPriorityLevel);
          const pShort = _prioLabel(incident.incidentPriorityLevel).split(' — ')[0] || '—';
          return `[Security Alert] ${emoji} ${pShort} — ${_truncate(incident.title || '', 68)}`;
        })(),
        emailText:    _emailBriefIncident(incident)
      },
      // ── Stub ticket (non implémenté — réservé pour sprint futur) ──────────
      _ticketStub: {
        _note:    'Adapt fields to your ITSM. Fill externalId/externalUrl after creation.',
        type:     'security_incident',
        title:    `[SEC] ${incident.title}`,
        priority: _ticketPriority(incident.incidentPriorityLevel),
        labels:   ['security', 'cyberveille', ...(incident.cves || []).slice(0, 3)],
        components: (incident.vendors || []).slice(0, 3),
        assignee: ws?.owner || null,
        description: [
          '## Security Incident — CyberVeille Pro',
          '',
          `**Priority** : ${_prioLabel(incident.incidentPriorityLevel)}`,
          `**Summary** : ${incident.summary || incident.title}`,
          '',
          '### Signals',
          incident.kev ? '- ⚠ CISA KEV — active exploitation confirmed' : null,
          incident.maxEpss != null ? `- EPSS max : ${_pct(incident.maxEpss)}` : null,
          incident.cves?.length ? `- CVEs : ${incident.cves.join(', ')}` : null,
          '',
          '### Sources',
          `${incident.articleCount} article(s) · ${incident.sourceCount} source(s)`,
          '',
          '---',
          `*Auto-generated by CyberVeille Pro on ${_now()}*`
        ].filter(s => s != null).join('\n'),
        _externalRef: {
          externalId:  null,  // à remplir après création dans l'ITSM
          externalUrl: null,
          syncedAt:    null
        }
      }
    };
  }

  // ── Copie presse-papiers ──────────────────────────────────────────────────

  async function _copy(text, label) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Fallback pour contextes sans Clipboard API (HTTP, extension, iframe)
      const ta = Object.assign(document.createElement('textarea'), {
        value: text
      });
      ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch { /* silent */ }
      ta.remove();
    }
    if (typeof UI !== 'undefined') UI.showToast(`✅ ${label} copied`, 'success');
  }

  // ── HTML des boutons — article ────────────────────────────────────────────

  // Sprint 23 — Dropdown ⚡ Actions (remplace les 4+ boutons plats du footer)
  // opts.showIoc : true → inclut le bouton IOC dans le dropdown
  function _articleButtonsHTML(opts) {
    const showIoc = opts && opts.showIoc;
    return `
      <div class="qa-actions-menu" id="art-qa-menu">
        <button class="btn qa-btn qa-actions-trigger" id="art-qa-trigger"
                title="Quick actions — summaries, ticket, share${showIoc ? ', IOCs' : ''}">
          ⚡ Actions ▾
        </button>
        <div class="qa-actions-popover" id="art-qa-popover" style="display:none" role="menu">
          <button class="qa-actions-item" id="art-modal-copy-analyst"
                  title="Detailed operational format — copied in one click">
            📋 Analyst summary
          </button>
          <button class="qa-actions-item" id="art-modal-copy-exec"
                  title="Short risk-oriented format — for management">
            📊 Executive summary
          </button>
          <div class="qa-actions-sep" role="separator"></div>
          <button class="qa-actions-item qa-actions-item-ticket" id="art-modal-ticket"
                  title="Structured ticket ready for your ITSM">
            🎫 Prepare ticket
          </button>
          <button class="qa-actions-item qa-actions-item-share" id="art-modal-share"
                  title="Share — Slack/Teams or internal email in one click">
            📤 Share
          </button>
          <div class="qa-actions-sep" role="separator"></div>
          <button class="qa-actions-item qa-actions-item-ai" id="art-modal-ai-brief"
                  title="Generate an AI-assisted analyst brief, executive brief and next step — based on existing signals">
            ✦ AI Brief
          </button>
          ${showIoc ? `
          <div class="qa-actions-sep" role="separator"></div>
          <button class="qa-actions-item" id="art-modal-copy-ioc"
                  title="Copy CVEs, URL, ATT&CK, IPs and detected domains">
            🔬 Copy IOCs
          </button>` : ''}
        </div>
      </div>`;
  }

  // ── HTML des boutons — incident ───────────────────────────────────────────

  // Sprint 23 — 3 actions primaires visibles + dropdown "···" (2 secondaires)
  // Primaires : Exécutif · Ticket · Partager  (usage fréquent, visible tout de suite)
  // Secondaires : Analyste · Export JSON        (usage moins fréquent, dans le dropdown)
  function _incidentButtonsHTML(incidentId) {
    const iid = String(incidentId).replace(/[^a-z0-9\-_]/gi, '-');
    return `
      <div class="qa-incident-actions">
        <button class="qa-btn qa-btn-sm qa-exec-inc" data-iid="${incidentId}"
                title="Short risk-oriented summary — for management">
          📊 Executive summary
        </button>
        <button class="qa-btn qa-btn-sm qa-btn-ticket qa-ticket-inc" data-iid="${incidentId}"
                title="Structured ticket ready for your ITSM">
          🎫 Prepare ticket
        </button>
        <button class="qa-btn qa-btn-sm qa-btn-share qa-share-inc" data-iid="${incidentId}"
                title="Share — Slack/Teams or internal email">
          📤 Share
        </button>
        <div class="qa-actions-menu qa-inc-more" data-iid="${incidentId}">
          <button class="qa-btn qa-btn-sm qa-actions-trigger qa-inc-more-trigger"
                  title="More actions — analyst summary, JSON export">
            ···
          </button>
          <div class="qa-actions-popover qa-inc-more-popover" style="display:none" role="menu">
            <button class="qa-actions-item qa-analyst-inc" data-iid="${incidentId}"
                    title="Detailed operational format — copied in one click">
              📋 Analyst summary
            </button>
            <button class="qa-actions-item qa-json-inc" data-iid="${incidentId}"
                    title="Export enriched JSON payload (webhook / integration)">
              📤 Export JSON
            </button>
            <div class="qa-actions-sep" role="separator"></div>
            <button class="qa-actions-item qa-actions-item-ai qa-ai-brief-inc" data-iid="${incidentId}"
                    title="Generate an AI-assisted analyst brief, executive brief and next step">
              ✦ AI Brief
            </button>
          </div>
        </div>
      </div>`;
  }

  // ── Bind article modal ────────────────────────────────────────────────────

  function bindArticle(article, nvdData) {
    // ── Sprint 23 — Toggle du dropdown ⚡ Actions ────────────────────────────
    const trigger = document.getElementById('art-qa-trigger');
    const popover = document.getElementById('art-qa-popover');
    if (trigger && popover) {
      trigger.addEventListener('click', e => {
        e.stopPropagation();
        const isOpen = popover.style.display !== 'none';
        popover.style.display = isOpen ? 'none' : 'block';
        trigger.classList.toggle('qa-actions-open', !isOpen);
        if (!isOpen) {
          // Fermer sur clic extérieur — ajouté après l'event courant
          setTimeout(() => {
            const _close = () => {
              popover.style.display = 'none';
              trigger.classList.remove('qa-actions-open');
              document.removeEventListener('click', _close);
            };
            document.addEventListener('click', _close);
          }, 0);
        }
      });
      document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && popover.style.display !== 'none') {
          popover.style.display = 'none';
          trigger.classList.remove('qa-actions-open');
        }
      });
    }

    // ── Actions dans le dropdown ─────────────────────────────────────────────
    document.getElementById('art-modal-copy-analyst')
      ?.addEventListener('click', () =>
        _copy(_analystSummaryArticle(article, nvdData || {}), 'Analyst summary'));

    document.getElementById('art-modal-copy-exec')
      ?.addEventListener('click', () =>
        _copy(_execSummaryArticle(article), 'Executive summary'));

    document.getElementById('art-modal-ticket')
      ?.addEventListener('click', () =>
        _showTicketModal(article, 'article', nvdData || null));

    document.getElementById('art-modal-share')
      ?.addEventListener('click', () =>
        _showShareModal(article, 'article'));

    document.getElementById('art-modal-ai-brief')
      ?.addEventListener('click', e => {
        e.stopPropagation();
        // Fermer le dropdown avant d'ouvrir la modale AI
        const popover = document.getElementById('art-qa-popover');
        const trigger = document.getElementById('art-qa-trigger');
        if (popover) popover.style.display = 'none';
        if (trigger) trigger.classList.remove('qa-actions-open');
        if (typeof AIBrief !== 'undefined') AIBrief.showModal(article, 'article');
      });

    // Note : art-modal-copy-ioc est bindé dans article-modal.js (accès à _copyIOCs privé)
  }

  // ── Bind panneau incident ─────────────────────────────────────────────────

  function bindIncidentPanel(container, incidentsCache) {
    container.querySelectorAll('.qa-analyst-inc').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const inc = incidentsCache.find(i => i.incidentId === btn.dataset.iid);
        if (inc) _copy(_analystSummaryIncident(inc), 'Incident analyst summary');
      });
    });

    container.querySelectorAll('.qa-exec-inc').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const inc = incidentsCache.find(i => i.incidentId === btn.dataset.iid);
        if (inc) _copy(_execSummaryIncident(inc), 'Incident executive summary');
      });
    });

    container.querySelectorAll('.qa-json-inc').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const inc = incidentsCache.find(i => i.incidentId === btn.dataset.iid);
        if (!inc) return;
        const payload = JSON.stringify(enrichedIncidentPayload(inc), null, 2);
        _copy(payload, 'Incident JSON payload');
      });
    });

    container.querySelectorAll('.qa-ticket-inc').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const inc = incidentsCache.find(i => i.incidentId === btn.dataset.iid);
        if (inc) _showTicketModal(inc, 'incident', null);
      });
    });

    // Partage court / email
    container.querySelectorAll('.qa-share-inc').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const inc = incidentsCache.find(i => i.incidentId === btn.dataset.iid);
        if (inc) _showShareModal(inc, 'incident');
      });
    });

    // ── Sprint IA — AI Brief par incident ────────────────────────────────────
    container.querySelectorAll('.qa-ai-brief-inc').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const inc = incidentsCache.find(i => i.incidentId === btn.dataset.iid);
        if (inc && typeof AIBrief !== 'undefined') AIBrief.showModal(inc, 'incident');
      });
    });

    // ── Sprint 23 — Dropdown "···" par incident ──────────────────────────────
    container.querySelectorAll('.qa-inc-more').forEach(menuEl => {
      const trigger = menuEl.querySelector('.qa-inc-more-trigger');
      const popover = menuEl.querySelector('.qa-inc-more-popover');
      if (!trigger || !popover) return;

      trigger.addEventListener('click', e => {
        e.stopPropagation();
        const isOpen = popover.style.display !== 'none';
        // Fermer tous les autres menus ouverts dans le panel
        container.querySelectorAll('.qa-inc-more-popover').forEach(p => {
          if (p !== popover) p.style.display = 'none';
        });
        container.querySelectorAll('.qa-inc-more-trigger').forEach(t => {
          if (t !== trigger) t.classList.remove('qa-actions-open');
        });
        popover.style.display = isOpen ? 'none' : 'block';
        trigger.classList.toggle('qa-actions-open', !isOpen);

        if (!isOpen) {
          setTimeout(() => {
            const _close = () => {
              popover.style.display = 'none';
              trigger.classList.remove('qa-actions-open');
              document.removeEventListener('click', _close);
            };
            document.addEventListener('click', _close);
          }, 0);
        }
      });
    });
  }

  // ── API publique ──────────────────────────────────────────────────────────

  return {
    bindArticle,
    bindIncidentPanel,
    enrichedIncidentPayload,
    ticketDraftJSON,
    articleButtonsHTML:  _articleButtonsHTML,
    incidentButtonsHTML: _incidentButtonsHTML,
    // Sprint 22 — Formats de partage (utilisables par des modules tiers)
    shareShortArticle:   _shareShortArticle,
    shareShortIncident:  _shareShortIncident,
    emailBriefArticle:   _emailBriefArticle,
    emailBriefIncident:  _emailBriefIncident
  };

})();
