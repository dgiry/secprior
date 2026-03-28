// recommender.js — Recommandations actionnables basées sur les signaux disponibles
//
// Génère 5 catégories à partir d'un article ou d'un incident :
//   1. Vérifier l'exposition
//   2. Patch et mitigation
//   3. Contrôles compensatoires
//   4. Vérifications SOC / SIEM / EDR
//   5. Escalade recommandée
//
// API publique : generate(ctx, type), renderHTML(ctx, type)
//   type : "article" | "incident"
//
// Chaque catégorie produit toujours au moins un item (fallback prudent).
// Aucune hallucination : rien n'est affirmé sans signal correspondant.

const Recommender = (() => {

  // ── Normalisation ─────────────────────────────────────────────────────────
  //
  // Produit une interface commune indépendante du type d'objet.
  // Article et incident ont des noms de champs différents — on unifie ici.

  function _norm(ctx, type) {
    if (type === 'incident') {
      const epss = ctx.maxEpss ?? null;
      return {
        priorityLevel:  ctx.incidentPriorityLevel || 'low',
        cves:           ctx.cves             || [],
        hasCVE:         (ctx.cves || []).length > 0,
        isKEV:          !!ctx.kev,
        epss,
        epssHigh:       epss !== null && epss >= 0.5,
        epssNot:        epss !== null && epss >= 0.1,
        // Détecte les 0-day depuis les articles sous-jacents si disponibles
        isZeroDay:      (ctx.articles || []).some(a => !!a.prioritySignals?.isZeroDay),
        iocCount:       ctx.rawIocCount      || 0,
        vendors:        ctx.vendors          || [],
        watchlistHit:   !!ctx.watchlistHit,
        watchlistItems: [],  // non agrégé au niveau incident
        tactics:        _parseTactics(ctx.attackTags || [], 'incident'),
        multiSource:    (ctx.sourceCount     || 0) >= 3,
        sources:        ctx.sourceCount      || 0,
      };
    }

    // Article
    const sig  = ctx.prioritySignals || {};
    const epss = sig.epss != null
      ? sig.epss / 100                // sig.epss est en % (ex: 87.3 → 0.873)
      : (ctx.epssScore ?? null);      // epssScore est déjà en 0-1
    return {
      priorityLevel:  ctx.priorityLevel  || 'low',
      cves:           ctx.cves || ctx.cveIds || [],
      hasCVE:         sig.hasCVE || (ctx.cves || ctx.cveIds || []).length > 0,
      isKEV:          sig.kev   || !!ctx.isKEV,
      epss,
      epssHigh:       sig.epssHigh || (epss !== null && epss >= 0.5),
      epssNot:        sig.epssMed  || (epss !== null && epss >= 0.1),
      isZeroDay:      !!sig.isZeroDay,
      iocCount:       sig.iocCount || ctx.iocCount || 0,
      vendors:        ctx.vendors  || [],
      watchlistHit:   sig.watchlist || (ctx.watchlistMatches || []).length > 0,
      watchlistItems: sig.watchlistItems || ctx.watchlistMatchItems || [],
      tactics:        _parseTactics(ctx.attackTags || [], 'article'),
      multiSource:    (sig.sources || ctx.trendingCount || 0) >= 3,
      sources:        sig.sources || ctx.trendingCount || 1,
    };
  }

  // ATT&CK → tableau de strings lowercase pour la détection de tactiques
  function _parseTactics(tags, type) {
    if (type === 'article') {
      // [{label: "T1190", tactic: "Initial Access"}]
      return tags.map(t => (t.tactic || '').toLowerCase());
    }
    // incident : ["T1190 (Initial Access)"]
    return tags.map(t => {
      const m = t.match(/\(([^)]+)\)/);
      return (m ? m[1] : t).toLowerCase();
    });
  }

  function _tactic(tactics, ...keywords) {
    return tactics.some(t => keywords.some(k => t.includes(k.toLowerCase())));
  }

  function _pct(epss) {
    return epss !== null && epss !== undefined ? `${Math.round(epss * 100)}%` : '';
  }

  // ── Section 1 : Vérifier l'exposition ─────────────────────────────────────

  function _secExposition(n) {
    const items = [];

    if (n.isKEV)
      items.push("Active exploitation confirmed (CISA KEV) — check your systems' exposure immediately.");

    if (n.vendors.length)
      items.push(`Inventory assets using: ${n.vendors.slice(0, 3).join(', ')}.`);

    if (n.cves.length)
      items.push(`Assess applicability in your environment: ${n.cves.slice(0, 3).join(', ')}.`);

    if (n.watchlistHit) {
      const hi = n.watchlistItems.filter(w => w.priority === 'high').map(w => w.label);
      items.push(hi.length
        ? `Critical watchlist assets potentially affected: ${hi.slice(0, 2).join(', ')}.`
        : "Watchlist items are affected — prioritize the analysis.");
    }

    if (n.multiSource)
      items.push(`Threat reported by ${n.sources} independent sources — potentially wide scope.`);

    if (!items.length)
      items.push("Identify potentially exposed assets in your inventory.");

    return { id: 'exposition', icon: '🔍', title: "Check exposure", items };
  }

  // ── Section 2 : Patch et mitigation ───────────────────────────────────────

  function _secPatch(n) {
    const items = [];

    if (n.isKEV)
      items.push("Emergency patch — active exploitation confirmed, CISA deadline ≤ 3 weeks.");
    else if (n.epssHigh)
      items.push(`EPSS ${_pct(n.epss)} — high exploitation probability, apply patch within 72h.`);
    else if (n.epssNot)
      items.push(`EPSS ${_pct(n.epss)} — notable risk, schedule patch within the next 2 weeks.`);

    if (n.isZeroDay)
      items.push("No patch available at this stage — apply immediate compensating controls.");
    else if (n.hasCVE && !n.isKEV)
      items.push("Check patch availability with relevant vendors.");

    if (!items.length)
      items.push(n.hasCVE
        ? "Check patch availability for the identified CVEs."
        : "Consult security advisories from the affected vendors.");

    return { id: 'patch', icon: '🩹', title: 'Patch et mitigation', items };
  }

  // ── Section 3 : Contrôles compensatoires ──────────────────────────────────

  function _secCompensatoires(n) {
    const items = [];
    const t = n.tactics;

    if (n.isZeroDay || (n.isKEV && n.priorityLevel === 'critical_now'))
      items.push("Consider isolating exposed systems until a patch is available.");

    if (n.iocCount > 0)
      items.push(`Proactively block the ${n.iocCount} identified IOC(s) on your filtering devices.`);

    if (_tactic(t, 'initial access', 'reconnaissance'))
      items.push("Strengthen network access controls and perimeter rules.");
    if (_tactic(t, 'execution', 'command and control'))
      items.push("Restrict execution permissions on sensitive systems.");
    if (_tactic(t, 'persistence'))
      items.push("Audit persistence mechanisms (scheduled tasks, services, registry keys).");
    if (_tactic(t, 'lateral movement'))
      items.push("Segment the network and limit lateral movement paths.");
    if (_tactic(t, 'exfiltration', 'collection'))
      items.push("Strengthen DLP controls and monitor abnormal outbound traffic.");
    if (_tactic(t, 'defense evasion'))
      items.push("Check the integrity of security tools (antivirus, EDR, logging).");

    if (!items.length)
      items.push("Enable advanced logging on potentially exposed systems.");

    return { id: 'compensatoires', icon: '🛡️', title: 'Contrôles compensatoires', items };
  }

  // ── Section 4 : SOC / SIEM / EDR ──────────────────────────────────────────

  function _secSOC(n) {
    const items = [];
    const active = n.priorityLevel === 'critical_now' || n.priorityLevel === 'investigate';

    if (active)
      items.push("Launch a retrospective hunt over the last 30 days in your SIEM.");

    if (n.iocCount > 0)
      items.push(`Search for the ${n.iocCount} available IOC(s) in your SIEM and EDR.`);

    if (n.cves.length)
      items.push(`Create or activate a detection rule for: ${n.cves.slice(0, 2).join(', ')}.`);

    if (n.isKEV)
      items.push("Check existing alerts — this threat is actively exploited in the wild.");

    if (n.watchlistHit)
      items.push("Traitez les alertes watchlist en attente dans votre console SIEM.");

    if (!items.length)
      items.push("Review recent access logs on potentially exposed systems.");

    return { id: 'soc', icon: '🖥️', title: 'Vérifications SOC / SIEM / EDR', items };
  }

  // ── Section 5 : Escalade recommandée ──────────────────────────────────────

  function _secEscalade(n) {
    const items = [];

    switch (n.priorityLevel) {
      case 'critical_now':
        items.push("Immediate escalation — notify the CISO and the incident response team.");
        if (n.isKEV)
          items.push("Activate the crisis management process if exposed systems are identified.");
        break;
      case 'investigate':
        items.push("If exposure confirmed: escalate within 24h with investigation report.");
        break;
      case 'watch':
        items.push("Active monitoring — include in the next periodic threat intelligence report.");
        break;
      default:
        items.push("No immediate escalation — monitor the situation in your threat feed.");
    }

    if (n.multiSource && (n.priorityLevel === 'critical_now' || n.priorityLevel === 'investigate'))
      items.push("Coordinate with infrastructure, application, and security teams.");

    return { id: 'escalade', icon: '📢', title: 'Escalade recommandée', items };
  }

  // ── Rendu HTML ─────────────────────────────────────────────────────────────

  function _esc(s) {
    return String(s || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function renderHTML(ctx, type) {
    const sections = generate(ctx, type);
    if (!sections.length) return '';

    const catsHTML = sections.map(s => `
      <div class="reco-cat">
        <div class="reco-cat-title">
          <span class="reco-cat-icon">${s.icon}</span>${_esc(s.title)}
        </div>
        <ul class="reco-list">
          ${s.items.map(item => `<li class="reco-item">${_esc(item)}</li>`).join('')}
        </ul>
      </div>`).join('');

    return `
      <div class="reco-block">
        <div class="reco-header">
          <span class="reco-header-label">⚡ Recommandations actionnables</span>
          <span class="reco-header-hint">Based on available signals · Adapt to your context</span>
        </div>
        <div class="reco-cats">${catsHTML}</div>
      </div>`;
  }

  // ── API publique ───────────────────────────────────────────────────────────

  function generate(ctx, type) {
    const n = _norm(ctx, type);
    return [
      _secExposition(n),
      _secPatch(n),
      _secCompensatoires(n),
      _secSOC(n),
      _secEscalade(n),
    ].filter(s => s.items.length > 0);
  }

  return { generate, renderHTML };
})();
