// onboarding.js v2 — Guide démarrage + packaging démo CyberVeille Pro
//
// Carte "Démarrage / Démo" affichée à la première visite :
//   • Pipeline Signal → Priorité → Incident → Action
//   • 6 différenciateurs clés (priorisation, vues, profils, incidents, actions, partage)
//   • Parcours démo 3 clics clairement narratif
//   • CTAs par rôle : Analyste SOC / CISO Manager / Incidents / OK
//   • Hint flottant "étape suivante" activé au clic sur un CTA démo
//
// Dismissed définitivement via localStorage cv_onboarding_v1_seen
// Re-déclenchable via Onboarding.showTour() (bouton "?" dans la barre Vues)
//
// Injection : avant #feed-grid, dans <main class="main">
// Auto-init : attend que le feed soit peuplé (MutationObserver)

const Onboarding = (() => {

  const SEEN_KEY = 'cv_onboarding_v1_seen';

  // ── Persistance ───────────────────────────────────────────────────────────

  function _isSeen() {
    try { return !!localStorage.getItem(SEEN_KEY); } catch { return true; }
  }

  function _markSeen() {
    try { localStorage.setItem(SEEN_KEY, '1'); } catch {}
  }

  // ── Dismiss (smooth fade-out) ─────────────────────────────────────────────

  function dismiss() {
    _markSeen();
    const el = document.getElementById('onboarding-card');
    if (!el) return;
    el.style.opacity      = '0';
    el.style.maxHeight    = '0';
    el.style.marginBottom = '0';
    el.style.padding      = '0';
    setTimeout(() => el.remove(), 320);
  }

  // ── Hint flottant "étape suivante" ────────────────────────────────────────
  // Apparaît en bas à droite après un clic CTA — guide le démo sans modal.

  function _showDemoHint(html, autoSec = 12) {
    let hint = document.getElementById('ob-demo-hint');
    if (!hint) {
      hint = document.createElement('div');
      hint.id = 'ob-demo-hint';
      hint.className = 'ob-hint';
      document.body.appendChild(hint);
    }
    hint.innerHTML = `
      <div class="ob-hint-inner">
        <div class="ob-hint-content">${html}</div>
        <button class="ob-hint-close" title="Close">✕</button>
      </div>`;
    hint.style.display = 'block';
    hint.querySelector('.ob-hint-close')
      ?.addEventListener('click', () => { hint.style.display = 'none'; });
    clearTimeout(hint._timer);
    hint._timer = setTimeout(() => { hint.style.display = 'none'; }, autoSec * 1000);
  }

  // ── CTAs ──────────────────────────────────────────────────────────────────

  function _goTopPrio() {
    dismiss();
    const pill = document.querySelector('[data-pid="today"]');
    if (pill) { pill.click(); }
    else { document.getElementById('btn-top-priorities')?.click(); }
    setTimeout(() => _showDemoHint(
      `<strong>📋 Step 2 of 3</strong><br>
       In the feed, click on a <strong>🔴 critical</strong> article<br>
       → in the modal: <strong>⚡ Actions ▾</strong> → Analyst summary or ITSM ticket`
    ), 600);
  }

  function _goCISO() {
    dismiss();
    document.querySelector('[data-pid="ciso"]')?.click();
    setTimeout(() => _showDemoHint(
      `<strong>📋 Step 2 of 3</strong><br>
       The <strong>👁 Visibility</strong> panel just opened<br>
       → Posture KPIs, top vendors, top incidents of the current profile<br>
       → Then click <strong>🔗 Incidents</strong> for the consolidated view`
    ), 600);
  }

  function _goIncidents() {
    dismiss();
    document.querySelector('[data-pid="soc"]')?.click();
    setTimeout(() => _showDemoHint(
      `<strong>📋 Step 2 of 3</strong><br>
       Click an incident in the list to see its <strong>CVE timeline</strong><br>
       → <strong>⚡ Actions</strong> → Executive summary or ITSM JSON export<br>
       → Then try <strong>📊 CISO View</strong> for the manager view`
    ), 600);
  }

  // ── Rendu de la carte ─────────────────────────────────────────────────────

  function _render() {
    const card = document.createElement('div');
    card.id        = 'onboarding-card';
    card.className = 'ob-card';
    card.setAttribute('role', 'complementary');
    card.setAttribute('aria-label', 'CyberVeille Pro Quick Start Guide');

    card.innerHTML = `

      <!-- ── En-tête marque + tagline ── -->
      <div class="ob-header">
        <div class="ob-brand">
          <span class="ob-tag">🛡 CyberVeille Pro</span>
          <span class="ob-tagline">
            Cyber threat intelligence · explainable prioritization · analyst actions in 1 click
          </span>
        </div>
        <button class="ob-close" title="Dismiss" aria-label="Close guide">✕</button>
      </div>

      <!-- ── Pipeline Signal → Priorité → Incident → Action ── -->
      <div class="ob-pipeline" role="list">
        <div class="ob-step" role="listitem"
             title="Live RSS feeds — CERT-FR, CISA, NVD, vendor advisories, threat intel">
          <span class="ob-step-icon">📡</span>
          <span class="ob-step-label">Signal</span>
          <span class="ob-step-sub">RSS · multi-sources</span>
        </div>
        <span class="ob-arrow" aria-hidden="true">→</span>
        <div class="ob-step" role="listitem"
             title="Auto-scoring: CVSS · KEV CISA · EPSS · profile watchlist · ATT&CK — priority explained with reasons">
          <span class="ob-step-icon">🎯</span>
          <span class="ob-step-label">Priority</span>
          <span class="ob-step-sub">KEV · EPSS · Score</span>
        </div>
        <span class="ob-arrow" aria-hidden="true">→</span>
        <div class="ob-step" role="listitem"
             title="Union-Find CVE + vendor — multiple linked articles = 1 incident with full timeline">
          <span class="ob-step-icon">🔗</span>
          <span class="ob-step-label">Incident</span>
          <span class="ob-step-sub">CVE consolidation</span>
        </div>
        <span class="ob-arrow" aria-hidden="true">→</span>
        <div class="ob-step" role="listitem"
             title="Analyst summary · executive summary · ITSM ticket · Slack/Teams/email share — all in 1 click">
          <span class="ob-step-icon">⚡</span>
          <span class="ob-step-label">Action</span>
          <span class="ob-step-sub">Summary · Ticket · Share</span>
        </div>
      </div>

      <!-- ── 6 différenciateurs clés ── -->
      <div class="ob-differentiators" aria-label="Key features">
        <span class="ob-diff-chip ob-diff-hot"
              title="Each alert is classified Critical Now / Investigate / Watch with explicit reasons (KEV, EPSS, ATT&CK, watchlist)">
          🔴 Explainable prioritization
        </span>
        <span class="ob-diff-chip ob-diff-hot"
              title="5 pre-configured business views: SOC Analyst, Vuln Mgmt, CISO/Manager, MSSP, Top priorities">
          🎭 Business views
        </span>
        <span class="ob-diff-chip"
              title="Multiple exposure profiles with dedicated watchlists — ideal for MSSP or multi-scope">
          👥 Multi-exposure profiles
        </span>
        <span class="ob-diff-chip"
              title="Union-Find CVE/vendor: multiple articles on the same topic = 1 consolidated incident with timeline">
          🔗 Consolidated incidents
        </span>
        <span class="ob-diff-chip"
              title="Analyst summary, executive summary, ITSM JSON ticket, Slack/Teams/email share — 1 click">
          ⚡ Quick actions 1 click
        </span>
        <span class="ob-diff-chip"
              title="Short Slack/Teams format · email brief · enriched webhook payload ready to use">
          📤 Enriched sharing
        </span>
      </div>

      <!-- ── Parcours démo 3 clics ── -->
      <div class="ob-demo-guide">
        <span class="ob-demo-label">3-click demo:</span>
        <div class="ob-demo-steps">
          <span class="ob-demo-step">
            <span class="ob-demo-num">①</span>
            <span>Click <strong>🚨 Top priorities</strong> below</span>
          </span>
          <span class="ob-demo-sep">→</span>
          <span class="ob-demo-step">
            <span class="ob-demo-num">②</span>
            <span>Open an article → <strong>⚡ Actions ▾</strong></span>
          </span>
          <span class="ob-demo-sep">→</span>
          <span class="ob-demo-step">
            <span class="ob-demo-num">③</span>
            <span>Try <strong>📊 CISO View</strong></span>
          </span>
        </div>
      </div>

      <!-- ── CTAs par rôle ── -->
      <div class="ob-actions">
        <button class="ob-cta ob-cta-primary"
                title="Critical threats from the last 24h · KEV/EPSS scoring · automatic priority sort">
          🚨 Top priorities
        </button>
        <button class="ob-cta"
                title="CISO/Manager view — global posture, top incidents, KPIs — ideal for manager demo">
          📊 CISO View
        </button>
        <button class="ob-cta"
                title="SOC Analyst — all consolidated incidents sorted by priority · CVE timeline">
          🔗 Incidents
        </button>
        <button class="ob-cta ob-cta-ok"
                title="Start using the app">
          ✓ OK
        </button>
      </div>`;

    // Bind boutons (pas d'onclick inline pour rester compatible CSP)
    const [btnPrio, btnCiso, btnInc, btnOk] = card.querySelectorAll('.ob-cta');
    btnPrio.addEventListener('click', _goTopPrio);
    btnCiso.addEventListener('click', _goCISO);
    btnInc.addEventListener('click',  _goIncidents);
    btnOk.addEventListener('click',   dismiss);
    card.querySelector('.ob-close').addEventListener('click', dismiss);

    return card;
  }

  // ── Injection dans le DOM ─────────────────────────────────────────────────

  function show() {
    if (document.getElementById('onboarding-card')) return; // idempotent

    const main = document.querySelector('main.main');
    const grid = document.getElementById('feed-grid');
    if (!main || !grid) return;

    const card = _render();
    main.insertBefore(card, grid);

    // Entrance animation
    requestAnimationFrame(() => {
      requestAnimationFrame(() => { card.style.opacity = '1'; });
    });
  }

  // ── Auto-init : attend que le feed soit peuplé ────────────────────────────

  function _waitForContent() {
    if (_isSeen()) return;

    const grid = document.getElementById('feed-grid');
    if (!grid) { setTimeout(_waitForContent, 200); return; }

    if (grid.children.length > 0) { setTimeout(show, 400); return; }

    const obs = new MutationObserver(() => {
      if (grid.children.length > 0) { obs.disconnect(); setTimeout(show, 400); }
    });
    obs.observe(grid, { childList: true });
  }

  // ── Re-trigger (bouton "?" de la barre Vues métier) ───────────────────────

  function showTour() {
    try { localStorage.removeItem(SEEN_KEY); } catch {}
    show();
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  function init() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', _waitForContent);
    } else {
      _waitForContent();
    }
  }

  return { init, dismiss, show, showTour };

})();

// Auto-init
Onboarding.init();
