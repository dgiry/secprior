// onboarding.js v6 — First-run persona picker overlay
//
// v6 — Remplace la carte tardive (après chargement du feed) par une overlay
//      fullscreen qui apparaît IMMÉDIATEMENT au premier lancement.
//
// Parcours :
//   1. Premier lancement → overlay persona picker (fullscreen, bloquant visuellement)
//   2. L'utilisateur choisit son espace de travail (persona)
//   3. PersonaPresets.pickAndActivate(id) :
//      → seed watchlist si vide
//      → active les filtres du persona
//      → persiste l'ID pour les sessions suivantes
//   4. Overlay se ferme avec animation → articles déjà chargés en arrière-plan
//   5. Retours suivants : overlay non montrée, persona restauré via app.js
//
// Rappelable via Onboarding.showTour() (bouton "?" dans la barre Vues)
// Clé de stockage : cv_onboarding_v1_seen (inchangée pour compat)

const Onboarding = (() => {

  const SEEN_KEY = 'cv_onboarding_v1_seen';

  // ── Persistance ───────────────────────────────────────────────────────────

  function _isSeen() {
    try { return !!localStorage.getItem(SEEN_KEY); } catch { return true; }
  }

  function _markSeen() {
    try { localStorage.setItem(SEEN_KEY, '1'); } catch {}
  }

  // ── Dismiss ───────────────────────────────────────────────────────────────

  function dismiss() {
    _markSeen();
    const el = document.getElementById('ob-overlay')
            || document.getElementById('onboarding-card'); // compat v5
    if (!el) return;
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 280);
  }

  // ── Données persona pour l'overlay ───────────────────────────────────────

  const _PICKER_PERSONAS = [
    {
      id:   'today',
      icon: '🚨',
      name: 'Top Priorities',
      desc: 'Critical alerts of the last 24h, ranked by KEV and EPSS score',
      kws:  ['ransomware', '0-day', 'CISA KEV']
    },
    {
      id:   'soc',
      icon: '🔴',
      name: 'SOC Analyst',
      desc: 'All consolidated incidents sorted by priority · full analyst view',
      kws:  ['exploitation', 'lateral movement', 'C2']
    },
    {
      id:   'vuln',
      icon: '🔍',
      name: 'Vuln Mgmt',
      desc: 'Priority CVEs by KEV and EPSS · patch tracking focus',
      kws:  ['CVE', 'CVSS', 'unpatched']
    },
    {
      id:   'ciso',
      icon: '📊',
      name: 'CISO / Manager',
      desc: 'Global posture, top incidents, KPIs — synthetic executive view',
      kws:  ['breach', 'APT', 'supply chain']
    },
    {
      id:   'mssp',
      icon: '🏢',
      name: 'MSSP',
      desc: 'Multi-source incidents · watchlist-driven · multi-tenant context',
      kws:  ['campaign', 'IOC', 'threat actor']
    }
  ];

  // ── Rendu de l'overlay ────────────────────────────────────────────────────

  function _render() {
    const overlay = document.createElement('div');
    overlay.id        = 'ob-overlay';
    overlay.className = 'ob-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'ThreatLens — Choose your workspace');

    const personaCards = _PICKER_PERSONAS.map(p => `
      <button class="ob-persona-card" data-persona-id="${p.id}" title="${p.desc}">
        <span class="ob-persona-icon">${p.icon}</span>
        <span class="ob-persona-name">${p.name}</span>
        <span class="ob-persona-desc">${p.desc}</span>
        <div class="ob-persona-kws">
          ${p.kws.map(kw => `<span class="ob-persona-kw">${kw}</span>`).join('')}
        </div>
      </button>`).join('');

    overlay.innerHTML = `
      <div class="ob-picker">
        <div class="ob-picker-header">
          <div class="ob-picker-brand">🛡 ThreatLens</div>
          <div class="ob-picker-tagline">Context-aware SecOps prioritization</div>
          <div class="ob-picker-title">Choose your workspace</div>
          <div class="ob-picker-sub">Sets up your filters and view — you can change it anytime</div>
        </div>
        <div class="ob-persona-grid">
          ${personaCards}
        </div>
        <button class="ob-picker-skip">Skip — explore freely →</button>
      </div>`;

    // Bind persona cards
    overlay.querySelectorAll('.ob-persona-card').forEach(btn => {
      btn.addEventListener('click', () => {
        const pid = btn.dataset.personaId;
        if (typeof PersonaPresets !== 'undefined') PersonaPresets.pickAndActivate(pid);
        dismiss();
      });
    });

    // Bind skip
    overlay.querySelector('.ob-picker-skip')?.addEventListener('click', dismiss);

    return overlay;
  }

  // ── Injection dans le DOM ─────────────────────────────────────────────────

  function show() {
    if (document.getElementById('ob-overlay')) return; // idempotent
    // Supprimer l'ancienne carte v5 si présente
    document.getElementById('onboarding-card')?.remove();

    const overlay = _render();
    document.body.appendChild(overlay);

    // Entrance animation (double rAF pour forcer la transition CSS)
    requestAnimationFrame(() => {
      requestAnimationFrame(() => overlay.classList.add('ob-visible'));
    });
  }

  // ── Auto-init : affiche immédiatement (pas d'attente du feed) ─────────────

  function init() {
    if (_isSeen()) return;
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', show);
    } else {
      show();
    }
  }

  // ── Re-trigger (bouton "?" de la barre Vues métier) ───────────────────────

  function showTour() {
    try { localStorage.removeItem(SEEN_KEY); } catch {}
    show();
  }

  return { init, dismiss, show, showTour };

})();

// Auto-init
Onboarding.init();
