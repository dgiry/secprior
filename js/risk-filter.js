// risk-filter.js — Filtre "Risque Réel" orienté menace opérationnelle
//
// Affiche une barre de filtres combinables sous la navbar.
// Chaque pill est un critère indépendant, combinés en AND :
//   ⚠  KEV actif    → présent dans CISA KEV (exploitation active confirmée)
//   📊  EPSS > N%   → probabilité d'exploitation dans 30j au-dessus du seuil
//   👁  Watchlist   → correspond à un terme de la watchlist utilisateur
//   🔥  Trending    → couvert par 3+ sources simultanément (signal fort)
//   🔬  IOCs        → contient des indicateurs extraits (hashes, IPs, domaines)
//   💀  0-Day       → vulnérabilité zero-day détectée (aucun patch disponible)
//
// API publique :
//   RiskFilter.init(onChangeFn) → initialise la barre, bind les events
//   RiskFilter.toggle()         → affiche / cache la barre
//   RiskFilter.getFilters()     → { active: Set, epssThreshold: 0.10 }
//   RiskFilter.setCount(n)      → met à jour le compteur d'articles correspondants
//   RiskFilter.hasActive()      → true si au moins un filtre est actif

const RiskFilter = (() => {

  // ── Définition des filtres ──────────────────────────────────────────────────
  const PILLS = [
    {
      id:    'kev',
      icon:  '⚠',
      label: 'KEV active',
      title: 'Present in CISA Known Exploited Vulnerabilities\nActive exploitation confirmed in production',
      color: 'kev'
    },
    {
      id:    'epss',
      icon:  '📊',
      label: 'EPSS',        // label complété par le seuil dynamique
      title: 'EPSS score (FIRST.org) above the defined threshold\nExploitation probability within the next 30 days',
      color: 'epss',
      hasInput: true        // pill avec champ numérique intégré
    },
    {
      id:    'watchlist',
      icon:  '👁',
      label: 'Watchlist',
      title: 'Matches a term in your watchlist\n(vendors, products, CVEs, specific threats)',
      color: 'watchlist'
    },
    {
      id:    'trending',
      icon:  '🔥',
      label: 'Trending',
      title: 'Topic covered simultaneously by 3+ RSS sources\nStrong signal — widely confirmed threat',
      color: 'trending'
    },
    {
      id:    'ioc',
      icon:  '🔬',
      label: 'IOCs',
      title: 'Contient des indicateurs extraits automatiquement\n(hashes SHA256/MD5, adresses IP, domaines suspects)',
      color: 'ioc'
    },
    {
      id:    'zero_day',
      icon:  '💀',
      label: '0-Day',
      title: 'Zero-day vulnerability — no official patch available\nDetected via ATT&CK T1203 or zero-day / 0day keywords',
      color: 'zero_day'
    }
  ];

  // ── État interne ────────────────────────────────────────────────────────────
  let _active    = new Set();    // IDs des pills actives
  let _threshold = 10;           // Seuil EPSS en % (1-99)
  let _onChange  = null;         // Callback → app.js re-render
  let _visible   = false;

  // ── API publique ────────────────────────────────────────────────────────────

  function init(onChangeFn) {
    _onChange = onChangeFn;
    _injectBar();
    document.getElementById('btn-risk-filter')
      ?.addEventListener('click', toggle);
  }

  function toggle() {
    _visible = !_visible;
    const bar = document.getElementById('risk-filter-bar');
    if (bar) bar.style.display = _visible ? 'flex' : 'none';
    document.getElementById('btn-risk-filter')
      ?.classList.toggle('active', _visible || _active.size > 0);
  }

  function getFilters() {
    return {
      active:        new Set(_active),
      epssThreshold: _threshold / 100
    };
  }

  function hasActive() { return _active.size > 0; }

  function setCount(n) {
    // Compteur dans la barre
    const countEl = document.getElementById('risk-result-count');
    if (countEl) {
      countEl.textContent = _active.size > 0
        ? `${n} article${n !== 1 ? 's' : ''} match${n === 1 ? 'es' : ''}`
        : '';
      countEl.style.display = _active.size > 0 ? 'inline' : 'none';
    }

    // Badge sur le bouton navbar (nombre de filtres actifs)
    const badge = document.getElementById('risk-nav-badge');
    if (badge) {
      badge.textContent = _active.size > 0 ? _active.size : '';
      badge.style.display = _active.size > 0 ? 'inline-flex' : 'none';
    }
    document.getElementById('btn-risk-filter')
      ?.classList.toggle('active', _active.size > 0);
  }

  // ── Construction de la barre ───────────────────────────────────────────────

  function _injectBar() {
    // Cibler le conteneur prévu dans le HTML
    const container = document.getElementById('risk-filter-container');
    if (!container || document.getElementById('risk-filter-bar')) return;

    const bar = document.createElement('div');
    bar.id        = 'risk-filter-bar';
    bar.className = 'risk-filter-bar';
    bar.style.display = 'none';

    bar.innerHTML = `
      <div class="risk-filter-inner">

        <span class="risk-filter-label">🎯 Operational threat</span>

        <div class="risk-pills" id="risk-pills-list">
          ${PILLS.map(p => _pillHTML(p)).join('')}
        </div>

        <div class="risk-filter-end">
          <span id="risk-result-count" class="risk-result-count" style="display:none"></span>
          <button id="risk-clear-btn" class="risk-clear-btn" title="Clear all filters">
            ✕ Clear
          </button>
        </div>

      </div>

      <div id="risk-desc-row" class="risk-desc-row" style="display:none">
        <span id="risk-desc-text" class="risk-desc-text"></span>
      </div>`;

    container.appendChild(bar);
    _bindBarEvents(bar);
  }

  function _pillHTML(p) {
    if (p.hasInput) {
      // Pill EPSS avec champ numérique intégré
      return `
        <div class="risk-pill-wrap" data-risk="${p.id}">
          <button class="risk-pill risk-pill-${p.color}" data-risk="${p.id}"
                  title="${p.title}">
            ${p.icon}
          </button>
          <span class="risk-pill-sep">EPSS &gt;</span>
          <input  class="risk-epss-input" id="risk-epss-input"
                  type="number" min="1" max="99" value="${_threshold}"
                  title="EPSS threshold (%)">
          <span class="risk-pill-pct">%</span>
        </div>`;
    }
    return `
      <button class="risk-pill risk-pill-${p.color}" data-risk="${p.id}"
              title="${p.title}">
        ${p.icon} ${p.label}
      </button>`;
  }

  function _bindBarEvents(bar) {
    // ── Clic sur chaque pill ────────────────────────────────────────────────
    bar.querySelectorAll('.risk-pill[data-risk]').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.risk;
        if (_active.has(id)) {
          _active.delete(id);
          _deactivatePill(id);
        } else {
          _active.add(id);
          _activatePill(id);
        }
        _updateDesc();
        _notify();
      });
    });

    // ── Champ seuil EPSS ────────────────────────────────────────────────────
    const epssInput = document.getElementById('risk-epss-input');
    if (epssInput) {
      // Empêcher le clic sur l'input de déclencher le bouton parent
      epssInput.addEventListener('click',   e => e.stopPropagation());
      epssInput.addEventListener('mousedown', e => e.stopPropagation());

      epssInput.addEventListener('change', e => {
        _threshold = Math.max(1, Math.min(99, parseInt(e.target.value) || 10));
        e.target.value = _threshold;
        if (_active.has('epss')) _notify(); // re-filter si EPSS actif
      });
    }

    // ── Bouton Effacer ──────────────────────────────────────────────────────
    document.getElementById('risk-clear-btn')?.addEventListener('click', () => {
      _active.clear();
      bar.querySelectorAll('.risk-pill').forEach(b => {
        b.classList.remove('risk-pill-active');
        b.removeAttribute('aria-pressed');
      });
      _updateDesc();
      _notify();
    });
  }

  // ── Activation / désactivation visuelle ──────────────────────────────────

  function _activatePill(id) {
    const btn = document.querySelector(`.risk-pill[data-risk="${id}"]`);
    if (btn) { btn.classList.add('risk-pill-active'); btn.setAttribute('aria-pressed', 'true'); }
  }

  function _deactivatePill(id) {
    const btn = document.querySelector(`.risk-pill[data-risk="${id}"]`);
    if (btn) { btn.classList.remove('risk-pill-active'); btn.removeAttribute('aria-pressed'); }
  }

  // ── Description textuelle des filtres actifs ─────────────────────────────

  function _updateDesc() {
    const descRow  = document.getElementById('risk-desc-row');
    const descText = document.getElementById('risk-desc-text');
    if (!descRow || !descText) return;

    if (_active.size === 0) {
      descRow.style.display = 'none';
      return;
    }

    const labels = {
      kev:       'Actively exploited (KEV)',
      epss:      `EPSS ≥ ${_threshold}%`,
      watchlist: 'In watchlist',
      trending:  'Trending (3+ sources)',
      ioc:       'Containing IOCs',
      zero_day:  '0-Day / sans patch'
    };

    const parts = [..._active].map(id => `<strong>${labels[id] || id}</strong>`);
    descText.innerHTML = `Showing only articles matching: ${parts.join(' AND ')}`;
    descRow.style.display = 'flex';
  }

  // ── Notification de changement ────────────────────────────────────────────

  function _notify() {
    if (_onChange) _onChange();
  }

  // ── Activer / désactiver une pill depuis l'extérieur (ex: bouton navbar IOC) ─
  function togglePill(id) {
    if (_active.has(id)) {
      _active.delete(id);
      _deactivatePill(id);
    } else {
      _active.add(id);
      _activatePill(id);
    }
    _updateDesc();
    _notify();
  }

  return { init, toggle, getFilters, hasActive, setCount, togglePill };
})();
