// profile-switcher.js — UI de sélection de profil d'exposition CyberVeille Pro
//
// Peuple la barre #profile-bar (div statique dans index.html) avec :
//   • Pill "profil actif" avec dropdown de sélection
//   • Bouton "+ Créer" → modal inline de création
//   • Bouton "✎" → modal inline de gestion (renommer, badge, supprimer)
//
// Après un changement de profil, la watchlist change → pipeline re-run via
//   le bouton Actualiser (re-contextualise les articles avec la nouvelle watchlist).
//
// Dépendances : ProfileManager (doit être chargé avant ce script)
//
// Idempotent : init() est sans effet si déjà initialisé.

const ProfileSwitcher = (() => {

  let _dropdownOpen = false;

  // ── Helpers ───────────────────────────────────────────────────────────────

  function _esc(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function _closeDropdown() {
    const dd = document.getElementById('prb-dropdown');
    if (dd) dd.style.display = 'none';
    _dropdownOpen = false;
  }

  // ── Rendu de la barre ─────────────────────────────────────────────────────

  function _render() {
    const bar = document.getElementById('profile-bar');
    if (!bar) return;

    const active   = ProfileManager.getActiveProfile();
    const profiles = ProfileManager.getAllProfiles();

    // ── Ligne persona active (Sprint 24) ──
    let personaLineHTML = '';
    if (typeof PersonaPresets !== 'undefined') {
      const persona = PersonaPresets.getActivePersona();
      if (persona) {
        personaLineHTML = `
          <div class="prb-persona-line" id="prb-persona-line">
            <span class="prb-persona-line-label">View:</span>
            <span class="prb-persona-line-icon">${_esc(persona.icon)}</span>
            <span class="prb-persona-line-name">${_esc(persona.name)}</span>
          </div>`;
      }
    }

    bar.innerHTML = `
      <div class="prb-wrapper">
        <div class="prb-line1">
          <div class="prb-pill-wrap">
            <button class="prb-active-pill" id="prb-toggle"
                    title="Switch active exposure profile">
              <span class="prb-badge">${_esc(active.badge)}</span>
              <span class="prb-name">${_esc(active.name)}</span>
              <span class="prb-arrow">▾</span>
            </button>
            <div class="prb-dropdown" id="prb-dropdown" style="display:none">
              <div class="prb-dd-section-label">Profiles</div>
              ${profiles.map(p => `
                <button class="prb-option${p.id === active.id ? ' prb-option-active' : ''}"
                        data-pid="${_esc(p.id)}"
                        title="${_esc(p.description || p.name)}">
                  <span class="prb-badge">${_esc(p.badge)}</span>
                  <span class="prb-option-name">${_esc(p.name)}</span>
                  ${p.id === active.id ? '<span class="prb-check">✓</span>' : ''}
                </button>`).join('')}
              <div class="prb-sep"></div>
              <button class="prb-option prb-option-create" id="prb-new-btn"
                      title="Create a new exposure profile">
                ＋ Create profile
              </button>
              <div class="prb-sep"></div>
              <button class="prb-option prb-option-manage" id="prb-manage-dd-btn"
                      title="Manage active profile (rename, badge, delete)">
                ⚙ Manage profiles
              </button>
            </div>
          </div>
          <button class="prb-manage-btn" id="prb-manage-btn"
                  title="Manage this profile (rename, badge, delete)">✎</button>
        </div>
        ${personaLineHTML}
      </div>`;

    // Bind dropdown toggle
    bar.querySelector('#prb-toggle').addEventListener('click', e => {
      e.stopPropagation();
      const dd = document.getElementById('prb-dropdown');
      _dropdownOpen = !_dropdownOpen;
      dd.style.display = _dropdownOpen ? 'block' : 'none';
    });

    // Bind sélection de profil
    bar.querySelectorAll('.prb-option[data-pid]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        _closeDropdown();
        const pid = btn.dataset.pid;
        if (pid === ProfileManager.getActiveId()) return;
        if (ProfileManager.setActiveProfile(pid)) {
          _onProfileChange();
        }
      });
    });

    // Bind "＋ Créer un profil"
    bar.querySelector('#prb-new-btn')?.addEventListener('click', e => {
      e.stopPropagation();
      _closeDropdown();
      _showCreateModal();
    });

    // Bind "✎ Gérer" (bouton pill extérieur)
    bar.querySelector('#prb-manage-btn')?.addEventListener('click', () => {
      _closeDropdown();
      _showManageModal();
    });

    // Bind "⚙ Gérer les profils" (section C du dropdown)
    bar.querySelector('#prb-manage-dd-btn')?.addEventListener('click', e => {
      e.stopPropagation();
      _closeDropdown();
      _showManageModal();
    });
  }

  // ── Changement de profil ──────────────────────────────────────────────────

  function _onProfileChange() {
    // Effacer la vue persona active avant le re-rendu (évite un flash de l'ancien contexte)
    if (typeof PersonaPresets !== 'undefined') PersonaPresets.clearActive();

    _render(); // re-rendre la barre avec le nouveau profil (persona line déjà absente)
    _rerenderWatchlistModal();

    // Mettre à jour le dashboard profil immédiatement (header + termes)
    if (typeof ProfilePanel !== 'undefined') ProfilePanel.refreshProfile();

    const name = ProfileManager.getActiveProfile().name;
    if (typeof UI !== 'undefined')
      UI.showToast(`✅ Profile «${name}» activated — refreshing…`, 'success');

    // Re-lancer le pipeline pour re-contextualiser avec la nouvelle watchlist
    setTimeout(() => {
      document.getElementById('btn-refresh')?.click();
    }, 300);
  }

  // Si la watchlist modal est ouverte, la rafraîchir pour montrer la bonne watchlist
  function _rerenderWatchlistModal() {
    const modal = document.getElementById('modal-watchlist');
    if (modal && modal.style.display !== 'none') {
      if (typeof WatchlistModal !== 'undefined') {
        WatchlistModal.close();
        WatchlistModal.open();
      }
    }
  }

  // ── Modal création de profil ──────────────────────────────────────────────

  function _showCreateModal() {
    _injectModalDOM();
    const modal = document.getElementById('prb-modal');
    if (!modal) return;

    const badges = ProfileManager.BADGES;
    let selectedBadge = badges[0];

    modal.innerHTML = `
      <div class="prb-modal-box">
        <div class="prb-modal-header">
          <h3>Create profile</h3>
          <button class="prb-modal-close" id="prb-modal-close">✕</button>
        </div>
        <div class="prb-modal-body">
          <label class="prb-field-label">Profile name</label>
          <input id="prb-input-name" class="prb-input" type="text"
                 placeholder="E.g.: Client A, Internal, CISO demo…"
                 maxlength="40" autocomplete="off">

          <label class="prb-field-label">Short description (optional)</label>
          <input id="prb-input-desc" class="prb-input" type="text"
                 placeholder="E.g.: Cloud servers scope…"
                 maxlength="120" autocomplete="off">

          <label class="prb-field-label">Badge</label>
          <div class="prb-badge-picker" id="prb-badge-picker">
            ${badges.map(b => `
              <button class="prb-badge-opt${b === selectedBadge ? ' prb-badge-sel' : ''}"
                      data-badge="${b}" title="${b}">${b}</button>`).join('')}
          </div>
        </div>
        <div class="prb-modal-footer">
          <button class="btn" id="prb-modal-cancel">Cancel</button>
          <button class="btn btn-primary" id="prb-modal-create">Create</button>
        </div>
      </div>`;

    modal.style.display = 'flex';

    // Badge picker
    modal.querySelectorAll('.prb-badge-opt').forEach(btn => {
      btn.addEventListener('click', () => {
        modal.querySelectorAll('.prb-badge-opt').forEach(b => b.classList.remove('prb-badge-sel'));
        btn.classList.add('prb-badge-sel');
        selectedBadge = btn.dataset.badge;
      });
    });

    // Dismiss
    modal.querySelector('#prb-modal-close')?.addEventListener('click',  () => _hideModal());
    modal.querySelector('#prb-modal-cancel')?.addEventListener('click', () => _hideModal());
    modal.addEventListener('click', e => { if (e.target === modal) _hideModal(); });

    // Créer
    modal.querySelector('#prb-modal-create')?.addEventListener('click', () => {
      const name = document.getElementById('prb-input-name')?.value?.trim();
      if (!name) {
        document.getElementById('prb-input-name')?.focus();
        return;
      }
      const desc  = document.getElementById('prb-input-desc')?.value?.trim() || '';
      const newId = ProfileManager.createProfile(name, { description: desc, badge: selectedBadge });
      ProfileManager.setActiveProfile(newId);
      _hideModal();
      _onProfileChange();
    });

    // Focus auto
    setTimeout(() => document.getElementById('prb-input-name')?.focus(), 80);
  }

  // ── Modal gestion du profil actif ─────────────────────────────────────────

  function _showManageModal() {
    _injectModalDOM();
    const modal  = document.getElementById('prb-modal');
    const active = ProfileManager.getActiveProfile();
    if (!modal) return;

    const badges = ProfileManager.BADGES;
    let selectedBadge = active.badge;
    const isDefault = active.id === ProfileManager.DEFAULT_ID;

    modal.innerHTML = `
      <div class="prb-modal-box">
        <div class="prb-modal-header">
          <h3>Manage profile</h3>
          <button class="prb-modal-close" id="prb-modal-close">✕</button>
        </div>
        <div class="prb-modal-body">
          <label class="prb-field-label">Name</label>
          <input id="prb-input-name" class="prb-input" type="text"
                 value="${_esc(active.name)}" maxlength="40" autocomplete="off">

          <label class="prb-field-label">Description</label>
          <input id="prb-input-desc" class="prb-input" type="text"
                 value="${_esc(active.description || '')}" maxlength="120" autocomplete="off">

          <label class="prb-field-label">Badge</label>
          <div class="prb-badge-picker" id="prb-badge-picker">
            ${badges.map(b => `
              <button class="prb-badge-opt${b === selectedBadge ? ' prb-badge-sel' : ''}"
                      data-badge="${b}" title="${b}">${b}</button>`).join('')}
          </div>

          <p class="prb-field-hint">
            Watchlist: ${active.watchlist?.length || 0} term(s) ·
            Created on ${new Date(active.createdAt || Date.now()).toLocaleDateString('en-US')}
          </p>
        </div>
        <div class="prb-modal-footer">
          ${!isDefault ? `<button class="btn prb-delete-btn" id="prb-modal-delete">🗑 Delete</button>` : ''}
          <button class="btn" id="prb-modal-cancel">Cancel</button>
          <button class="btn btn-primary" id="prb-modal-save">Save</button>
        </div>
      </div>`;

    modal.style.display = 'flex';

    // Badge picker
    modal.querySelectorAll('.prb-badge-opt').forEach(btn => {
      btn.addEventListener('click', () => {
        modal.querySelectorAll('.prb-badge-opt').forEach(b => b.classList.remove('prb-badge-sel'));
        btn.classList.add('prb-badge-sel');
        selectedBadge = btn.dataset.badge;
      });
    });

    // Dismiss
    modal.querySelector('#prb-modal-close')?.addEventListener('click',  () => _hideModal());
    modal.querySelector('#prb-modal-cancel')?.addEventListener('click', () => _hideModal());
    modal.addEventListener('click', e => { if (e.target === modal) _hideModal(); });

    // Enregistrer
    modal.querySelector('#prb-modal-save')?.addEventListener('click', () => {
      const name = document.getElementById('prb-input-name')?.value?.trim();
      if (!name) { document.getElementById('prb-input-name')?.focus(); return; }
      const desc = document.getElementById('prb-input-desc')?.value?.trim() || '';
      ProfileManager.updateProfile(active.id, { name, description: desc, badge: selectedBadge });
      _hideModal();
      _render();
      if (typeof UI !== 'undefined') UI.showToast('✅ Profile updated', 'success');
    });

    // Supprimer
    modal.querySelector('#prb-modal-delete')?.addEventListener('click', () => {
      if (!confirm(`Delete profile «${active.name}» and its watchlist? This action cannot be undone.`)) return;
      ProfileManager.deleteProfile(active.id);
      _hideModal();
      _onProfileChange();
    });

    setTimeout(() => document.getElementById('prb-input-name')?.focus(), 80);
  }

  // ── DOM modal (injecté une seule fois) ───────────────────────────────────

  function _injectModalDOM() {
    if (document.getElementById('prb-modal')) return;
    const el = document.createElement('div');
    el.id        = 'prb-modal';
    el.className = 'prb-modal-overlay';
    el.style.display = 'none';
    document.body.appendChild(el);
  }

  function _hideModal() {
    const modal = document.getElementById('prb-modal');
    if (modal) modal.style.display = 'none';
  }

  // ── Fermer dropdown au clic extérieur ────────────────────────────────────

  function _bindGlobalClose() {
    document.addEventListener('click', () => _closeDropdown());
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') { _closeDropdown(); _hideModal(); }
    });
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  function init() {
    const bar = document.getElementById('profile-bar');
    if (!bar) return;
    if (bar.dataset.init) return; // idempotent
    bar.dataset.init = '1';

    _render();
    _injectModalDOM();
    _bindGlobalClose();
  }

  return { init, render: _render };

})();

// Auto-init : le DOM est prêt (script en fin de body)
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => ProfileSwitcher.init());
} else {
  ProfileSwitcher.init();
}
