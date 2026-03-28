// pwa.js — Gestion PWA : installation, hors-ligne, mises à jour
//
// Fonctionnalités :
//   • Enregistrement du Service Worker
//   • Bannière d'installation (bouton "Installer l'app")
//   • Barre hors-ligne (détection online/offline + auto-refresh à la reconnexion)
//   • Toast "Mise à jour disponible" avec rechargement en un clic
//   • Gestion des raccourcis URL (manifest shortcuts)

const PWA = (() => {

  let _deferredPrompt = null; // BeforeInstallPromptEvent

  // ── Enregistrement du Service Worker ────────────────────────────────────────

  async function _registerSW() {
    if (!('serviceWorker' in navigator)) {
      console.info('[PWA] Service Workers non supportés dans ce navigateur.');
      return;
    }
    try {
      const reg = await navigator.serviceWorker.register('/service-worker.js', { scope: '/' });
      console.info('[PWA] Service Worker enregistré :', reg.scope);

      // Écouter les mises à jour disponibles
      reg.addEventListener('updatefound', () => {
        const newSW = reg.installing;
        if (!newSW) return;
        newSW.addEventListener('statechange', () => {
          if (newSW.state === 'installed' && navigator.serviceWorker.controller) {
            // Une nouvelle version est prête
            _showUpdateBanner(newSW);
          }
        });
      });

      // Recharger tous les onglets après activation du nouveau SW
      let refreshing = false;
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        if (!refreshing) { refreshing = true; window.location.reload(); }
      });

    } catch (err) {
      console.warn('[PWA] Échec enregistrement SW :', err);
    }
  }

  // ── Invite d'installation ────────────────────────────────────────────────────

  function _listenInstallPrompt() {
    window.addEventListener('beforeinstallprompt', e => {
      // Empêcher l'invite automatique du navigateur
      e.preventDefault();
      _deferredPrompt = e;
      _showInstallBanner();
    });

    window.addEventListener('appinstalled', () => {
      _deferredPrompt = null;
      document.getElementById('pwa-install-banner')?.remove();
      if (window.UI) UI.showToast('ThreatLens installed! 🎉', 'success');
    });
  }

  function _showInstallBanner() {
    if (document.getElementById('pwa-install-banner')) return;
    // Ne pas afficher si déjà en mode standalone (déjà installé)
    if (window.matchMedia('(display-mode: standalone)').matches) return;

    const banner = document.createElement('div');
    banner.id = 'pwa-install-banner';
    banner.innerHTML = `
      <span class="pwa-banner-text">
        📲 <strong>Installez l'app</strong> pour un accès rapide et le mode hors-ligne
      </span>
      <div class="pwa-banner-actions">
        <button id="pwa-install-btn" class="btn btn-primary pwa-btn">Installer</button>
        <button id="pwa-install-dismiss" class="pwa-dismiss" title="Close">✕</button>
      </div>
    `;
    // Insérer sous la navbar
    const navbar = document.querySelector('.navbar');
    navbar ? navbar.after(banner) : document.body.prepend(banner);

    document.getElementById('pwa-install-btn')?.addEventListener('click', async () => {
      if (!_deferredPrompt) return;
      _deferredPrompt.prompt();
      const { outcome } = await _deferredPrompt.userChoice;
      _deferredPrompt = null;
      if (outcome === 'accepted') banner.remove();
    });

    document.getElementById('pwa-install-dismiss')?.addEventListener('click', () => {
      banner.remove();
      // Ne plus afficher pendant 7 jours
      localStorage.setItem('cv_pwa_dismissed', Date.now() + 7 * 86_400_000);
    });
  }

  // ── Détection connectivité ────────────────────────────────────────────────────

  function _listenConnectivity() {
    const _update = () => {
      const offline = !navigator.onLine;
      let bar = document.getElementById('pwa-offline-bar');

      if (offline) {
        if (!bar) {
          bar = document.createElement('div');
          bar.id = 'pwa-offline-bar';
          bar.innerHTML = `
            <span>⚡ Mode hors-ligne</span>
            <span class="pwa-offline-hint">Les articles affichés proviennent du cache local</span>
          `;
          const navbar = document.querySelector('.navbar');
          navbar ? navbar.after(bar) : document.body.prepend(bar);
        }
      } else {
        if (bar) {
          bar.remove();
          if (window.UI) UI.showToast('Connexion rétablie — Actualisation en cours…', 'success');
          // Auto-refresh à la reconnexion
          setTimeout(() => window.App?.refreshForced?.(), 500);
        }
      }
    };

    window.addEventListener('online',  _update);
    window.addEventListener('offline', _update);
    _update(); // vérification initiale
  }

  // ── Bannière mise à jour disponible ──────────────────────────────────────────

  function _showUpdateBanner(newSW) {
    if (document.getElementById('pwa-update-banner')) return;
    const banner = document.createElement('div');
    banner.id = 'pwa-update-banner';
    banner.innerHTML = `
      <span>🔄 <strong>Update available</strong> — A new version of ThreatLens is ready</span>
      <div class="pwa-banner-actions">
        <button id="pwa-reload-btn" class="btn btn-primary pwa-btn">Update</button>
        <button id="pwa-update-dismiss" class="pwa-dismiss" title="Plus tard">✕</button>
      </div>
    `;
    const navbar = document.querySelector('.navbar');
    navbar ? navbar.after(banner) : document.body.prepend(banner);

    document.getElementById('pwa-reload-btn')?.addEventListener('click', () => {
      newSW.postMessage({ type: 'SKIP_WAITING' });
    });
    document.getElementById('pwa-update-dismiss')?.addEventListener('click', () => banner.remove());
  }

  // ── Gestion des raccourcis URL (manifest shortcuts) ───────────────────────────
  // Permet les URL ?criticality=high, ?view=favs, ?action=pdf

  function _handleURLShortcuts() {
    const params = new URLSearchParams(location.search);

    const criticality = params.get('criticality');
    const view        = params.get('view');
    const action      = params.get('action');

    if (criticality) {
      // Appliquer le filtre de criticité une fois le DOM prêt
      const sel = document.getElementById('filter-criticality');
      if (sel) {
        sel.value = criticality;
        sel.dispatchEvent(new Event('change'));
      }
    }

    if (view === 'favs') {
      const btn = document.getElementById('btn-favs');
      btn?.click();
    }

    if (action === 'pdf') {
      // Déclencher le PDF après le premier chargement des articles
      const _tryPDF = () => {
        const btn = document.getElementById('btn-pdf');
        if (btn && window._statsLastArticles?.length) {
          btn.click();
        } else {
          setTimeout(_tryPDF, 1000);
        }
      };
      setTimeout(_tryPDF, 2000);
    }

    // Nettoyer l'URL sans recharger la page
    if (criticality || view || action) {
      history.replaceState({}, '', location.pathname);
    }
  }

  // ── Init ─────────────────────────────────────────────────────────────────────

  function init() {
    // Vérifier si la bannière d'install a été récemment dismissée
    const dismissed = parseInt(localStorage.getItem('cv_pwa_dismissed') || '0');
    const skipInstall = dismissed > Date.now();

    _registerSW();
    if (!skipInstall) _listenInstallPrompt();
    _listenConnectivity();
    _handleURLShortcuts();
  }

  return { init };
})();
