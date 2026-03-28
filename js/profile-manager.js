// profile-manager.js — Profils d'exposition multi-contexte CyberVeille Pro
//
// Fournit un stockage localStorage structuré pour plusieurs profils d'exposition.
// Chaque profil contient sa propre watchlist (termes surveillés) + métadonnées.
//
// Clé de stockage : "cv_profiles"
// Migration automatique : si "cv_watchlist" (ancien format) existe, son contenu
//   est copié dans le profil par défaut au premier chargement.
//
// Structure en localStorage :
//   {
//     activeProfileId: "default",
//     profiles: {
//       "default": {
//         id, name, description, badge, createdAt,
//         watchlist: [...],      // même format que l'ancien cv_watchlist (V2)
//         // Champs réservés pour futurs paramètres de profil :
//         // tags: [], notes: "", localCriticality: null, alertThreshold: null
//       },
//       "p_abc123": { ... }
//     }
//   }
//
// Compatibilité : si "cv_profiles" est absent, le module crée automatiquement
//   le profil "default" et y migre le contenu de "cv_watchlist".
//   L'ancienne clé "cv_watchlist" est supprimée après migration réussie.

const ProfileManager = (() => {

  const STORE_KEY  = 'cv_profiles';   // Nouvelle clé multi-profil
  const LEGACY_KEY = 'cv_watchlist';  // Ancienne clé — lecture uniquement pour migration
  const DEFAULT_ID = 'default';

  // Badges disponibles pour un profil (emoji visuellement distinctifs)
  const BADGES = ['🔵', '🟠', '🟢', '🔴', '🟣', '🟡', '⚪', '🏢', '🔒', '🌐'];

  // ── Structure initiale ────────────────────────────────────────────────────

  function _defaultStore() {
    return {
      activeProfileId: DEFAULT_ID,
      profiles: {
        [DEFAULT_ID]: {
          id:          DEFAULT_ID,
          name:        'Main profile',
          description: '',
          badge:       '🔵',
          createdAt:   new Date().toISOString(),
          watchlist:   []
          // Champs réservés pour un sprint futur :
          // tags: [], notes: '', localCriticality: null, alertThreshold: null
        }
      }
    };
  }

  // ── Chargement avec migration automatique ─────────────────────────────────

  function _load() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        // Validation minimale de la structure
        if (parsed?.profiles && parsed?.activeProfileId) return parsed;
      }
    } catch (e) {
      console.warn('[ProfileManager] Lecture store échouée:', e.message);
    }

    // Première ouverture ou structure invalide → créer le store par défaut
    const store = _defaultStore();

    // Migrer l'ancienne watchlist unique vers le profil par défaut
    try {
      const legacyRaw = localStorage.getItem(LEGACY_KEY);
      if (legacyRaw) {
        const legacy = JSON.parse(legacyRaw);
        if (Array.isArray(legacy) && legacy.length > 0) {
          store.profiles[DEFAULT_ID].watchlist = legacy;
          store.profiles[DEFAULT_ID].name = 'Main profile';
          console.info(
            `[ProfileManager] Migration : ${legacy.length} terme(s) watchlist → profil "${DEFAULT_ID}"`
          );
        }
      }
    } catch { /* migration silencieuse — ne pas bloquer */ }

    return store;
  }

  function _save(store) {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(store));
      // Supprimer l'ancienne clé après migration réussie
      localStorage.removeItem(LEGACY_KEY);
    } catch (e) {
      console.warn('[ProfileManager] Sauvegarde échouée:', e.message);
    }
  }

  // Garantit que activeProfileId pointe vers un profil existant
  function _ensureActive(store) {
    if (!store.profiles[store.activeProfileId]) {
      const ids = Object.keys(store.profiles);
      store.activeProfileId = ids.includes(DEFAULT_ID) ? DEFAULT_ID : (ids[0] || DEFAULT_ID);
    }
    return store;
  }

  // ── API profils ───────────────────────────────────────────────────────────

  function getActiveId() {
    return _ensureActive(_load()).activeProfileId;
  }

  function getActiveProfile() {
    const store = _ensureActive(_load());
    return store.profiles[store.activeProfileId];
  }

  function getAllProfiles() {
    const store = _load();
    return Object.values(store.profiles).sort((a, b) => {
      if (a.id === DEFAULT_ID) return -1;
      if (b.id === DEFAULT_ID) return 1;
      return (a.createdAt || '').localeCompare(b.createdAt || '');
    });
  }

  function setActiveProfile(id) {
    const store = _load();
    if (!store.profiles[id]) return false;
    store.activeProfileId = id;
    _save(store);
    return true;
  }

  function createProfile(name, opts = {}) {
    const store = _load();
    const id    = 'p_' + Math.random().toString(36).slice(2, 10);
    store.profiles[id] = {
      id,
      name:        (name || '').trim().slice(0, 40) || 'New profile',
      description: ((opts.description || '')).trim().slice(0, 120),
      badge:       BADGES.includes(opts.badge) ? opts.badge : BADGES[0],
      createdAt:   new Date().toISOString(),
      watchlist:   Array.isArray(opts.watchlist) ? opts.watchlist : []
    };
    _save(store);
    return id;
  }

  function updateProfile(id, patch) {
    const store = _load();
    if (!store.profiles[id]) return false;
    const p = store.profiles[id];
    if (patch.name !== undefined)
      p.name = (patch.name || '').trim().slice(0, 40) || p.name;
    if (patch.description !== undefined)
      p.description = (patch.description || '').trim().slice(0, 120);
    if (patch.badge !== undefined && BADGES.includes(patch.badge))
      p.badge = patch.badge;
    _save(store);
    return true;
  }

  function deleteProfile(id) {
    if (id === DEFAULT_ID) return false; // le profil par défaut est non-supprimable
    const store = _load();
    if (!store.profiles[id]) return false;
    if (Object.keys(store.profiles).length <= 1) return false; // garder au moins 1
    delete store.profiles[id];
    if (store.activeProfileId === id) store.activeProfileId = DEFAULT_ID;
    _save(store);
    return true;
  }

  // ── API watchlist du profil actif ─────────────────────────────────────────
  // Ces deux fonctions sont le point d'intégration avec contextualizer.js

  function getActiveWatchlist() {
    return getActiveProfile()?.watchlist || [];
  }

  function saveActiveWatchlist(list) {
    const store = _ensureActive(_load());
    const pid   = store.activeProfileId;
    if (store.profiles[pid]) {
      store.profiles[pid].watchlist = list;
      _save(store);
    }
  }

  // ── API publique ──────────────────────────────────────────────────────────

  return {
    BADGES,
    DEFAULT_ID,
    getActiveId,
    getActiveProfile,
    getAllProfiles,
    setActiveProfile,
    createProfile,
    updateProfile,
    deleteProfile,
    getActiveWatchlist,
    saveActiveWatchlist
  };

})();
