// config-export.js — Export / Import de configuration ThreatLens
//
// Permet de transporter la configuration utilisateur entre navigateurs ou machines.
//
// Sections exportées :
//   • cv_profiles        — profils d'exposition + watchlists
//   • cv_saved_filters   — presets sauvegardés
//   • cv_custom_feeds    — flux RSS personnalisés
//   • cv_feed_overrides  — états actif/inactif des flux par défaut
//   • cv_alert_settings  — paramètres alertes (webhook, email…)
//   • cv_favorites       — articles mis en favoris
//   • cv_entity_statuses — workflow incidents (statut, owner, note)
//
// Stratégies d'import :
//   FUSIONNER  — ajoute les éléments absents, conserve l'existant en cas de conflit
//   REMPLACER  — écrase chaque section entièrement avec le contenu importé
//
// Après import : rechargement de la page pour re-initialiser tous les modules.
//
// Intégration : bouton #btn-config-export dans la navbar → ConfigExport.open()

const ConfigExport = (() => {

  const SCHEMA  = 'cyberveille-pro-config';
  const VERSION = 1;

  // ── Champs sensibles dans alertSettings ──────────────────────────────────
  // Ces champs sont exclus de l'export "safe" pour éviter tout partage involontaire.

  const SENSITIVE_FIELDS = [
    'webhookUrl',          // Webhook endpoint URL (may expose internal infra)
    'resendApiKey',        // Resend.com API key          (SECRET)
    'sendgridApiKey',      // SendGrid API key             (SECRET)
    'emailjsPublicKey',    // EmailJS public key           (SECRET)
    'emailjsService',      // EmailJS Service ID           (semi-sensitive)
    'emailjsTemplate',     // EmailJS Template ID          (semi-sensitive)
    'alertToken',          // ALERT_TOKEN for /api/send-alert (SECRET)
    'recipientEmail',      // Destination email address    (PII)
    'resendFrom',          // Sender email address         (PII)
    'sendgridFrom'         // Sender email address         (PII)
  ];

  // ── Clés localStorage ─────────────────────────────────────────────────────

  const KEYS = {
    profiles:      'cv_profiles',
    savedFilters:  'cv_saved_filters',
    customFeeds:   'cv_custom_feeds',
    feedOverrides: 'cv_feed_overrides',
    alertSettings: 'cv_alert_settings',
    favorites:     'cv_favorites',
    workflow:      'cv_entity_statuses'   // incident workflow — status / owner / note
  };

  // ── Helpers ───────────────────────────────────────────────────────────────

  // Retourne une copie de alertSettings sans les champs sensibles.
  function _stripSensitive(settings) {
    const safe = { ...settings };
    SENSITIVE_FIELDS.forEach(k => delete safe[k]);
    return safe;
  }

  function _read(key) {
    try   { return JSON.parse(localStorage.getItem(key) ?? 'null'); }
    catch { return null; }
  }

  function _write(key, val) {
    try   { localStorage.setItem(key, JSON.stringify(val)); return true; }
    catch { return false; }
  }

  function _esc(s) {
    return String(s ?? '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Export ────────────────────────────────────────────────────────────────
  //
  // includeSensitive = true  → export complet (comportement historique)
  // includeSensitive = false → export safe : champs sensibles retirés de alertSettings

  function exportConfig(includeSensitive = true) {
    let alertSettings = _read(KEYS.alertSettings) ?? {};
    if (!includeSensitive) alertSettings = _stripSensitive(alertSettings);

    const payload = {
      schema:       SCHEMA,
      version:      VERSION,
      exportedAt:   new Date().toISOString(),
      app:          'ThreatLens',
      safeExport:   !includeSensitive,   // flag lisible à l'import
      profiles:        _read(KEYS.profiles)      ?? null,
      savedFilters:    _read(KEYS.savedFilters)  ?? [],
      customFeeds:     _read(KEYS.customFeeds)   ?? [],
      feedOverrides:   _read(KEYS.feedOverrides) ?? {},
      alertSettings,
      favorites:       _read(KEYS.favorites)     ?? [],
      entityStatuses:  _read(KEYS.workflow)      ?? {}
    };

    const suffix = includeSensitive ? '' : '-safe';
    const blob = new Blob(
      [JSON.stringify(payload, null, 2)],
      { type: 'application/json' }
    );
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `threatlens-config-${new Date().toISOString().slice(0,10)}${suffix}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    const msg = includeSensitive
      ? '📤 Full configuration exported'
      : '🛡️ Safe export ready (no credentials)';
    if (typeof UI !== 'undefined') UI.showToast(msg, 'success');
  }

  // ── Validation ────────────────────────────────────────────────────────────

  function _validate(data) {
    if (!data || typeof data !== 'object')
      return 'Invalid or empty JSON file.';
    if (data.schema !== SCHEMA)
      return "This file is not a ThreatLens configuration.";
    if (typeof data.version !== 'number')
      return 'Missing schema version.';
    if (data.version > VERSION)
      return `Version ${data.version} not supported (max supported: ${VERSION}).`;
    return null; // OK
  }

  // ── Import — FUSION (ajoute les éléments absents, local gagne les conflits) ─

  function _mergeProfiles(incoming) {
    if (!incoming || typeof incoming !== 'object') return 0;
    const local     = _read(KEYS.profiles) ?? { activeProfileId: 'default', profiles: {} };
    const inProfs   = incoming.profiles ?? {};
    let added = 0;
    Object.entries(inProfs).forEach(([id, prof]) => {
      if (!local.profiles[id]) { local.profiles[id] = prof; added++; }
    });
    // Sécurité : activeProfileId doit exister dans les profils
    if (!local.profiles[local.activeProfileId]) {
      local.activeProfileId = Object.keys(local.profiles)[0] ?? 'default';
    }
    _write(KEYS.profiles, local);
    return added;
  }

  function _mergeSavedFilters(incoming) {
    if (!Array.isArray(incoming)) return 0;
    const local    = _read(KEYS.savedFilters) ?? [];
    const localIds = new Set(local.map(f => f.id).filter(Boolean));
    const toAdd    = incoming.filter(f => f.id && !localIds.has(f.id));
    _write(KEYS.savedFilters, [...local, ...toAdd].slice(0, 20));
    return toAdd.length;
  }

  function _mergeCustomFeeds(incoming) {
    if (!Array.isArray(incoming)) return 0;
    const local    = _read(KEYS.customFeeds) ?? [];
    const localUrls= new Set(local.map(f => (f.url ?? '').toLowerCase()).filter(Boolean));
    const toAdd    = incoming.filter(f => f.url && !localUrls.has(f.url.toLowerCase()));
    _write(KEYS.customFeeds, [...local, ...toAdd]);
    return toAdd.length;
  }

  function _mergeFeedOverrides(incoming) {
    if (!incoming || typeof incoming !== 'object') return;
    const local  = _read(KEYS.feedOverrides) ?? {};
    _write(KEYS.feedOverrides, { ...incoming, ...local }); // local gagne les conflits
  }

  function _mergeAlertSettings(incoming) {
    if (!incoming || typeof incoming !== 'object') return;
    const local = _read(KEYS.alertSettings) ?? {};
    _write(KEYS.alertSettings, { ...incoming, ...local }); // local gagne les conflits
  }

  function _mergeFavorites(incoming) {
    if (!Array.isArray(incoming)) return 0;
    const local  = _read(KEYS.favorites) ?? [];
    const merged = [...new Set([...local, ...incoming])];
    _write(KEYS.favorites, merged);
    return merged.length - local.length;
  }

  // ── Import — REMPLACEMENT (écrase chaque section entièrement) ────────────

  function _replaceProfiles(incoming) {
    if (!incoming || typeof incoming !== 'object') return 0;
    const safe = {
      activeProfileId: incoming.activeProfileId ?? 'default',
      profiles: incoming.profiles ?? {}
    };
    // Sécurité : l'activeProfileId doit exister
    if (!safe.profiles[safe.activeProfileId]) {
      safe.activeProfileId = Object.keys(safe.profiles)[0] ?? 'default';
    }
    // Sécurité : toujours au moins un profil
    if (Object.keys(safe.profiles).length === 0) {
      safe.profiles['default'] = {
        id: 'default', name: 'Main profile', description: '',
        badge: '🔵', createdAt: new Date().toISOString(), watchlist: []
      };
      safe.activeProfileId = 'default';
    }
    _write(KEYS.profiles, safe);
    return Object.keys(safe.profiles).length;
  }

  function _replaceSavedFilters(incoming) {
    const safe = Array.isArray(incoming) ? incoming.slice(0, 20) : [];
    _write(KEYS.savedFilters, safe);
    return safe.length;
  }

  function _replaceCustomFeeds(incoming) {
    const safe = Array.isArray(incoming) ? incoming : [];
    _write(KEYS.customFeeds, safe);
    return safe.length;
  }

  function _replaceFeedOverrides(incoming) {
    _write(KEYS.feedOverrides, (incoming && typeof incoming === 'object') ? incoming : {});
  }

  function _replaceAlertSettings(incoming) {
    if (!incoming || typeof incoming !== 'object') return;
    // Si l'export source était un "safe export", les champs sensibles sont absents.
    // On les préserve depuis le localStorage local pour ne pas effacer les credentials.
    const local  = _read(KEYS.alertSettings) ?? {};
    const merged = { ...incoming };
    SENSITIVE_FIELDS.forEach(k => {
      if (!(k in incoming) && k in local) merged[k] = local[k];
    });
    _write(KEYS.alertSettings, merged);
  }

  function _replaceFavorites(incoming) {
    const safe = Array.isArray(incoming) ? incoming : [];
    _write(KEYS.favorites, safe);
    return safe.length;
  }

  // ── Import — workflow (entity statuses) ───────────────────────────────────
  //
  // Merge  : local gagne les conflits — les choix de l'analyste sont préservés.
  //          Les entrées absentes localement sont importées.
  // Replace: le store entier est remplacé par les données importées.

  function _mergeEntityStatuses(incoming) {
    if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) return 0;
    const local  = _read(KEYS.workflow) ?? {};
    const merged = { ...incoming, ...local }; // local gagne les conflits
    const added  = Object.keys(incoming).filter(k => !local[k]).length;
    _write(KEYS.workflow, merged);
    return added;
  }

  function _replaceEntityStatuses(incoming) {
    if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
      _write(KEYS.workflow, {});
      return 0;
    }
    _write(KEYS.workflow, incoming);
    return Object.keys(incoming).length;
  }

  // ── Import — dispatcher ────────────────────────────────────────────────────

  function applyImport(data, mode) {
    const m = mode === 'merge';
    const r = { profiles: 0, savedFilters: 0, customFeeds: 0, favorites: 0, entityStatuses: 0 };

    if (data.profiles !== undefined) {
      r.profiles = m ? _mergeProfiles(data.profiles) : _replaceProfiles(data.profiles);
    }
    if (data.savedFilters !== undefined) {
      r.savedFilters = m ? _mergeSavedFilters(data.savedFilters) : _replaceSavedFilters(data.savedFilters);
    }
    if (data.customFeeds !== undefined) {
      r.customFeeds = m ? _mergeCustomFeeds(data.customFeeds) : _replaceCustomFeeds(data.customFeeds);
    }
    if (data.feedOverrides !== undefined) {
      m ? _mergeFeedOverrides(data.feedOverrides) : _replaceFeedOverrides(data.feedOverrides);
    }
    if (data.alertSettings !== undefined) {
      m ? _mergeAlertSettings(data.alertSettings) : _replaceAlertSettings(data.alertSettings);
    }
    if (data.favorites !== undefined) {
      r.favorites = m ? _mergeFavorites(data.favorites) : _replaceFavorites(data.favorites);
    }
    if (data.entityStatuses !== undefined) {
      r.entityStatuses = m
        ? _mergeEntityStatuses(data.entityStatuses)
        : _replaceEntityStatuses(data.entityStatuses);
    }
    return r;
  }

  // ── Modal ─────────────────────────────────────────────────────────────────

  let _pendingData = null;

  function open() {
    _injectDOM();
    const modal = document.getElementById('cex-modal');
    if (!modal) return;
    _renderIdle();
    modal.style.display = 'flex';
  }

  function close() {
    const modal = document.getElementById('cex-modal');
    if (modal) modal.style.display = 'none';
    _pendingData = null;
    document.removeEventListener('keydown', _onEsc);
  }

  function _injectDOM() {
    if (document.getElementById('cex-modal')) return;
    const el = document.createElement('div');
    el.id = 'cex-modal';
    el.className = 'cex-overlay';
    el.style.display = 'none';
    document.body.appendChild(el);
  }

  function _onEsc(e) { if (e.key === 'Escape') close(); }

  // ── Rendu idle (état initial) ──────────────────────────────────────────────

  function _renderIdle() {
    const modal = document.getElementById('cex-modal');
    if (!modal) return;
    _pendingData = null;

    const profileData  = _read(KEYS.profiles);
    const profileCount = Object.keys(profileData?.profiles ?? {}).length;
    const filterCount  = (_read(KEYS.savedFilters) ?? []).length;
    const feedCount    = (_read(KEYS.customFeeds)  ?? []).length;
    const favCount     = (_read(KEYS.favorites)    ?? []).length;
    const hasAlerts    = !!_read(KEYS.alertSettings)?.channel;
    const wfData       = _read(KEYS.workflow) ?? {};
    const wfCount      = Object.values(wfData).filter(e => e.status && e.status !== 'new').length;

    modal.innerHTML = `
      <div class="cex-box">
        <div class="cex-header">
          <h3 class="cex-title">📦 Export / Import Configuration</h3>
          <button class="cex-close" id="cex-close" title="Close">✕</button>
        </div>
        <div class="cex-body">

          <!-- ── Export ── -->
          <div class="cex-section">
            <div class="cex-section-title">📤 Export</div>
            <p class="cex-desc">
              Download your local configuration as JSON.<br>
              You can import it in another browser or on another machine.
            </p>
            <div class="cex-chips">
              <span class="cex-chip">${profileCount} profile${profileCount !== 1 ? 's' : ''}</span>
              <span class="cex-chip">${filterCount} preset${filterCount !== 1 ? 's' : ''}</span>
              <span class="cex-chip">${feedCount} custom feed${feedCount !== 1 ? 's' : ''}</span>
              <span class="cex-chip">${favCount} favorite${favCount !== 1 ? 's' : ''}</span>
              ${wfCount > 0 ? `<span class="cex-chip">🔍 ${wfCount} tracked incident${wfCount !== 1 ? 's' : ''}</span>` : ''}
              ${hasAlerts ? '<span class="cex-chip cex-chip-warn">⚠ alert settings</span>' : ''}
            </div>
            ${hasAlerts ? `
            <div class="cex-security-notice">
              🔐 <strong>Security notice:</strong> Your configuration contains
              <strong>credentials</strong> (API keys, webhook URL, token, email addresses).
              Use <em>Export without credentials</em> to share safely.
            </div>` : ''}
            <div class="cex-export-row">
              <button class="btn cex-btn-safe" id="cex-export-safe-btn"
                      title="Recommended — excludes API keys, webhook URL, token and email addresses">
                🛡️ Export without credentials
              </button>
              ${hasAlerts ? `
              <button class="btn cex-btn-full" id="cex-export-full-btn"
                      title="Full export — includes API keys, webhook URL, token and email addresses">
                📤 Full export
              </button>` : ''}
            </div>
          </div>

          <div class="cex-sep"></div>

          <!-- ── Import ── -->
          <div class="cex-section">
            <div class="cex-section-title">📥 Import</div>
            <p class="cex-desc">
              Load a file exported from ThreatLens.<br>
              Then choose between <strong>Merge</strong> (adds without overwriting)
              or <strong>Replace</strong> (overwrites completely).
            </p>
            <label class="cex-file-label" for="cex-file-input">
              📂 Choose a JSON file…
              <input type="file" id="cex-file-input"
                     accept=".json,application/json" style="display:none">
            </label>
            <div id="cex-import-zone"></div>
          </div>

        </div>
      </div>`;

    document.getElementById('cex-close')?.addEventListener('click', close);
    modal.addEventListener('click', e => { if (e.target === modal) close(); });
    document.getElementById('cex-export-safe-btn')?.addEventListener('click', () => exportConfig(false));
    document.getElementById('cex-export-full-btn')?.addEventListener('click', () => exportConfig(true));
    document.getElementById('cex-file-input')?.addEventListener('change', _onFileSelected);
    document.addEventListener('keydown', _onEsc);
  }

  // ── Lecture fichier ────────────────────────────────────────────────────────

  function _onFileSelected(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      let data;
      try { data = JSON.parse(ev.target.result); }
      catch { _showError('Invalid JSON file — unable to read.'); return; }
      const err = _validate(data);
      if (err) { _showError(err); return; }
      _pendingData = data;
      _renderPreview(data);
    };
    reader.readAsText(file);
  }

  // ── Aperçu + choix de mode ────────────────────────────────────────────────

  function _renderPreview(data) {
    const zone = document.getElementById('cex-import-zone');
    if (!zone) return;

    const profileCount = Object.keys(data.profiles?.profiles ?? {}).length;
    const filterCount  = (data.savedFilters ?? []).length;
    const feedCount    = (data.customFeeds  ?? []).length;
    const favCount     = (data.favorites    ?? []).length;
    const wfCount      = Object.values(data.entityStatuses ?? {}).filter(e => e.status && e.status !== 'new').length;
    const exportDate   = data.exportedAt
      ? new Date(data.exportedAt).toLocaleDateString('en-US',
          { day: '2-digit', month: '2-digit', year: 'numeric' })
      : '—';

    const safeLabel = data.safeExport
      ? ' · <span class="cex-badge-safe">🛡️ safe export</span>'
      : '';

    zone.innerHTML = `
      <div class="cex-preview">
        <div class="cex-preview-meta">
          File from <strong>${_esc(exportDate)}</strong> · version ${data.version}${safeLabel}
        </div>
        <div class="cex-chips">
          <span class="cex-chip">${profileCount} profile${profileCount !== 1 ? 's' : ''}</span>
          <span class="cex-chip">${filterCount} preset${filterCount !== 1 ? 's' : ''}</span>
          <span class="cex-chip">${feedCount} custom feed${feedCount !== 1 ? 's' : ''}</span>
          <span class="cex-chip">${favCount} favorite${favCount !== 1 ? 's' : ''}</span>
          ${wfCount > 0 ? `<span class="cex-chip">🔍 ${wfCount} tracked incident${wfCount !== 1 ? 's' : ''}</span>` : ''}
        </div>
        <div class="cex-mode-row">
          <button class="btn cex-mode-btn" id="cex-merge-btn">
            <span class="cex-mode-icon">➕</span>
            <span class="cex-mode-info">
              <span class="cex-mode-label">Merge</span>
              <span class="cex-mode-hint">Adds missing items, preserves existing</span>
            </span>
          </button>
          <button class="btn cex-mode-btn cex-mode-btn-danger" id="cex-replace-btn">
            <span class="cex-mode-icon">🔄</span>
            <span class="cex-mode-info">
              <span class="cex-mode-label">Replace</span>
              <span class="cex-mode-hint">Overwrites each section with the imported file</span>
            </span>
          </button>
        </div>
      </div>`;

    document.getElementById('cex-merge-btn')?.addEventListener('click', () => _doImport('merge'));
    document.getElementById('cex-replace-btn')?.addEventListener('click', () => {
      if (!confirm(
        '⚠ "Replace" will overwrite your existing configuration (profiles, presets, feeds, favorites).\n\n' +
        'Make sure you have exported your current state before continuing.\n\nContinue?'
      )) return;
      _doImport('replace');
    });
  }

  // ── Exécution de l'import ─────────────────────────────────────────────────

  function _doImport(mode) {
    if (!_pendingData) return;
    try {
      const result = applyImport(_pendingData, mode);
      _renderSuccess(mode, result);
      setTimeout(() => { close(); window.location.reload(); }, 2000);
    } catch (err) {
      console.error('[ConfigExport] Import error:', err);
      _showError("Unexpected error during import: " + (err.message ?? String(err)));
    }
  }

  function _renderSuccess(mode, r) {
    const zone = document.getElementById('cex-import-zone');
    if (!zone) return;
    const modeLabel = mode === 'merge' ? 'Merge' : 'Replace';
    const details = [
      r.profiles       > 0 ? `${r.profiles} profile(s)` : null,
      r.savedFilters   > 0 ? `${r.savedFilters} preset(s)` : null,
      r.customFeeds    > 0 ? `${r.customFeeds} custom feed(s)` : null,
      r.favorites      > 0 ? `${r.favorites} favorite(s)` : null,
      r.entityStatuses > 0 ? `${r.entityStatuses} workflow entry(ies)` : null
    ].filter(Boolean).join(' · ') || 'no new items';

    zone.innerHTML = `
      <div class="cex-success">
        <div class="cex-success-icon">✅</div>
        <div>
          <strong>${_esc(modeLabel)} completed.</strong><br>
          <small>${_esc(details)}</small><br>
          <small class="cex-reload-msg">Reloading…</small>
        </div>
      </div>`;
  }

  function _showError(msg) {
    const zone = document.getElementById('cex-import-zone');
    if (zone) zone.innerHTML = `<div class="cex-error">⚠ ${_esc(msg)}</div>`;
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  function init() {
    document.getElementById('btn-config-export')
      ?.addEventListener('click', open);
  }

  return { init, open, close, exportConfig, applyImport };

})();

// Auto-init
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => ConfigExport.init());
} else {
  ConfigExport.init();
}
