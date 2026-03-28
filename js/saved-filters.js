// saved-filters.js — Vues / filtres sauvegardés (V1.2 — Sprint 17 : Profile-scoped presets)
//
// V1.1 — 3 améliorations ciblées :
//   1. _closeAllPanelsExcept(view) — ferme les autres panneaux avant d'ouvrir la cible
//   2. Support explicite de stats, briefing, health dans capture + application
//   3. updatePreset(id) — écrase un preset existant avec l'état courant
//
// V1.2 — Profile-scoped presets :
//   • addPreset() attache le profil actif (profileId, profileName, profileBadge) au preset
//   • Les anciens presets sans profileId restent « globaux » et fonctionnent comme avant
//   • _renderList() regroupe les presets : « Ce profil », « Globales », « Autres profils »
//   • applyPreset() affiche un toast informatif si le preset vient d'un autre profil
//   • open() injecte un hint affichant le profil actif dans la ligne de sauvegarde
//
// API publique : init, open, close, addPreset, removePreset, applyPreset, updatePreset

const SavedFilters = (() => {

  const STORAGE_KEY = "cv_saved_filters";
  const MAX_PRESETS = 20;

  // ── Stockage ──────────────────────────────────────────────────────────────

  function _load() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); }
    catch { return []; }
  }

  function _save(list) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  }

  // ── Fermer tous les panneaux sauf la cible ────────────────────────────────
  //
  // Appelle toggle() uniquement si le panneau est actuellement ouvert,
  // pour laisser le pattern toggle existant gérer la classe active du bouton.

  function _closeAllPanelsExcept(view) {
    const PANELS = [
      { id: "stats-panel",    view: "stats",     mod: () => (typeof StatsPanel    !== "undefined" ? StatsPanel    : null) },
      { id: "briefing-panel", view: "briefing",  mod: () => (typeof BriefingPanel !== "undefined" ? BriefingPanel : null) },
      { id: "health-panel",   view: "health",    mod: () => (typeof HealthPanel   !== "undefined" ? HealthPanel   : null) },
      { id: "vendor-panel",     view: "vendors",    mod: () => (typeof VendorPanel     !== "undefined" ? VendorPanel     : null) },
      { id: "cve-panel",        view: "cves",       mod: () => (typeof CVEPanel        !== "undefined" ? CVEPanel        : null) },
      { id: "incident-panel",   view: "incidents",  mod: () => (typeof IncidentPanel   !== "undefined" ? IncidentPanel   : null) },
      { id: "visibility-panel", view: "visibility", mod: () => (typeof VisibilityPanel !== "undefined" ? VisibilityPanel : null) },
    ];
    for (const { id, view: pView, mod } of PANELS) {
      if (pView === view) continue;
      const el = document.getElementById(id);
      if (el && el.style.display !== "none") mod()?.toggle();
    }
  }

  // ── Capture de l'état courant ─────────────────────────────────────────────

  function captureState() {
    const view       = (typeof App !== "undefined") ? App.getActivePanel() : "main";
    const appFilters = (typeof App !== "undefined") ? App.getFilters()     : {};
    const filters    = { ...appFilters };

    if (view === "cves"      && typeof CVEPanel      !== "undefined") Object.assign(filters, CVEPanel.getFilters());
    if (view === "incidents" && typeof IncidentPanel !== "undefined") Object.assign(filters, IncidentPanel.getFilters());
    if (view === "vendors"   && typeof VendorPanel   !== "undefined") Object.assign(filters, VendorPanel.getFilters());
    // stats, briefing, health — pas de filtres internes à capturer pour l'instant

    return { view, filters };
  }

  // ── CRUD presets ──────────────────────────────────────────────────────────

  function addPreset(name) {
    const list = _load();
    if (list.length >= MAX_PRESETS) {
      _toast(`Maximum ${MAX_PRESETS} views reached — delete one first.`, "warning");
      return null;
    }
    const { view, filters } = captureState();
    const id     = `preset_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;

    // Sprint 17 — attacher le profil actif si ProfileManager est disponible
    let profileId = null, profileName = null, profileBadge = null;
    if (typeof ProfileManager !== "undefined") {
      const p = ProfileManager.getActiveProfile();
      if (p) { profileId = p.id; profileName = p.name; profileBadge = p.badge || null; }
    }

    const preset = {
      id,
      name:      (name || "").trim() || "Unnamed view",
      view,
      filters,
      createdAt: new Date().toISOString(),
      profileId,
      profileName,
      profileBadge
    };
    list.push(preset);
    _save(list);
    return preset;
  }

  function removePreset(id) {
    _save(_load().filter(p => p.id !== id));
    _renderList();
  }

  // ── Mise à jour d'un preset existant (V1.1) ───────────────────────────────

  function updatePreset(id) {
    const list = _load();
    const idx  = list.findIndex(p => p.id === id);
    if (idx === -1) return;
    const { view, filters } = captureState();
    list[idx] = { ...list[idx], view, filters, updatedAt: new Date().toISOString() };
    _save(list);
    _renderList();
    _toast(`View "${list[idx].name}" updated.`, "success");
  }

  // ── Application d'un preset ───────────────────────────────────────────────

  function applyPreset(preset) {
    const { view, filters } = preset;

    // Sprint 17 — toast informatif si le preset appartient à un autre profil
    if (preset.profileId && typeof ProfileManager !== "undefined") {
      const activeId = ProfileManager.getActiveId();
      if (preset.profileId !== activeId) {
        const badge = preset.profileBadge ? preset.profileBadge + " " : "";
        _toast(`ℹ️ This view was created for profile ${badge}«${preset.profileName || preset.profileId}»`, "info");
      }
    }

    // 1. Fermer tous les panneaux sauf la cible (V1.1)
    _closeAllPanelsExcept(view);

    // 2. Filtres globaux (dashboard principal)
    if (typeof App !== "undefined") {
      App.setFilters({
        query:         filters.query         ?? "",
        criticality:   filters.criticality   ?? "all",
        source:        filters.source        ?? "all",
        date:          filters.date          ?? "all",
        priorityLevel: filters.priorityLevel ?? "all",
        sortBy:        filters.sortBy        ?? "default",
        showFavOnly:   filters.showFavOnly   ?? false
      });
    }

    // 3. Ouvrir la bonne vue + appliquer ses filtres
    if (view === "cves" && typeof CVEPanel !== "undefined") {
      const panel = document.getElementById("cve-panel");
      if (panel && panel.style.display === "none") CVEPanel.toggle();
      CVEPanel.setFilters({
        filterBy:    filters.filterBy    ?? "all",
        searchQuery: filters.searchQuery ?? ""
      });

    } else if (view === "incidents" && typeof IncidentPanel !== "undefined") {
      const panel = document.getElementById("incident-panel");
      if (panel && panel.style.display === "none") IncidentPanel.toggle();
      IncidentPanel.setFilters({
        filterBy:    filters.filterBy    ?? "all",
        sortBy:      filters.sortBy      ?? "default",
        searchQuery: filters.searchQuery ?? ""
      });

    } else if (view === "vendors" && typeof VendorPanel !== "undefined") {
      const panel = document.getElementById("vendor-panel");
      if (panel && panel.style.display === "none") VendorPanel.toggle();
      VendorPanel.setFilters({
        filterBy:    filters.filterBy    ?? "all",
        sortBy:      filters.sortBy      ?? "default",
        searchQuery: filters.searchQuery ?? ""
      });

    // V1.1 — vues stats, briefing, health ────────────────────────────────────
    } else if (view === "stats" && typeof StatsPanel !== "undefined") {
      const panel = document.getElementById("stats-panel");
      if (panel && panel.style.display === "none") StatsPanel.toggle();

    } else if (view === "briefing" && typeof BriefingPanel !== "undefined") {
      const panel = document.getElementById("briefing-panel");
      if (panel && panel.style.display === "none") BriefingPanel.toggle();

    } else if (view === "health" && typeof HealthPanel !== "undefined") {
      const panel = document.getElementById("health-panel");
      if (panel && panel.style.display === "none") HealthPanel.toggle();

    } else if (view === "visibility" && typeof VisibilityPanel !== "undefined") {
      const panel = document.getElementById("visibility-panel");
      if (panel && panel.style.display === "none") VisibilityPanel.toggle();
    }
    // view === "main" → aucun panneau à ouvrir, filtres déjà appliqués

    // Sprint 21 — effacer la vue persona active (un preset sauvegardé prend le dessus)
    if (typeof PersonaPresets !== 'undefined') PersonaPresets.clearActive();

    close();
    _toast(`View "${preset.name}" applied.`, "success");
  }

  // ── UI helpers ────────────────────────────────────────────────────────────

  const _VIEW_LABELS = {
    main:       "📰 Dashboard",
    cves:       "🔍 CVEs",
    incidents:  "🔗 Incidents",
    vendors:    "🏢 Vendors",
    visibility: "👁 Visibility",
    stats:      "📊 Stats",
    briefing:   "📰 Briefing",
    health:     "🩺 Health"
  };

  function _esc(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  const _PRIO_LABELS = {
    critical_now: "CRITICAL",
    investigate:  "INVESTIG.",
    watch:        "MONITR.",
    low:          "LOW"
  };

  function _formatFilters(f) {
    const parts = [];
    if (f.query)                                           parts.push(`"${_esc(f.query)}"`);
    if (f.criticality   && f.criticality   !== "all")     parts.push(f.criticality.toUpperCase());
    if (f.priorityLevel && f.priorityLevel !== "all")     parts.push(`prio:${_PRIO_LABELS[f.priorityLevel] || f.priorityLevel}`);
    if (f.date          && f.date          !== "all")     parts.push(f.date);
    if (f.source        && f.source        !== "all")     parts.push(_esc(f.source));
    if (f.filterBy      && f.filterBy      !== "all")     parts.push(f.filterBy);
    if (f.searchQuery)                                     parts.push(`"${_esc(f.searchQuery)}"`);
    if (f.sortBy        && f.sortBy        !== "default") parts.push(`sort:${f.sortBy}`);
    if (f.showFavOnly)                                     parts.push("favorites");
    return parts.length ? parts.join(" · ") : "No active filters";
  }

  function _presetRowHTML(p, dimmed) {
    const scopeBadge = p.profileId
      ? `<span class="sf-scope sf-scope-profile" title="Profile: ${_esc(p.profileName || p.profileId)}">${p.profileBadge || "◉"}</span>`
      : `<span class="sf-scope sf-scope-global"  title="Global view (all profiles)">🌐</span>`;
    return `
      <div class="sf-preset-row${dimmed ? " sf-row-other" : ""}">
        ${scopeBadge}
        <span class="sf-view-badge">${_VIEW_LABELS[p.view] || p.view}</span>
        <div class="sf-preset-info">
          <span class="sf-preset-name">${_esc(p.name)}</span>
          <span class="sf-preset-meta">${_formatFilters(p.filters)}</span>
        </div>
        <div class="sf-preset-actions">
          <button class="btn btn-primary sf-apply-btn"  data-id="${_esc(p.id)}" title="Apply this view">↩ Apply</button>
          <button class="btn sf-update-btn" data-id="${_esc(p.id)}" title="Overwrite with current view">⟳</button>
          <button class="btn sf-delete-btn" data-id="${_esc(p.id)}" title="Delete this view">✕</button>
        </div>
      </div>`;
  }

  function _renderList() {
    const container = document.getElementById("sf-preset-list");
    if (!container) return;
    const list = _load();
    if (list.length === 0) {
      container.innerHTML = '<p class="sf-empty">No saved views yet.</p>';
      return;
    }

    // Sprint 17 — grouper par scope
    let activeId = null;
    if (typeof ProfileManager !== "undefined") activeId = ProfileManager.getActiveId();

    const mine   = list.filter(p => p.profileId && p.profileId === activeId);
    const global = list.filter(p => !p.profileId);
    const other  = list.filter(p => p.profileId && p.profileId !== activeId);

    let html = "";

    if (mine.length) {
      html += `<div class="sf-group-label">This profile</div>`;
      html += mine.map(p => _presetRowHTML(p, false)).join("");
    }
    if (global.length) {
      html += `<div class="sf-group-label">Global</div>`;
      html += global.map(p => _presetRowHTML(p, false)).join("");
    }
    if (other.length) {
      html += `<div class="sf-group-label">Other profiles</div>`;
      html += other.map(p => _presetRowHTML(p, true)).join("");
    }

    container.innerHTML = html;
  }

  function _toast(msg, type) {
    if (typeof UI !== "undefined") UI.showToast(msg, type);
  }

  // ── Sauvegarder depuis l'UI ───────────────────────────────────────────────

  function _onSave() {
    const nameInput = document.getElementById("sf-name-input");
    const name = (nameInput?.value || "").trim();
    if (!name) {
      nameInput?.focus();
      nameInput?.classList.add("sf-input-error");
      setTimeout(() => nameInput?.classList.remove("sf-input-error"), 800);
      return;
    }
    const preset = addPreset(name);
    if (preset) {
      if (nameInput) nameInput.value = "";
      _renderList();
      _toast(`View "${preset.name}" saved.`, "success");
    }
  }

  // ── Ouvrir / fermer le modal ──────────────────────────────────────────────

  function open() {
    _renderList();
    const modal = document.getElementById("modal-saved-filters");
    if (modal) modal.style.display = "flex";

    // Sprint 17 — injecter/mettre à jour le hint de profil actif
    _updateProfileHint();

    setTimeout(() => document.getElementById("sf-name-input")?.focus(), 50);
  }

  function _updateProfileHint() {
    const saveRow = document.querySelector(".sf-save-row");
    if (!saveRow) return;

    // Supprimer l'ancien hint s'il existe
    saveRow.querySelector(".sf-profile-hint")?.remove();

    if (typeof ProfileManager === "undefined") return;
    const p = ProfileManager.getActiveProfile();
    if (!p) return;

    const hint = document.createElement("div");
    hint.className = "sf-profile-hint";
    hint.innerHTML = `<span class="sf-scope sf-scope-profile">${p.badge || "◉"}</span>`
                   + `<span class="sf-profile-hint-text">Will be linked to profile <strong>${_esc(p.name)}</strong></span>`;
    saveRow.appendChild(hint);
  }

  function close() {
    const modal = document.getElementById("modal-saved-filters");
    if (modal) modal.style.display = "none";
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  function init() {
    document.getElementById("btn-saved-filters")
      ?.addEventListener("click", open);

    document.getElementById("sf-save-btn")
      ?.addEventListener("click", _onSave);

    document.getElementById("sf-name-input")
      ?.addEventListener("keydown", e => { if (e.key === "Enter") _onSave(); });

    // Délégation sur la liste (Apply + Update + Delete)
    document.getElementById("sf-preset-list")
      ?.addEventListener("click", e => {
        const applyBtn  = e.target.closest(".sf-apply-btn");
        const updateBtn = e.target.closest(".sf-update-btn");
        const deleteBtn = e.target.closest(".sf-delete-btn");

        if (applyBtn) {
          const preset = _load().find(p => p.id === applyBtn.dataset.id);
          if (preset) applyPreset(preset);
        }
        if (updateBtn) {
          updatePreset(updateBtn.dataset.id);
        }
        if (deleteBtn) {
          removePreset(deleteBtn.dataset.id);
        }
      });
  }

  return { init, open, close, addPreset, removePreset, applyPreset, updatePreset };
})();
