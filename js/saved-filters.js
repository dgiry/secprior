// saved-filters.js — Vues / filtres sauvegardés (V1)
//
// Stocke dans localStorage (clé "cv_saved_filters") une liste de presets.
// Chaque preset capture : vue active + filtres globaux + filtres du panneau.
//
// API publique : init, open, close, addPreset, removePreset, applyPreset

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

  // ── Capture de l'état courant ─────────────────────────────────────────────

  function captureState() {
    const view       = (typeof App !== "undefined") ? App.getActivePanel() : "main";
    const appFilters = (typeof App !== "undefined") ? App.getFilters()     : {};
    const filters    = { ...appFilters };

    if (view === "cves"      && typeof CVEPanel      !== "undefined") Object.assign(filters, CVEPanel.getFilters());
    if (view === "incidents" && typeof IncidentPanel !== "undefined") Object.assign(filters, IncidentPanel.getFilters());
    if (view === "vendors"   && typeof VendorPanel   !== "undefined") Object.assign(filters, VendorPanel.getFilters());

    return { view, filters };
  }

  // ── CRUD presets ──────────────────────────────────────────────────────────

  function addPreset(name) {
    const list = _load();
    if (list.length >= MAX_PRESETS) {
      _toast(`Maximum ${MAX_PRESETS} vues atteint — supprimez-en une d'abord.`, "warning");
      return null;
    }
    const { view, filters } = captureState();
    const id     = `preset_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    const preset = {
      id,
      name:      (name || "").trim() || "Vue sans nom",
      view,
      filters,
      createdAt: new Date().toISOString()
    };
    list.push(preset);
    _save(list);
    return preset;
  }

  function removePreset(id) {
    _save(_load().filter(p => p.id !== id));
    _renderList();
  }

  // ── Application d'un preset ───────────────────────────────────────────────

  function applyPreset(preset) {
    const { view, filters } = preset;

    // 1. Filtres globaux
    if (typeof App !== "undefined") {
      App.setFilters({
        query:       filters.query       ?? "",
        criticality: filters.criticality ?? "all",
        source:      filters.source      ?? "all",
        date:        filters.date        ?? "all",
        showFavOnly: filters.showFavOnly ?? false
      });
    }

    // 2. Ouvrir le bon panneau + ses filtres
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
    }

    close();
    _toast(`Vue "${preset.name}" appliquée.`, "success");
  }

  // ── UI helpers ────────────────────────────────────────────────────────────

  const _VIEW_LABELS = {
    main:      "📰 Dashboard",
    cves:      "🔍 CVEs",
    incidents: "🎯 Incidents",
    vendors:   "🏢 Vendors",
    stats:     "📊 Stats",
    briefing:  "📰 Briefing",
    health:    "🩺 Santé"
  };

  function _esc(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function _formatFilters(f) {
    const parts = [];
    if (f.query)                                      parts.push(`"${_esc(f.query)}"`);
    if (f.criticality && f.criticality !== "all")     parts.push(f.criticality.toUpperCase());
    if (f.date        && f.date        !== "all")     parts.push(f.date);
    if (f.source      && f.source      !== "all")     parts.push(_esc(f.source));
    if (f.filterBy    && f.filterBy    !== "all")     parts.push(f.filterBy);
    if (f.searchQuery)                                parts.push(`"${_esc(f.searchQuery)}"`);
    if (f.sortBy      && f.sortBy      !== "default") parts.push(`tri:${f.sortBy}`);
    if (f.showFavOnly)                                parts.push("favoris");
    return parts.length ? parts.join(" · ") : "Aucun filtre actif";
  }

  function _renderList() {
    const container = document.getElementById("sf-preset-list");
    if (!container) return;
    const list = _load();
    if (list.length === 0) {
      container.innerHTML = '<p class="sf-empty">Aucune vue sauvegardée pour l\'instant.</p>';
      return;
    }
    container.innerHTML = list.map(p => `
      <div class="sf-preset-row">
        <span class="sf-view-badge">${_VIEW_LABELS[p.view] || p.view}</span>
        <div class="sf-preset-info">
          <span class="sf-preset-name">${_esc(p.name)}</span>
          <span class="sf-preset-meta">${_formatFilters(p.filters)}</span>
        </div>
        <div class="sf-preset-actions">
          <button class="btn btn-primary sf-apply-btn" data-id="${_esc(p.id)}">↩ Appliquer</button>
          <button class="btn sf-delete-btn" data-id="${_esc(p.id)}" title="Supprimer cette vue">✕</button>
        </div>
      </div>
    `).join("");
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
      _toast(`Vue "${preset.name}" sauvegardée.`, "success");
    }
  }

  // ── Ouvrir / fermer le modal ──────────────────────────────────────────────

  function open() {
    _renderList();
    const modal = document.getElementById("modal-saved-filters");
    if (modal) modal.style.display = "flex";
    setTimeout(() => document.getElementById("sf-name-input")?.focus(), 50);
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

    // Délégation sur la liste (Apply + Delete)
    document.getElementById("sf-preset-list")
      ?.addEventListener("click", e => {
        const applyBtn  = e.target.closest(".sf-apply-btn");
        const deleteBtn = e.target.closest(".sf-delete-btn");
        if (applyBtn) {
          const preset = _load().find(p => p.id === applyBtn.dataset.id);
          if (preset) applyPreset(preset);
        }
        if (deleteBtn) {
          removePreset(deleteBtn.dataset.id);
        }
      });
  }

  return { init, open, close, addPreset, removePreset, applyPreset };
})();
