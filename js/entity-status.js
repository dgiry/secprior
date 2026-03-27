// entity-status.js — Statuts analyste (V1)
//
// Stocke dans localStorage (clé "cv_entity_statuses") un objet plat
// indexé par "entityType:entityId".
//
// Statuts : new · todo · in_progress · monitoring · escalated · closed · false_positive
// État par défaut si absent : "new"
//
// API publique :
//   getStatus(type, id)                        → entry | null
//   getEffectiveStatus(type, id)               → string  (défaut : "new")
//   setStatus(type, id, status, note?)         → void
//   updateNote(type, id, note)                 → void
//   filterByStatus(items, type, filter, idFn)  → items[]
//   badgeHTML(type, id)                        → string HTML  (vide si "new")
//   statusBlockHTML(type, id)                  → string HTML  (select + note)

const EntityStatus = (() => {

  const STORAGE_KEY = "cv_entity_statuses";

  const VALID_STATUSES = [
    "new", "todo", "in_progress", "monitoring",
    "escalated", "closed", "false_positive"
  ];

  const STATUS_META = {
    new:            { label: "Nouveau",    emoji: "·",   color: "#8b949e", bg: "#21262d" },
    todo:           { label: "À traiter",  emoji: "📋",  color: "#f0883e", bg: "#2d1a00" },
    in_progress:    { label: "En cours",   emoji: "🔄",  color: "#79c0ff", bg: "#0d1b2e" },
    monitoring:     { label: "Surveillé",  emoji: "👁",  color: "#3fb950", bg: "#0d2818" },
    escalated:      { label: "Escaladé",   emoji: "⬆️",  color: "#f85149", bg: "#2d1515" },
    closed:         { label: "Clos",       emoji: "✅",  color: "#484f58", bg: "#161b22" },
    false_positive: { label: "Faux pos.",  emoji: "🚫",  color: "#8b949e", bg: "#1c1c1c" }
  };

  // ── Helpers internes ──────────────────────────────────────────────────────

  function _key(entityType, entityId) {
    return entityType + ":" + entityId;
  }

  // Identifiant DOM-safe — doit correspondre aux calculs dans chaque panneau
  function _domSafeId(entityType, entityId) {
    return entityType === "cve"
      ? String(entityId).replace(/[^A-Z0-9\-]/g, "")
      : String(entityId).replace(/[^a-z0-9\-_]/g, "-");
  }

  function _escAttr(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // ── Stockage ──────────────────────────────────────────────────────────────

  function _load() {
    try {
      const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
      return (parsed && typeof parsed === "object" && !Array.isArray(parsed)) ? parsed : {};
    } catch {
      return {};
    }
  }

  function _save(map) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
    } catch (e) {
      console.warn("[EntityStatus] localStorage write failed:", e);
    }
  }

  // ── API lecture ───────────────────────────────────────────────────────────

  function getStatus(entityType, entityId) {
    if (!entityType || !entityId) return null;
    return _load()[_key(entityType, entityId)] || null;
  }

  function getEffectiveStatus(entityType, entityId) {
    return getStatus(entityType, entityId)?.status || "new";
  }

  // ── API écriture ──────────────────────────────────────────────────────────

  function setStatus(entityType, entityId, status, note) {
    if (!VALID_STATUSES.includes(status)) {
      console.warn("[EntityStatus] Statut invalide:", status);
      return;
    }
    const map  = _load();
    const key  = _key(entityType, entityId);
    const prev = map[key] || {};
    map[key] = {
      entityType,
      entityId,
      status,
      updatedAt: new Date().toISOString(),
      note:      note !== undefined ? String(note) : (prev.note || ""),
      updatedBy: "local"
      // Extensible : assignedTo, history, priority…
    };
    _save(map);
  }

  function updateNote(entityType, entityId, note) {
    const map  = _load();
    const key  = _key(entityType, entityId);
    const prev = map[key];
    if (prev) {
      prev.note      = String(note || "");
      prev.updatedAt = new Date().toISOString();
    } else {
      // Crée une entrée minimale — statut "new" effectif
      map[key] = {
        entityType, entityId,
        status:    "new",
        updatedAt: new Date().toISOString(),
        note:      String(note || ""),
        updatedBy: "local"
      };
    }
    _save(map);
  }

  // ── Maintenance du store ──────────────────────────────────────────────────

  /**
   * pruneStale({ maxAgeDays, statuses }) → number
   *
   * Supprime du localStorage les entrées obsolètes pour limiter la croissance.
   * Par défaut : statuts "closed" et "false_positive" vieux de plus de 90 jours.
   * Retourne le nombre d'entrées supprimées.
   */
  function pruneStale({ maxAgeDays = 90, statuses = ["closed", "false_positive"] } = {}) {
    const map    = _load();
    const cutoff = Date.now() - maxAgeDays * 24 * 60 * 60 * 1000;
    let pruned   = 0;
    for (const key of Object.keys(map)) {
      const entry = map[key];
      if (!entry) continue;
      const age = new Date(entry.updatedAt || 0).getTime();
      if (statuses.includes(entry.status) && age < cutoff) {
        delete map[key];
        pruned++;
      }
    }
    if (pruned > 0) {
      _save(map);
      console.log(`[EntityStatus] ${pruned} entrée(s) purgée(s) (>${maxAgeDays}j, statuts : ${statuses.join(", ")})`);
    }
    return pruned;
  }

  /**
   * getStats() → { total, byStatus }
   *
   * Statistiques du store : nombre d'entrées total et par statut.
   * Utilisé pour la supervision et le debug.
   */
  function getStats() {
    const map  = _load();
    const all  = Object.values(map);
    const bySt = {};
    VALID_STATUSES.forEach(s => { bySt[s] = 0; });
    all.forEach(e => { if (bySt[e.status] !== undefined) bySt[e.status]++; });
    return { total: all.length, byStatus: bySt };
  }

  // ── Filtrage ──────────────────────────────────────────────────────────────

  /**
   * filterByStatus(items, entityType, statusFilter, idGetter)
   *   statusFilter : "all" | l'un des VALID_STATUSES
   *   idGetter     : item => entityId  (ex: i => i.incidentId, e => e.cve)
   */
  function filterByStatus(items, entityType, statusFilter, idGetter) {
    if (!statusFilter || statusFilter === "all") return items;
    return items.filter(item => {
      const eff = getEffectiveStatus(entityType, idGetter(item));
      return eff === statusFilter;
    });
  }

  // ── Helpers HTML ──────────────────────────────────────────────────────────

  /**
   * Badge inline pour la colonne d'une liste.
   * Retourne "" pour "new" (pas de badge = pas de bruit visuel).
   */
  function badgeHTML(entityType, entityId) {
    const status = getEffectiveStatus(entityType, entityId);
    if (status === "new") return "";
    const m = STATUS_META[status] || STATUS_META.new;
    return `<span class="es-badge es-${status}" style="color:${m.color};background:${m.bg}">${m.emoji} ${m.label}</span>`;
  }

  /**
   * Bloc complet : sélecteur de statut + champ note.
   * À insérer dans la section détail d'une ligne de tableau.
   *
   * Attributs data-etype, data-eid (raw), data-safe-eid (DOM-safe) permettent
   * une mise à jour ciblée du badge sans re-render de toute la liste.
   */
  function statusBlockHTML(entityType, entityId) {
    const entry   = getStatus(entityType, entityId);
    const status  = entry?.status || "new";
    const note    = entry?.note   || "";
    const safeEid = _domSafeId(entityType, entityId);

    const opts = VALID_STATUSES.map(s => {
      const m = STATUS_META[s];
      return `<option value="${s}"${s === status ? " selected" : ""}>${m.emoji} ${m.label}</option>`;
    }).join("");

    return `
      <div class="es-block" data-etype="${_escAttr(entityType)}" data-eid="${_escAttr(entityId)}" data-safe-eid="${safeEid}">
        <span class="es-label">Statut analyste</span>
        <div class="es-row">
          <select class="es-select" title="Changer le statut">${opts}</select>
          <input type="text" class="es-note-input"
                 placeholder="Note courte (optionnelle)…"
                 value="${_escAttr(note)}"
                 maxlength="200"
                 title="Note analyste — sauvegardée à la sortie du champ (Enter ou Tab)">
        </div>
      </div>`;
  }

  return {
    VALID_STATUSES,
    STATUS_META,
    getStatus,
    getEffectiveStatus,
    setStatus,
    updateNote,
    pruneStale,
    getStats,
    filterByStatus,
    badgeHTML,
    statusBlockHTML
  };
})();
