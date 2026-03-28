// entity-status.js — Workflow analyste (V2)
//
// Stocke dans localStorage (clé "cv_entity_statuses") un objet plat
// indexé par "entityType:entityId".
//
// Statuts : new · acknowledged · investigating · mitigated · ignored
// État par défaut si absent : "new"
// Champs : status, note, owner, updatedAt, updatedBy
//
// API publique :
//   getStatus(type, id)                        → entry | null
//   getEffectiveStatus(type, id)               → string  (défaut : "new")
//   setStatus(type, id, status, note?)         → void
//   updateNote(type, id, note)                 → void
//   updateOwner(type, id, owner)               → void
//   filterByStatus(items, type, filter, idFn)  → items[]
//   badgeHTML(type, id)                        → string HTML  (vide si "new")
//   statusBlockHTML(type, id)                  → string HTML  (select + note + owner)
//
// Extensibilité Jira/ServiceNow :
//   Chaque entrée conserve { entityType, entityId, status, note, owner, updatedAt, updatedBy }
//   Un connecteur externe peut lire/écrire ces mêmes champs via une API REST,
//   en ajoutant { externalId, externalUrl, syncedAt } sans casser le contrat local.

const EntityStatus = (() => {

  const STORAGE_KEY = "cv_entity_statuses";

  const VALID_STATUSES = [
    "new", "acknowledged", "investigating", "mitigated", "ignored"
  ];

  const STATUS_META = {
    new:          { label: "New",             emoji: "·",   color: "#8b949e", bg: "#21262d" },
    acknowledged: { label: "Acknowledged", emoji: "📥",  color: "#f0883e", bg: "#2d1a00" },
    investigating:{ label: "Investigating",  emoji: "🔍",  color: "#79c0ff", bg: "#0d1b2e" },
    mitigated:    { label: "Mitigated",      emoji: "✅",  color: "#3fb950", bg: "#0d2818" },
    ignored:      { label: "Ignored",        emoji: "🚫",  color: "#484f58", bg: "#161b22" }
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
    const s = getStatus(entityType, entityId)?.status;
    // Guard : ignore statuts d'une version antérieure (non dans VALID_STATUSES)
    return (s && VALID_STATUSES.includes(s)) ? s : "new";
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
      note:      note !== undefined ? String(note) : (prev.note  || ""),
      owner:     prev.owner || "",
      updatedBy: "local"
      // Extensible : externalId, externalUrl, syncedAt (connecteur Jira/ServiceNow)
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
      map[key] = {
        entityType, entityId,
        status:    "new",
        updatedAt: new Date().toISOString(),
        note:      String(note || ""),
        owner:     "",
        updatedBy: "local"
      };
    }
    _save(map);
  }

  function updateOwner(entityType, entityId, owner) {
    const map  = _load();
    const key  = _key(entityType, entityId);
    const prev = map[key];
    if (prev) {
      prev.owner     = String(owner || "");
      prev.updatedAt = new Date().toISOString();
    } else {
      map[key] = {
        entityType, entityId,
        status:    "new",
        updatedAt: new Date().toISOString(),
        note:      "",
        owner:     String(owner || ""),
        updatedBy: "local"
      };
    }
    _save(map);
  }

  // ── Maintenance du store ──────────────────────────────────────────────────

  /**
   * pruneStale({ maxAgeDays, statuses }) → number
   *
   * Supprime les entrées obsolètes pour limiter la croissance.
   * Par défaut : "mitigated" et "ignored" de plus de 90 jours.
   */
  function pruneStale({ maxAgeDays = 90, statuses = ["mitigated", "ignored"] } = {}) {
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
   *   idGetter     : item => entityId
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
   * Badge inline pour les listes.
   * Retourne "" pour "new" (pas de badge = pas de bruit visuel).
   */
  function badgeHTML(entityType, entityId) {
    const status = getEffectiveStatus(entityType, entityId);
    if (status === "new") return "";
    const m = STATUS_META[status] || STATUS_META.new;
    return `<span class="es-badge es-${status}" style="color:${m.color};background:${m.bg}">${m.emoji} ${m.label}</span>`;
  }

  /**
   * Bloc complet : sélecteur de statut + note + owner + updatedAt.
   * À insérer dans la section détail d'une ligne ou d'un modal.
   */
  function statusBlockHTML(entityType, entityId) {
    const entry   = getStatus(entityType, entityId);
    const status  = (entry?.status && VALID_STATUSES.includes(entry.status)) ? entry.status : "new";
    const note    = entry?.note   || "";
    const owner   = entry?.owner  || "";
    const safeEid = _domSafeId(entityType, entityId);

    const updatedLine = entry?.updatedAt
      ? `<span class="es-updated">Updated on ${new Date(entry.updatedAt).toLocaleString("en-US", {
            day:"2-digit", month:"2-digit", year:"2-digit",
            hour:"2-digit", minute:"2-digit"})}</span>`
      : "";

    const opts = VALID_STATUSES.map(s => {
      const m = STATUS_META[s];
      return `<option value="${s}"${s === status ? " selected" : ""}>${m.emoji} ${m.label}</option>`;
    }).join("");

    return `
      <div class="es-block" data-etype="${_escAttr(entityType)}" data-eid="${_escAttr(entityId)}" data-safe-eid="${safeEid}">
        <div class="es-block-header">
          <span class="es-label">Analyst status</span>
          ${updatedLine}
        </div>
        <div class="es-row">
          <select class="es-select" title="Change status">${opts}</select>
          <input type="text" class="es-note-input"
                 placeholder="Short note (optional)…"
                 value="${_escAttr(note)}"
                 maxlength="200"
                 title="Analyst note — saved on field exit (Enter or Tab)">
        </div>
        <div class="es-row es-owner-row">
          <input type="text" class="es-owner-input"
                 placeholder="Owner (optional)…"
                 value="${_escAttr(owner)}"
                 maxlength="80"
                 title="Responsible analyst or team — saved on field exit">
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
    updateOwner,
    pruneStale,
    getStats,
    filterByStatus,
    badgeHTML,
    statusBlockHTML
  };
})();
