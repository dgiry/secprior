// ai-brief.js — AI-assisted brief generation (Sprint IA v3)
//
// Génère 6 sorties IA depuis /api/ai-brief (Claude Haiku via Anthropic) :
//   🔬 Analyst Brief       — brief technique pour analyste SOC
//   📊 Executive Brief     — résumé risque métier pour RSSI / manager
//   ▶  Next Step           — action prudente recommandée
//   🎫 AI Ticket Draft     — ticket Jira/ServiceNow formaté
//   📢 AI Escalation Note  — note d'escalade 3-4 lignes
//   📤 AI Share Rewrite    — message Slack/Teams naturel
//
// Design :
//   • Seuls les champs signaux vérifiés sont transmis à l'API (jamais de données brutes libres)
//   • La description est débarrassée des tags HTML et tronquée à 800 caractères avant envoi
//   • Les sorties sont affichées telles quelles depuis l'API (validées côté serveur)
//   • 4 onglets dans la modale — un seul appel API, commutation instantanée
//   • En cas d'erreur : message explicite, jamais de crash silencieux
//   • Si l'API n'est pas configurée (503) : message d'aide clair
//   • Si mode statique / pas de réseau : dégradation gracieuse
//
// API publique :
//   AIBrief.buildContext(entity, type)   — extrait le contexte structuré (article|incident)
//   AIBrief.generate(entity, type)       — appelle /api/ai-brief, retourne { analystBrief, … }
//   AIBrief.showModal(entity, type)      — ouvre la modale et déclenche la génération
//   AIBrief.closeModal()                 — ferme la modale

const AIBrief = (() => {

  const HISTORY_KEY = "cv_ai_brief_history";
  const MAX_HISTORY = 15;  // Garder les 15 derniers briefs

  // ── Gestion de l'historique localStorage ──────────────────────────────────

  /**
   * Sauvegarde un brief généré dans l'historique local.
   * Conserve les MAX_HISTORY derniers briefs, supprime les plus anciens.
   * @param {object} result - Résultat de generate() avec analystBrief, executiveBrief, etc.
   * @param {object} entity - Article ou incident original
   * @param {string} type - "article" ou "incident"
   */
  function _saveBriefToHistory(result, entity, type) {
    if (result.error) return; // Ne pas sauvegarder les erreurs

    try {
      const history = _loadHistory();
      const entry = {
        id:           `brief_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        timestamp:    new Date().toISOString(),
        entityId:     entity.id || entity.incidentId || null,
        entityType:   type,
        title:        type === "incident" ? (entity.title || "Incident") : (entity.title || "Article"),
        analystBrief: result.analystBrief || "",
        executiveBrief: result.executiveBrief || "",
        nextStep:     result.nextStep || "",
        ticketDraft:  result.ticketDraft || "",
        escalationNote: result.escalationNote || "",
        shareRewrite: result.shareRewrite || "",
        model:        result.model || "AI"
      };

      history.unshift(entry);
      if (history.length > MAX_HISTORY) {
        history.splice(MAX_HISTORY);
      }

      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch (e) {
      console.warn("[AIBrief] History save failed:", e.message);
    }
  }

  /**
   * Charge l'historique des briefs depuis localStorage.
   * @returns {array} Tableau des briefs sauvegardés (plus récents d'abord)
   */
  function _loadHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) {
      console.warn("[AIBrief] History load failed:", e.message);
      return [];
    }
  }

  /**
   * Récupère un brief spécifique de l'historique par ID.
   * @param {string} briefId - ID du brief à récupérer
   * @returns {object|null} Le brief ou null si non trouvé
   */
  function _getBriefFromHistory(briefId) {
    const history = _loadHistory();
    return history.find(b => b.id === briefId) || null;
  }

  // ── Construction du contexte ──────────────────────────────────────────────
  //
  // UNIQUEMENT les champs signaux connus et vérifiés.
  // Pas de champs HTML bruts, pas de contenu libre non contrôlé.

  function buildContext(entity, type) {
    return type === "incident"
      ? _buildIncidentContext(entity)
      : _buildArticleContext(entity);
  }

  function _buildArticleContext(a) {
    const ctx = { type: "article" };

    // Identité
    if (a.title)      ctx.title  = String(a.title).slice(0, 200);
    if (a.sourceName) ctx.source = String(a.sourceName).slice(0, 80);
    if (a.pubDate) {
      ctx.pubDate = a.pubDate instanceof Date
        ? a.pubDate.toISOString().slice(0, 10)
        : String(a.pubDate).slice(0, 25);
    }

    // Description : strip HTML + troncature anti-injection
    const desc = String(a.description || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
    if (desc.length > 3) ctx.description = desc.slice(0, 800);

    // Priorité
    if (a.priorityLevel)             ctx.priorityLevel   = a.priorityLevel;
    if ((a.priorityScore || 0) > 0)  ctx.priorityScore   = Math.round(a.priorityScore);
    if (a.priorityReasons?.length)   ctx.priorityReasons = a.priorityReasons.slice(0, 5);

    // Vulnérabilité
    const cves = a.cveIds || a.cves || [];
    if (cves.length)          ctx.cves      = cves.slice(0, 6);
    if (a.isKEV === true)     ctx.isKEV     = true;
    if (a.epssScore != null)  ctx.epssScore = Math.round(a.epssScore * 1000) / 10; // → %
    if (a.cvssScore != null)  ctx.cvssScore = a.cvssScore;

    // Couverture & signaux
    if (a.vendors?.length)          ctx.vendors       = a.vendors.slice(0, 5);
    if ((a.iocCount || 0) > 0)      ctx.iocCount      = a.iocCount;
    if (a.isTrending === true)      ctx.trending      = true;
    if ((a.trendingCount || 0) > 1) ctx.trendingCount = a.trendingCount;
    if (a.watchlistMatches?.length) ctx.watchlistHits = a.watchlistMatches.slice(0, 5);
    if (a.attackTags?.length) {
      ctx.attackTags = a.attackTags.slice(0, 4).map(t => ({
        label:  String(t.label  || "").slice(0, 30),
        tactic: String(t.tactic || "").slice(0, 40)
      }));
    }

    return ctx;
  }

  function _buildIncidentContext(inc) {
    const ctx = { type: "incident" };

    // Identité
    if (inc.title)         ctx.title        = String(inc.title).slice(0, 200);
    if (inc.summary)       ctx.summary      = String(inc.summary).slice(0, 500);
    if (inc.articleCount)  ctx.articleCount = inc.articleCount;
    if (inc.sourceCount)   ctx.sourceCount  = inc.sourceCount;
    if (inc.sources?.length) ctx.sources    = inc.sources.slice(0, 5);

    // Priorité
    if (inc.incidentPriorityLevel)   ctx.priorityLevel   = inc.incidentPriorityLevel;
    if (inc.incidentPriorityScore)   ctx.priorityScore   = Math.round(inc.incidentPriorityScore);
    if (inc.priorityReasons?.length) ctx.priorityReasons = inc.priorityReasons.slice(0, 5);

    // Vulnérabilité
    if (inc.cves?.length)  ctx.cves    = inc.cves.slice(0, 6);
    if (inc.kev === true)  ctx.isKEV   = true;
    const epss = inc.maxEpss ?? inc.epssScore;
    if (epss != null)      ctx.epssScore = Math.round(epss * 1000) / 10;
    if (inc.vendors?.length) ctx.vendors = inc.vendors.slice(0, 5);

    // Couverture
    if (inc.watchlistMatches?.length) ctx.watchlistHits = inc.watchlistMatches.slice(0, 5);
    else if (inc.watchlistHit === true) ctx.watchlistHit = true;
    if (inc.trending === true)     ctx.trending     = true;
    if ((inc.rawIocCount || 0) > 0) ctx.iocCount    = inc.rawIocCount;
    if (inc.attackTags?.length)    ctx.attackTags   = inc.attackTags.slice(0, 4);
    if (inc.firstSeen)             ctx.firstSeen    = String(inc.firstSeen).slice(0, 25);
    if (inc.lastSeen)              ctx.lastSeen     = String(inc.lastSeen).slice(0, 25);

    // Angles de couverture (PoC · Exploitation · Patch · Advisory · News)
    if (inc.angles?.length)        ctx.angles       = inc.angles.slice(0, 5);

    return ctx;
  }

  // ── Appel API ─────────────────────────────────────────────────────────────

  async function generate(entity, type) {
    const ctx = buildContext(entity, type);
    if (!ctx) return { error: "build_failed", message: "Could not extract context." };

    try {
      const res = await fetch("/api/ai-brief", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(ctx),
        signal:  AbortSignal.timeout(28_000)
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        if (res.status === 503) {
          return { error: "not_configured", message: err.detail || "ANTHROPIC_API_KEY not set in Vercel environment." };
        }
        if (res.status === 504) {
          return { error: "timeout", message: "AI service timed out — try again." };
        }
        return { error: "api_error", message: err.error || `HTTP ${res.status}` };
      }

      return await res.json();

    } catch (e) {
      if (e.name === "TimeoutError" || e.name === "AbortError") {
        return { error: "timeout", message: "Request timed out — try again." };
      }
      // Mode statique ou réseau indisponible
      return {
        error:   "network_error",
        message: "AI Brief requires a Vercel deployment (API mode not available in static mode)."
      };
    }
  }

  // ── Rendu HTML ────────────────────────────────────────────────────────────

  function _renderResult(result) {
    if (result.error) {
      const msgs = {
        not_configured: `<strong>AI Brief not configured.</strong><br><small class="ai-brief-err-hint">${_esc(result.message)}</small>`,
        timeout:        `<strong>⏱ Timeout.</strong> ${_esc(result.message)}`,
        api_error:      `<strong>⚠ API error:</strong> ${_esc(result.message)}`,
        network_error:  `<strong>⚠ Not available.</strong><br><small class="ai-brief-err-hint">${_esc(result.message)}</small>`,
        build_failed:   `<strong>⚠ Context error:</strong> ${_esc(result.message)}`
      };
      return `<div class="ai-brief-error">${msgs[result.error] || "⚠ " + _esc(result.message)}</div>`;
    }

    const signalNote = result.signalCount ? `${result.signalCount} signals` : "";
    const modelLabel = result.model ? _esc(result.model) : "AI";
    const genTime    = result.generatedAt
      ? new Date(result.generatedAt).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
      : "";

    const hasTicket   = result.ticketDraft   && result.ticketDraft.trim().length > 0;
    const hasEscalate = result.escalationNote && result.escalationNote.trim().length > 0;
    const hasShare    = result.shareRewrite   && result.shareRewrite.trim().length > 0;

    return `
      <div class="ai-brief-panel">

        <!-- Tab bar -->
        <div class="ai-brief-tabs" role="tablist">
          <button class="ai-brief-tab ai-brief-tab-active" data-tab="brief"    role="tab" aria-selected="true">🔬 Brief</button>
          <button class="ai-brief-tab${hasTicket   ? '' : ' ai-brief-tab-empty'}" data-tab="ticket"   role="tab" aria-selected="false">🎫 Ticket</button>
          <button class="ai-brief-tab${hasEscalate ? '' : ' ai-brief-tab-empty'}" data-tab="escalate" role="tab" aria-selected="false">📢 Escalate</button>
          <button class="ai-brief-tab${hasShare    ? '' : ' ai-brief-tab-empty'}" data-tab="share"    role="tab" aria-selected="false">📤 Share</button>
        </div>

        <!-- Panel: Brief -->
        <div class="ai-brief-tab-panel" data-panel="brief">

          <div class="ai-brief-sec">
            <div class="ai-brief-sec-title">🔬 Analyst Brief</div>
            <p class="ai-brief-text">${_esc(result.analystBrief)}</p>
            <button class="ai-brief-copy-btn" data-ai-copy="analyst" title="Copy analyst brief">⎘ Copy</button>
          </div>

          <div class="ai-brief-sec">
            <div class="ai-brief-sec-title">📊 Executive Brief</div>
            <p class="ai-brief-text">${_esc(result.executiveBrief)}</p>
            <button class="ai-brief-copy-btn" data-ai-copy="exec" title="Copy executive brief">⎘ Copy</button>
          </div>

          <div class="ai-brief-sec ai-brief-nextstep-sec">
            <div class="ai-brief-sec-title">▶ Recommended Next Step</div>
            <p class="ai-brief-text ai-brief-nextstep-text">${_esc(result.nextStep)}</p>
            <button class="ai-brief-copy-btn" data-ai-copy="nextstep" title="Copy next step">⎘ Copy</button>
          </div>

          <div class="ai-brief-tab-footer">
            <button class="ai-brief-copy-btn ai-brief-copy-all-btn" data-ai-copy-all="brief">⎘ Copy all</button>
          </div>
        </div>

        <!-- Panel: Ticket -->
        <div class="ai-brief-tab-panel ai-brief-tab-panel-hidden" data-panel="ticket">
          ${hasTicket
            ? `<div class="ai-ticket-block">${_renderTicketDraft(result.ticketDraft)}</div>
               <div class="ai-brief-tab-footer">
                 <button class="ai-brief-copy-btn ai-brief-copy-all-btn" data-ai-copy-all="ticket">⎘ Copy ticket</button>
               </div>`
            : `<div class="ai-brief-error">Ticket draft not available for this context.</div>`
          }
        </div>

        <!-- Panel: Escalate -->
        <div class="ai-brief-tab-panel ai-brief-tab-panel-hidden" data-panel="escalate">
          ${hasEscalate
            ? `<div class="ai-brief-sec">
                 <div class="ai-brief-sec-title">📢 Escalation Note</div>
                 <div class="ai-brief-lines">${_renderLines(result.escalationNote)}</div>
                 <button class="ai-brief-copy-btn" data-ai-copy="escalate" title="Copy escalation note">⎘ Copy</button>
               </div>
               <div class="ai-brief-tab-footer">
                 <button class="ai-brief-copy-btn ai-brief-copy-all-btn" data-ai-copy-all="escalate">⎘ Copy note</button>
               </div>`
            : `<div class="ai-brief-error">Escalation note not available for this context.</div>`
          }
        </div>

        <!-- Panel: Share -->
        <div class="ai-brief-tab-panel ai-brief-tab-panel-hidden" data-panel="share">
          ${hasShare
            ? `<div class="ai-brief-sec">
                 <div class="ai-brief-sec-title">📤 Share Rewrite <span class="ai-brief-sec-hint">Slack / Teams</span></div>
                 <div class="ai-brief-lines ai-brief-share-lines">${_renderLines(result.shareRewrite)}</div>
                 <button class="ai-brief-copy-btn" data-ai-copy="share" title="Copy share message">⎘ Copy</button>
               </div>
               <div class="ai-brief-tab-footer">
                 <button class="ai-brief-copy-btn ai-brief-copy-all-btn" data-ai-copy-all="share">⎘ Copy message</button>
               </div>`
            : `<div class="ai-brief-error">Share rewrite not available for this context.</div>`
          }
        </div>

        <!-- Global footer / disclaimer -->
        <div class="ai-brief-footer">
          <span class="ai-brief-disclaimer">
            ✦ ${_esc(modelLabel)} · ${_esc(signalNote)}${genTime ? " · " + _esc(genTime) : ""}
            · Always verify before action
          </span>
        </div>

      </div>`;
  }

  // Render ticketDraft: each line "KEY: value" → labeled row; bare lines → value-only row
  function _renderTicketDraft(raw) {
    if (!raw) return "";
    const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);
    return lines.map(line => {
      const colon = line.indexOf(": ");
      if (colon > 0 && colon < 30) {
        const key = line.slice(0, colon).trim();
        const val = line.slice(colon + 2).trim();
        return `<div class="ai-ticket-row">
          <span class="ai-ticket-key">${_esc(key)}</span>
          <span class="ai-ticket-val">${_esc(val)}</span>
        </div>`;
      }
      return `<div class="ai-ticket-row ai-ticket-row-full"><span class="ai-ticket-val">${_esc(line)}</span></div>`;
    }).join("");
  }

  // Render escalationNote / shareRewrite: split on \n, each line → <p>
  function _renderLines(raw) {
    if (!raw) return "";
    return raw.split("\n")
      .map(l => l.trim())
      .filter(Boolean)
      .map(l => `<p class="ai-brief-line">${_esc(l)}</p>`)
      .join("");
  }

  // ── Modal ─────────────────────────────────────────────────────────────────

  function showModal(entity, type) {
    // Réutiliser ou créer l'overlay
    let overlay = document.getElementById("ai-brief-overlay");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id        = "ai-brief-overlay";
      overlay.className = "ai-brief-overlay";
      overlay.style.display = "none";
      document.body.appendChild(overlay);
    }

    const rawTitle   = type === "incident"
      ? (entity.title || "Incident")
      : (entity.title || "Article");
    const shortTitle = String(rawTitle).slice(0, 70) + (rawTitle.length > 70 ? "…" : "");

    // Build incident context badge (article count · source count)
    let contextBadge = "";
    if (type === "incident") {
      const parts = ["Incident"];
      if (entity.articleCount) parts.push(`${entity.articleCount} article${entity.articleCount !== 1 ? "s" : ""}`);
      if (entity.sourceCount)  parts.push(`${entity.sourceCount} source${entity.sourceCount !== 1 ? "s" : ""}`);
      contextBadge = `<span class="ai-brief-context-badge">${_esc(parts.join(" · "))}</span>`;
    }

    overlay.innerHTML = `
      <div class="ai-brief-box" role="dialog" aria-modal="true">
        <div class="ai-brief-modal-hd">
          <span class="ai-brief-modal-logo">✦</span>
          <div class="ai-brief-modal-hd-text">
            <span class="ai-brief-modal-title">${_esc(shortTitle)}</span>
            ${contextBadge}
          </div>
          <button class="ai-brief-modal-close" id="ai-brief-close" title="Close">✕</button>
        </div>
        <div class="ai-brief-modal-body" id="ai-brief-body">
          <div class="ai-brief-loading">
            <span class="ai-brief-spinner"></span>
            <span>Generating AI brief…</span>
          </div>
        </div>
      </div>`;

    overlay.style.display = "flex";
    document.body.style.overflow = "hidden";

    document.getElementById("ai-brief-close")
      ?.addEventListener("click", closeModal);
    overlay.addEventListener("click", e => { if (e.target === overlay) closeModal(); });
    document.addEventListener("keydown", _onEsc);

    // Génération asynchrone
    generate(entity, type).then(result => {
      const body = document.getElementById("ai-brief-body");
      if (!body) return;
      body.innerHTML = _renderResult(result);
      if (!result.error) {
        // Sauvegarder le brief généré dans l'historique
        _saveBriefToHistory(result, entity, type);
        _bindTabs(body);
        _bindCopyButtons(body, result);
      }
    });
  }

  function closeModal() {
    const overlay = document.getElementById("ai-brief-overlay");
    if (overlay) overlay.style.display = "none";
    document.body.style.overflow = "";
    document.removeEventListener("keydown", _onEsc);
  }

  function _onEsc(e) { if (e.key === "Escape") closeModal(); }

  // ── Onglets ───────────────────────────────────────────────────────────────

  function _bindTabs(container) {
    const tabs   = container.querySelectorAll(".ai-brief-tab");
    const panels = container.querySelectorAll(".ai-brief-tab-panel");

    tabs.forEach(tab => {
      tab.addEventListener("click", () => {
        const target = tab.dataset.tab;

        tabs.forEach(t => {
          t.classList.remove("ai-brief-tab-active");
          t.setAttribute("aria-selected", "false");
        });
        panels.forEach(p => p.classList.add("ai-brief-tab-panel-hidden"));

        tab.classList.add("ai-brief-tab-active");
        tab.setAttribute("aria-selected", "true");
        const panel = container.querySelector(`[data-panel="${target}"]`);
        if (panel) panel.classList.remove("ai-brief-tab-panel-hidden");
      });
    });
  }

  // ── Boutons Copy ──────────────────────────────────────────────────────────

  function _buildBriefText(result) {
    return [
      `🔬 ANALYST BRIEF\n${result.analystBrief}`,
      `\n📊 EXECUTIVE BRIEF\n${result.executiveBrief}`,
      `\n▶ RECOMMENDED NEXT STEP\n${result.nextStep}`,
      `\n[✦ AI-generated by ThreatLens · ${result.model || "AI"} · ${new Date().toLocaleString("en-US")}]`
    ].join("");
  }

  function _bindCopyButtons(container, result) {
    // Boutons copy individuels
    container.querySelectorAll("[data-ai-copy]").forEach(btn => {
      btn.addEventListener("click", () => {
        const which = btn.dataset.aiCopy;
        const text  = which === "analyst"  ? result.analystBrief
                    : which === "exec"     ? result.executiveBrief
                    : which === "nextstep" ? result.nextStep
                    : which === "escalate" ? result.escalationNote
                    : which === "share"    ? result.shareRewrite
                    : "";
        if (text) _copyText(text, btn);
      });
    });

    // Boutons "Copy all" par onglet
    container.querySelectorAll("[data-ai-copy-all]").forEach(btn => {
      btn.addEventListener("click", () => {
        const which = btn.dataset.aiCopyAll;
        let text = "";
        if (which === "brief") {
          text = _buildBriefText(result);
        } else if (which === "ticket") {
          text = result.ticketDraft || "";
        } else if (which === "escalate") {
          text = result.escalationNote || "";
        } else if (which === "share") {
          text = result.shareRewrite || "";
        }
        if (text) _copyText(text, btn);
      });
    });
  }

  function _copyText(text, btn) {
    navigator.clipboard?.writeText(text).then(() => {
      if (!btn) return;
      const orig = btn.textContent;
      btn.textContent = "✓ Copied";
      setTimeout(() => { btn.textContent = orig; }, 1600);
    }).catch(() => {
      if (typeof UI !== "undefined") UI.showToast("⚠ Copy failed", "error");
    });
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  function _esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  return { buildContext, generate, showModal, closeModal };

})();
