// settings-modal.js — Modal Paramètres : onglet Alertes + onglet Flux RSS

const SettingsModal = (() => {

  let _currentTab  = "alerts";
  let _feedFilter  = "all"; // "all" | "active" | "error"
  let _feedsDirty  = false; // true si l'utilisateur a modifié des flux sans actualiser

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 1 — Ouvrir / fermer / tabs
  // ══════════════════════════════════════════════════════════════════════════

  function open() {
    const modal = document.getElementById("modal-settings");
    if (!modal) return;
    _feedsDirty = false;   // reset à chaque ouverture
    _populate();
    modal.style.display = "flex";
    document.body.style.overflow = "hidden";
    switchTab(_currentTab);
  }

  function close() {
    const modal = document.getElementById("modal-settings");
    if (modal) modal.style.display = "none";
    document.body.style.overflow = "";
    // Rappel discret si des flux ont été modifiés sans actualiser
    if (_feedsDirty) {
      UI.showToast("💾 Flux sauvegardés — cliquez ↺ Actualiser pour voir les effets", "info");
      _feedsDirty = false;
    }
  }

  function switchTab(tab) {
    _currentTab = tab;
    document.querySelectorAll(".settings-tab").forEach(t =>
      t.classList.toggle("settings-tab-active", t.dataset.tab === tab)
    );
    document.querySelectorAll(".settings-tab-pane").forEach(p =>
      (p.style.display = p.id === `settings-tab-${tab}` ? "block" : "none")
    );
    if (tab === "feeds") renderFeeds(_feedFilter);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 2 — Onglet Alertes (logique existante inchangée)
  // ══════════════════════════════════════════════════════════════════════════

  function _populate() {
    const s = AlertManager.loadSettings();

    _val("alert-enabled",     s.enabled,       "checked");
    _val("alert-threshold",   s.threshold);
    _val("alert-cooldown",    Math.round(s.cooldownMs / 60_000));
    _val("alert-batch",       s.batchSize);
    _val("alert-webhook-url",  s.webhookUrl);
    _val("alert-resend-key",   s.resendApiKey);
    _val("alert-resend-from",  s.resendFrom);
    _val("alert-resend-to",    s.recipientEmail);
    _val("alert-sg-key",       s.sendgridApiKey);
    _val("alert-sg-from",      s.sendgridFrom);
    _val("alert-sg-to",        s.recipientEmail);
    _val("alert-ejs-service",  s.emailjsService);
    _val("alert-ejs-template", s.emailjsTemplate);
    _val("alert-ejs-key",      s.emailjsPublicKey);
    _val("alert-recipient",    s.recipientEmail);
    _val("alert-mailto-email", s.recipientEmail);

    _val("alert-mode", s.mode || "immediate");
    _val("alert-digest-hour",    s.digestHour    || "08:00");
    _val("alert-digest-weekday", s.digestWeekday ?? 1);
    _updateModeHint(s.mode || "immediate");

    const radio = document.querySelector(`input[name="alert-channel"][value="${s.channel}"]`);
    if (radio) radio.checked = true;
    _showChannelSection(s.channel);
    _bindChannelRadios();
    _bindModeSelect();
    _renderAlertHistory("all");
  }

  function save() {
    const channel  = document.querySelector('input[name="alert-channel"]:checked')?.value ?? "webhook";
    const cooldown = Math.max(5, parseInt(_val("alert-cooldown") || 30)) * 60_000;
    const batch    = Math.max(1, Math.min(20, parseInt(_val("alert-batch") || 5)));

    const recipientMap = {
      resend:   _val("alert-resend-to"),
      sendgrid: _val("alert-sg-to"),
      emailjs:  _val("alert-recipient"),
      mailto:   _val("alert-mailto-email"),
      webhook:  ""
    };
    const recipientEmail = recipientMap[channel] || _val("alert-recipient");

    const settings = {
      ...AlertManager.loadSettings(),
      enabled:         _val("alert-enabled", null, "checked"),
      mode:            _val("alert-mode") || "immediate",
      channel,
      webhookUrl:      _val("alert-webhook-url"),
      resendApiKey:    _val("alert-resend-key"),
      resendFrom:      _val("alert-resend-from"),
      sendgridApiKey:  _val("alert-sg-key"),
      sendgridFrom:    _val("alert-sg-from"),
      emailjsService:  _val("alert-ejs-service"),
      emailjsTemplate: _val("alert-ejs-template"),
      emailjsPublicKey:_val("alert-ejs-key"),
      recipientEmail,
      threshold:       _val("alert-threshold") || "high",
      cooldownMs:      cooldown,
      batchSize:       batch,
      digestHour:      _val("alert-digest-hour")    || "08:00",
      digestWeekday:   parseInt(_val("alert-digest-weekday") ?? "1")
    };

    AlertManager.saveSettings(settings);
    UI.showToast("⚙️ Paramètres alertes enregistrés", "success");
    close();
    _updateSettingsBtn(settings);
  }

  async function testWebhook() {
    const url = _val("alert-webhook-url");
    if (!url) { UI.showToast("Entrez d'abord une URL webhook", "error"); return; }
    const btn = document.querySelector(".btn-test");
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Envoi…"; }
    try {
      const res = await fetch(url, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event: "cyberveille_test", message: "✅ CyberVeille Pro — Test webhook réussi !", timestamp: new Date().toISOString() }),
        signal: AbortSignal.timeout(8000)
      });
      if (res.ok) UI.showToast("✅ Webhook test envoyé avec succès !", "success");
      else        UI.showToast(`⚠️ Webhook répondu HTTP ${res.status}`, "warning");
    } catch (e) {
      UI.showToast(`❌ Échec webhook : ${e.message}`, "error");
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "🧪 Tester le webhook"; }
    }
  }

  async function testEmailJS() {
    const s = {
      emailjsService:  _val("alert-ejs-service"),
      emailjsTemplate: _val("alert-ejs-template"),
      emailjsPublicKey:_val("alert-ejs-key"),
      recipientEmail:  _val("alert-recipient")
    };
    if (!s.emailjsService || !s.emailjsTemplate || !s.emailjsPublicKey) {
      UI.showToast("Remplissez Service ID, Template ID et Clé publique", "error"); return;
    }
    const fakeArticle = [{ id: "test-article", title: "Test CyberVeille Pro — email de test", sourceName: "CyberVeille Pro", criticality: "high", link: "https://example.com", pubDate: new Date(), description: "Email de test." }];
    const testBtn = document.querySelectorAll(".btn-test")[1];
    if (testBtn) { testBtn.disabled = true; testBtn.textContent = "⏳ Envoi…"; }
    const saved = AlertManager.loadSettings();
    AlertManager.saveSettings({ ...saved, ...s, channel: "emailjs", enabled: true, lastSentAt: 0, cooldownMs: 0 });
    try {
      await AlertManager.processNewArticles(fakeArticle);
      UI.showToast("✅ Email test envoyé — vérifiez votre boîte", "success");
    } catch (e) {
      UI.showToast(`❌ EmailJS : ${e.message}`, "error");
    } finally {
      AlertManager.saveSettings(saved);
      if (testBtn) { testBtn.disabled = false; testBtn.textContent = "🧪 Envoyer un email test"; }
    }
  }

  async function testResend() {
    const s = { resendApiKey: _val("alert-resend-key"), resendFrom: _val("alert-resend-from"), recipientEmail: _val("alert-resend-to") };
    if (!s.resendApiKey)   { UI.showToast("Clé API Resend manquante", "error"); return; }
    if (!s.recipientEmail) { UI.showToast("Email destinataire manquant", "error"); return; }
    await _runTest("resend", s, "🧪 Envoyer un email test", "#section-resend .btn-test");
  }

  async function testSendGrid() {
    const s = { sendgridApiKey: _val("alert-sg-key"), sendgridFrom: _val("alert-sg-from"), recipientEmail: _val("alert-sg-to") };
    if (!s.sendgridApiKey)  { UI.showToast("Clé API SendGrid manquante", "error"); return; }
    if (!s.sendgridFrom)    { UI.showToast("Adresse expéditeur manquante", "error"); return; }
    if (!s.recipientEmail)  { UI.showToast("Email destinataire manquant", "error"); return; }
    await _runTest("sendgrid", s, "🧪 Envoyer un email test", "#section-sendgrid .btn-test");
  }

  async function _runTest(channel, overrides, btnLabel, btnSelector) {
    const btn = document.querySelector(btnSelector);
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Envoi…"; }
    const fakeArticles = [{ id: `test-${channel}`, title: `✅ Test CyberVeille Pro via ${channel}`, sourceName: "CyberVeille Pro", criticality: "high", link: "https://example.com", pubDate: new Date(), description: `Email de test ${channel}.` }];
    const saved = AlertManager.loadSettings();
    AlertManager.saveSettings({ ...saved, ...overrides, channel, enabled: true, lastSentAt: 0, cooldownMs: 0 });
    try {
      await AlertManager.processNewArticles(fakeArticles);
      UI.showToast(`✅ Email test ${channel} envoyé — vérifiez votre boîte`, "success");
    } catch (e) {
      UI.showToast(`❌ ${channel} : ${e.message}`, "error");
    } finally {
      AlertManager.saveSettings(saved);
      if (btn) { btn.disabled = false; btn.textContent = btnLabel; }
    }
  }

  function _showChannelSection(channel) {
    ["webhook", "resend", "sendgrid", "emailjs", "mailto"].forEach(c => {
      const el = document.getElementById(`section-${c}`);
      if (el) el.style.display = c === channel ? "block" : "none";
    });
  }

  function _bindChannelRadios() {
    document.querySelectorAll('input[name="alert-channel"]').forEach(radio => {
      radio.onchange = () => _showChannelSection(radio.value);
    });
  }

  function _updateSettingsBtn(settings) {
    const btn = document.getElementById("btn-settings");
    if (!btn) return;
    if (settings.enabled) {
      btn.classList.add("active");
      btn.title = `Alertes activées — canal : ${settings.channel}`;
    } else {
      btn.classList.remove("active");
      btn.title = "Paramètres alertes email/webhook";
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 3 — Onglet Flux RSS
  // ══════════════════════════════════════════════════════════════════════════

  /** Rendu de la liste des flux avec filtre optionnel. */
  function renderFeeds(filter = "all") {
    _feedFilter = filter;
    const list = document.getElementById("fm-feed-list");
    if (!list) return;

    // Mettre à jour les pills de filtre
    document.querySelectorAll(".fm-filter-pill").forEach(p =>
      p.classList.toggle("fm-filter-active", p.dataset.filter === filter)
    );

    const all    = FeedManager.getAllFeeds();
    const active = all.filter(f => f.enabled).length;
    const errors = all.filter(f => f.lastStatus === "error").length;

    // Compteur de statut
    const statsEl = document.getElementById("fm-count-stats");
    if (statsEl) {
      statsEl.textContent = `${active} actifs · ${all.length} total`
        + (errors > 0 ? ` · ⚠ ${errors} en erreur` : "");
    }

    // Badge sur l'onglet
    const badge = document.getElementById("fm-active-badge");
    if (badge) badge.textContent = active > 0 ? String(active) : "";

    // Filtrage
    let feeds = all;
    if (filter === "active") feeds = all.filter(f => f.enabled);
    if (filter === "error")  feeds = all.filter(f => f.lastStatus === "error");

    if (feeds.length === 0) {
      const allUnknown = all.every(f => f.lastStatus === "unknown");
      list.innerHTML = `<div class="fm-empty">${
        filter === "error"  ? (allUnknown ? "Aucun test effectué — cliquez ↺ Actualiser pour diagnostiquer les flux" : "Aucun flux en erreur 🎉") :
        filter === "active" ? "Aucun flux actif" :
        "Aucun flux configuré"
      }</div>`;
      return;
    }

    list.innerHTML = feeds.map(f => _buildFeedRow(f)).join("");
  }

  /** Construit le HTML d'une ligne de flux. */
  function _buildFeedRow(f) {
    const neverTested = !f.lastTestAt;
    const statusClass = f.lastStatus === "ok"    ? "fm-status-ok"
                      : f.lastStatus === "error" ? "fm-status-error"
                      :                            "fm-status-unknown";
    const statusLabel = f.lastStatus === "ok"    ? "✓ OK"
                      : f.lastStatus === "error" ? "✗ Erreur"
                      : neverTested              ? "— jamais testé"
                      :                            "? Inconnu";

    const lastTest  = f.lastTestAt ? _relTime(f.lastTestAt) : "jamais testé";
    const itemCount = f.lastItemCount !== null ? `${f.lastItemCount} art.` : "";
    const hostname  = (() => { try { return new URL(f.url).hostname; } catch { return (f.url || "").slice(0, 40); } })();

    const deleteBtn = f.isDefault ? "" :
      `<button class="fm-btn fm-btn-danger" title="Supprimer ce flux" onclick="SettingsModal.deleteFeed('${f.id}')">🗑</button>`;
    const editBtn   = f.isDefault ? "" :
      `<button class="fm-btn" title="Modifier ce flux" onclick="SettingsModal.editFeedToggle('${f.id}')">✏️</button>`;

    const errorRow = (f.lastStatus === "error") ?
      `<div class="fm-error-row">❌ ${_esc(f.lastErrorMessage || "Erreur inconnue")}</div>` : "";

    const editForm = f.isDefault ? "" : `
      <div class="fm-edit-row" id="fm-edit-${f.id}" style="display:none">
        <div class="fm-edit-grid">
          <input class="settings-input" placeholder="Nom" id="fm-en-${f.id}" value="${_esc(f.name)}">
          <input class="settings-input" placeholder="URL RSS" id="fm-eu-${f.id}" value="${_esc(f.url)}">
          <select class="select-filter" id="fm-ec-${f.id}">
            ${["news","advisory","exploit","threat","cert","research"].map(c =>
              `<option value="${c}"${f.category === c ? " selected" : ""}>${c}</option>`
            ).join("")}
          </select>
          <input class="settings-input fm-edit-icon-input" placeholder="📡" maxlength="4" id="fm-ei-${f.id}" value="${_esc(f.icon || "")}">
        </div>
        <div class="fm-edit-errors" id="fm-ee-${f.id}" style="display:none"></div>
        <div class="fm-edit-actions">
          <button class="btn btn-primary" onclick="SettingsModal.saveEditFeed('${f.id}')">💾 Sauvegarder</button>
          <button class="btn" onclick="SettingsModal.editFeedToggle('${f.id}')">Annuler</button>
        </div>
      </div>`;

    const disabledClass = f.enabled ? "" : " fm-feed-disabled";

    return `
      <div class="fm-feed-item${disabledClass}" id="fm-row-${f.id}">
        <div class="fm-feed-main">
          <span class="fm-feed-icon">${f.icon || "📡"}</span>
          <div class="fm-feed-info">
            <div class="fm-feed-name">
              ${_esc(f.name)}
              <span class="${f.isDefault ? "fm-badge-default" : "fm-badge-custom"}">${f.isDefault ? "défaut" : "custom"}</span>
            </div>
            <div class="fm-feed-url" title="${_esc(f.url)}">${hostname}</div>
            <div class="fm-feed-meta">
              <span class="fm-status ${statusClass}">${statusLabel}</span>
              ${itemCount ? `<span class="fm-meta-sep">·</span><span class="fm-meta-item">📦 ${itemCount}</span>` : ""}
              <span class="fm-meta-sep">·</span>
              <span class="fm-meta-item">🕐 ${lastTest}</span>
            </div>
          </div>
          <div class="fm-feed-actions">
            <button class="fm-btn fm-btn-test" title="Tester ce flux maintenant" onclick="SettingsModal.testFeedUI('${f.id}')">🧪</button>
            ${editBtn}
            ${deleteBtn}
            <label class="fm-toggle-wrap" title="${f.enabled ? "Désactiver" : "Activer"}">
              <input type="checkbox" class="fm-toggle-input" ${f.enabled ? "checked" : ""} onchange="SettingsModal.toggleFeedUI('${f.id}', this.checked)">
              <span class="fm-toggle-track"><span class="fm-toggle-thumb"></span></span>
            </label>
          </div>
        </div>
        ${errorRow}
        ${editForm}
      </div>`;
  }

  /** Lance le test d'un flux depuis l'UI. */
  async function testFeedUI(feedId) {
    const feed = FeedManager.getAllFeeds().find(f => f.id === feedId);
    if (!feed) return;

    const row = document.getElementById(`fm-row-${feedId}`);
    const btn = row?.querySelector(".fm-btn-test");
    if (btn) { btn.disabled = true; btn.textContent = "⏳"; }

    UI.showToast(`🧪 Test de ${feed.name}…`, "info");

    const result = await FeedManager.testFeed(feed);

    if (result.ok) UI.showToast(`✅ ${feed.name} — ${result.message}`, "success");
    else           UI.showToast(`❌ ${feed.name} — ${result.message}`, "error");

    // Rafraîchir la ligne pour afficher le nouveau statut
    renderFeeds(_feedFilter);
  }

  /** Active ou désactive un flux depuis le toggle. */
  function toggleFeedUI(feedId, enabled) {
    FeedManager.toggleFeed(feedId, enabled);
    _feedsDirty = true;
    Storage.clearCache();           // invalide le cache → le prochain refresh prend en compte le changement
    renderFeeds(_feedFilter);
    _syncCounters();
  }

  /** Supprime un flux custom avec confirmation. */
  function deleteFeed(feedId) {
    const feed = FeedManager.getAllFeeds().find(f => f.id === feedId);
    if (!feed || feed.isDefault) return;
    if (!confirm(`Supprimer définitivement le flux « ${feed.name} » ?`)) return;
    const r = FeedManager.removeFeed(feedId);
    if (r.ok) {
      _feedsDirty = true;
      Storage.clearCache();
      UI.showToast(`Flux « ${feed.name} » supprimé`, "success");
      renderFeeds(_feedFilter);
      _syncCounters();
    } else {
      UI.showToast("Impossible de supprimer ce flux", "error");
    }
  }

  /** Affiche ou masque le formulaire d'édition inline d'un flux. */
  function editFeedToggle(feedId) {
    const editRow = document.getElementById(`fm-edit-${feedId}`);
    if (!editRow) return;
    const isOpen = editRow.style.display !== "none";
    editRow.style.display = isOpen ? "none" : "block";
    // Effacer les erreurs à l'ouverture
    if (!isOpen) {
      const errEl = document.getElementById(`fm-ee-${feedId}`);
      if (errEl) errEl.style.display = "none";
    }
  }

  /** Sauvegarde les modifications inline d'un flux custom. */
  function saveEditFeed(feedId) {
    const name  = document.getElementById(`fm-en-${feedId}`)?.value.trim();
    const url   = document.getElementById(`fm-eu-${feedId}`)?.value.trim();
    const cat   = document.getElementById(`fm-ec-${feedId}`)?.value;
    const icon  = document.getElementById(`fm-ei-${feedId}`)?.value.trim();
    const errEl = document.getElementById(`fm-ee-${feedId}`);

    const r = FeedManager.updateFeed(feedId, { name, url, category: cat, icon: icon || "📡" });
    if (!r.ok) {
      if (errEl) {
        errEl.innerHTML = (r.errors || [r.error]).map(e => `<div class="fm-err-item">⚠ ${e}</div>`).join("");
        errEl.style.display = "block";
      }
      return;
    }
    _feedsDirty = true;
    Storage.clearCache();   // l'URL a peut-être changé → forcer un refetch
    UI.showToast("✅ Flux mis à jour", "success");
    renderFeeds(_feedFilter);
    _syncCounters();
  }

  /** Ajoute un nouveau flux depuis le formulaire d'ajout. */
  function addFeed() {
    const nameEl = document.getElementById("fm-new-name");
    const urlEl  = document.getElementById("fm-new-url");
    const catEl  = document.getElementById("fm-new-category");
    const iconEl = document.getElementById("fm-new-icon");
    const errEl  = document.getElementById("fm-add-errors");

    const r = FeedManager.addFeed({
      name:     nameEl?.value.trim(),
      url:      urlEl?.value.trim(),
      category: catEl?.value || "news",
      icon:     iconEl?.value.trim() || "📡"
    });

    if (!r.ok) {
      if (errEl) {
        errEl.innerHTML = r.errors.map(e => `<div class="fm-err-item">⚠ ${e}</div>`).join("");
        errEl.style.display = "block";
      }
      return;
    }

    // Vider le formulaire
    if (nameEl) nameEl.value = "";
    if (urlEl)  urlEl.value  = "";
    if (iconEl) iconEl.value = "";
    if (errEl)  errEl.style.display = "none";

    _feedsDirty = true;
    Storage.clearCache();           // force un refetch complet incluant le nouveau flux
    UI.showToast(`✅ Flux « ${r.feed.name} » ajouté`, "success");
    renderFeeds(_feedFilter);
    _syncCounters();
  }

  /** Réinitialise tous les flux personnalisés avec confirmation. */
  function resetCustomFeeds() {
    const custom = FeedManager.loadCustomFeeds();
    if (custom.length === 0) { UI.showToast("Aucun flux personnalisé à supprimer", "info"); return; }
    if (!confirm(`Supprimer les ${custom.length} flux personnalisés ?`)) return;
    FeedManager.resetCustomFeeds();
    Storage.clearCache();
    UI.showToast("Flux personnalisés réinitialisés", "success");
    renderFeeds(_feedFilter);
    _syncCounters();
  }

  /** Ferme le modal et force immédiatement un refresh RSS avec les flux actifs. */
  function applyAndRefresh() {
    _feedsDirty = false;   // reset avant close() pour éviter le double toast
    close();
    UI.showToast("↺ Actualisation en cours…", "info");
    // Storage.clearCache() déjà appelé par les actions précédentes si nécessaire
    // On force un refetch complet même si le cache est encore frais
    Storage.clearCache();
    App.refreshForced();
  }

  /** Restaure tous les flux par défaut (réactive les désactivés). */
  function restoreDefaultFeeds() {
    if (!confirm("Réactiver tous les flux par défaut désactivés ?")) return;
    FeedManager.restoreDefaultFeeds();
    Storage.clearCache();
    UI.showToast("Flux par défaut restaurés", "success");
    renderFeeds(_feedFilter);
    _syncCounters();
  }

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 4 — Utilitaires privés
  // ══════════════════════════════════════════════════════════════════════════

  const MODE_HINTS = {
    immediate:      "Chaque alerte est envoyée immédiatement, dans la limite du cooldown configuré.",
    urgent_only:    "Seuls les articles KEV actif ou EPSS ≥ 70 % déclenchent une alerte, sans cooldown.",
    daily_digest:   "Les alertes sont accumulées et envoyées chaque jour à l'heure configurée.",
    weekly_digest:  "Les alertes sont accumulées et envoyées chaque semaine à l'heure configurée."
  };

  function _updateModeHint(mode) {
    const hint = document.getElementById("alert-mode-hint");
    if (hint) hint.textContent = MODE_HINTS[mode] || "";

    const flushBtn      = document.getElementById("btn-flush-digest");
    const countEl       = document.getElementById("digest-queue-count");
    const hourGroup     = document.getElementById("digest-hour-group");
    const weekdayGroup  = document.getElementById("digest-weekday-group");
    const hourHint      = document.getElementById("digest-hour-hint");
    const isDigest      = mode === "daily_digest" || mode === "weekly_digest";
    const isWeekly      = mode === "weekly_digest";

    if (flushBtn)     flushBtn.style.display    = isDigest ? "inline-flex" : "none";
    if (hourGroup)    hourGroup.style.display   = isDigest ? "block"       : "none";
    if (weekdayGroup) weekdayGroup.style.display = isWeekly ? "block"      : "none";

    if (countEl && isDigest) {
      const n = AlertManager.getDigestCount();
      countEl.textContent = n > 0 ? ` (${n} en attente)` : "";
    }
    // Hint contextuel selon le mode
    if (hourHint) {
      hourHint.textContent = isWeekly
        ? "Le briefing sera envoyé une fois par semaine, le jour et à l'heure configurés."
        : "Le briefing quotidien sera envoyé chaque jour à cette heure.";
    }
  }

  function _bindModeSelect() {
    const sel = document.getElementById("alert-mode");
    if (sel) sel.onchange = () => _updateModeHint(sel.value);
  }

  /**
   * Synchronise le compteur de la barre de statut + le filtre source dans la navbar.
   * À appeler après toute modification des flux (add, toggle, delete, reset, restore).
   */
  function _syncCounters() {
    const el = document.getElementById("statusbar-feed-count");
    if (el) el.textContent = FeedManager.getActiveCount();
    UI.initSourceFilter();
  }

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 3b — Historique des alertes
  // ══════════════════════════════════════════════════════════════════════════

  /** Rend la liste des entrées d'historique selon le filtre actif. */
  function _renderAlertHistory(filter) {
    const listEl  = document.getElementById("alert-history-list");
    const countEl = document.getElementById("alert-hist-count");
    if (!listEl) return;

    const history = AlertManager.loadAlertHistory();

    if (countEl) {
      countEl.textContent = history.length > 0 ? `(${history.length})` : "";
    }

    if (history.length === 0) {
      listEl.innerHTML = '<div class="ah-empty">Aucun envoi enregistré.</div>';
      return;
    }

    const filtered = filter === "success" ? history.filter(e => e.success)
                   : filter === "error"   ? history.filter(e => !e.success)
                   : history;

    if (filtered.length === 0) {
      listEl.innerHTML = '<div class="ah-empty">Aucune entrée pour ce filtre.</div>';
      return;
    }

    listEl.innerHTML = filtered.map(e => {
      const d  = new Date(e.sentAt);
      const ts = isNaN(d) ? (e.sentAt || "—")
        : `${d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" })} ${d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}`;
      const icon    = e.success ? "✅" : "❌";
      const channel = _esc((e.channel || "—").charAt(0).toUpperCase() + (e.channel || "—").slice(1));
      const reason  = _esc(e.reason || e.mode || "—");
      const count   = `${e.articleCount ?? 0} art.`;
      const errHtml = (!e.success && e.errorMessage)
        ? `<span class="ah-err" title="${_esc(e.errorMessage)}">${_esc(e.errorMessage.slice(0, 60))}${e.errorMessage.length > 60 ? "…" : ""}</span>`
        : "";
      const titlesHtml = Array.isArray(e.titles) && e.titles.length
        ? `<div class="ah-titles">${e.titles.map(t => `<span class="ah-title">${_esc(t)}</span>`).join("")}</div>`
        : "";
      return `<div class="ah-entry${e.success ? "" : " ah-entry-err"}">
  <div class="ah-row">
    <span class="ah-icon">${icon}</span>
    <span class="ah-ts">${ts}</span>
    <span class="ah-channel">${channel}</span>
    <span class="ah-reason">${reason}</span>
    <span class="ah-count">${count}</span>
    ${errHtml}
  </div>
  ${titlesHtml}
</div>`;
    }).join("");
  }

  /** Vide l'historique après confirmation. */
  function clearAlertHistoryUI() {
    if (!confirm("Vider tout l'historique des alertes ?")) return;
    AlertManager.clearAlertHistory();
    _renderAlertHistory("all");
    document.querySelectorAll(".ah-filter-btn").forEach(b =>
      b.classList.toggle("active", b.dataset.filter === "all"));
    UI.showToast("Historique vidé", "success");
  }

  /** Change le filtre et met à jour l'affichage. */
  function filterAlertHistory(filter, btn) {
    document.querySelectorAll(".ah-filter-btn").forEach(b => b.classList.remove("active"));
    if (btn) btn.classList.add("active");
    _renderAlertHistory(filter);
  }

  /** Temps relatif à partir d'un timestamp ISO. */
  function _relTime(iso) {
    if (!iso) return "—";
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60_000)     return "à l'instant";
    if (diff < 3_600_000)  return `il y a ${Math.floor(diff / 60_000)} min`;
    if (diff < 86_400_000) return `il y a ${Math.floor(diff / 3_600_000)} h`;
    return `il y a ${Math.floor(diff / 86_400_000)} j`;
  }

  /** Échappe les caractères HTML. */
  function _esc(s) {
    return (s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /** Getter/setter générique pour un champ du modal. */
  function _val(id, setValue, prop = "value") {
    const el = document.getElementById(id);
    if (!el) return prop === "checked" ? false : "";
    if (setValue !== undefined && setValue !== null) el[prop] = setValue;
    return el[prop];
  }

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 5 — Initialisation
  // ══════════════════════════════════════════════════════════════════════════

  function init() {
    document.getElementById("btn-settings")?.addEventListener("click", open);
    document.addEventListener("keydown", e => { if (e.key === "Escape") close(); });
    _updateSettingsBtn(AlertManager.loadSettings());
  }

  // ── API publique ────────────────────────────────────────────────────────────

  return {
    // Modal général
    open, close, switchTab, init,
    // Alertes
    save, testWebhook, testEmailJS, testResend, testSendGrid,
    // Historique des alertes
    clearAlertHistoryUI, filterAlertHistory,
    // Flux RSS
    renderFeeds, testFeedUI, toggleFeedUI,
    deleteFeed, editFeedToggle, saveEditFeed,
    addFeed, resetCustomFeeds, restoreDefaultFeeds, applyAndRefresh
  };
})();
