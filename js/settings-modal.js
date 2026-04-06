// settings-modal.js v20 — Modal Paramètres : Alertes · Flux RSS · Integrations

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
      UI.showToast("💾 Feeds saved — click ↺ Refresh to apply changes", "info");
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
    // ── Onglet Integrations — Jira ───────────────────────────────────────────
    if (typeof JiraConfig !== 'undefined') {
      const jira = JiraConfig.load();
      _val('jira-base-url',    jira.baseUrl    || '');
      _val('jira-project-key', jira.projectKey || '');
    }
    // ── Onglet Integrations — TV1 ────────────────────────────────────────────
    if (typeof TV1Sync !== 'undefined') {
      const tv1 = TV1Sync.loadConfig();
      const sel = document.getElementById('tv1-region');
      if (sel && tv1.region) sel.value = tv1.region;
      // Per-CVE VP toggle removed — TV1 API does not expose IPS rule catalog

      // Afficher le statut de la dernière sync
      const lastSyncEl = document.getElementById('tv1-last-sync');
      if (lastSyncEl) {
        if (tv1.lastSyncAt) {
          const d = new Date(tv1.lastSyncAt);
          const dateStr = d.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' });
          const srcLabel = tv1.lastSyncSource === 'tv1_live' ? 'live' : 'démo';
          const addedPart = tv1.lastSyncAdded > 0 ? ` · ${tv1.lastSyncAdded} ajouté(s)` : '';
          const disabledPart = tv1.lastSyncDisabled > 0 ? ` · ${tv1.lastSyncDisabled} désactivé(s)` : '';
          const resultIcon  = tv1.lastSyncResult === 'success' ? '✅'
            : tv1.lastSyncResult === 'demo' ? '🔵'
            : '⚠';
          lastSyncEl.textContent = `${resultIcon} Dernière sync : ${dateStr} (${srcLabel}${addedPart}${disabledPart})`;
        } else {
          lastSyncEl.textContent = '';
        }
      }
    }

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
    _val("alert-token",        s.alertToken);
    _val("alert-sg-token",     s.alertToken);
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
    _adaptToMode();
    _renderAlertHistory("all");
  }

  // ── Adaptation de l'UI selon le mode prod/dev ─────────────────────────────
  //
  // En production (CONFIG.USE_API=true) : les clés API ne doivent pas être
  // saisies côté client — elles sont dans les env vars Vercel.
  // On cache les champs clé et on affiche un message "géré côté serveur".
  // On montre à la place les champs "token optionnel" (pour ALERT_TOKEN).

  function _adaptToMode() {
    const isProd = (typeof CONFIG !== "undefined") && CONFIG.USE_API;

    // Resend
    _showEl("resend-local-notice",  !isProd);
    _showEl("resend-prod-notice",    isProd);
    _showEl("resend-key-row",       !isProd);
    _showEl("resend-token-row",      isProd);

    // SendGrid
    _showEl("sg-local-notice",      !isProd);
    _showEl("sg-prod-notice",        isProd);
    _showEl("sg-key-row",           !isProd);
    _showEl("sg-token-row",          isProd);
  }

  function _showEl(id, visible) {
    const el = document.getElementById(id);
    if (el) el.style.display = visible ? "" : "none";
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

    const isProd   = (typeof CONFIG !== "undefined") && CONFIG.USE_API;
    const existing = AlertManager.loadSettings();

    const settings = {
      ...existing,
      enabled:         _val("alert-enabled", null, "checked"),
      mode:            _val("alert-mode") || "immediate",
      channel,
      webhookUrl:      _val("alert-webhook-url"),
      // En prod, ne pas écraser les clés locales par des champs cachés vides
      resendApiKey:    isProd ? existing.resendApiKey   : _val("alert-resend-key"),
      resendFrom:      _val("alert-resend-from"),
      sendgridApiKey:  isProd ? existing.sendgridApiKey : _val("alert-sg-key"),
      sendgridFrom:    _val("alert-sg-from"),
      emailjsService:  _val("alert-ejs-service"),
      emailjsTemplate: _val("alert-ejs-template"),
      emailjsPublicKey:_val("alert-ejs-key"),
      recipientEmail,
      threshold:       _val("alert-threshold") || "high",
      cooldownMs:      cooldown,
      batchSize:       batch,
      digestHour:      _val("alert-digest-hour")    || "08:00",
      digestWeekday:   parseInt(_val("alert-digest-weekday") ?? "1"),
      // Token d'auth optionnel pour /api/send-alert (si ALERT_TOKEN configuré sur Vercel)
      alertToken:      _val("alert-token") || _val("alert-sg-token") || existing.alertToken || ""
    };

    AlertManager.saveSettings(settings);
    UI.showToast("⚙️ Alert settings saved", "success");
    close();
    _updateSettingsBtn(settings);
  }

  async function testWebhook() {
    const url = _val("alert-webhook-url");
    if (!url) { UI.showToast("Entrez d'abord une URL webhook", "error"); return; }
    const btn = document.querySelector(".btn-test");
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Sending…"; }
    try {
      const res = await fetch(url, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event: "cyberveille_test", message: "✅ ThreatLens — Test webhook successful!", timestamp: new Date().toISOString() }),
        signal: AbortSignal.timeout(8000)
      });
      if (res.ok) UI.showToast("✅ Webhook test sent successfully!", "success");
      else        UI.showToast(`⚠️ Webhook responded HTTP ${res.status}`, "warning");
    } catch (e) {
      UI.showToast(`❌ Webhook error: ${e.message}`, "error");
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = "🧪 Test webhook"; }
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
      UI.showToast("Fill in Service ID, Template ID and public key", "error"); return;
    }
    const fakeArticle = [{ id: "test-article", title: "Test ThreatLens — test email", sourceName: "ThreatLens", criticality: "high", link: "https://example.com", pubDate: new Date(), description: "Test email." }];
    const testBtn = document.querySelectorAll(".btn-test")[1];
    if (testBtn) { testBtn.disabled = true; testBtn.textContent = "⏳ Sending…"; }
    const saved = AlertManager.loadSettings();
    AlertManager.saveSettings({ ...saved, ...s, channel: "emailjs", enabled: true, lastSentAt: 0, cooldownMs: 0 });
    try {
      await AlertManager.processNewArticles(fakeArticle);
      UI.showToast("✅ Test email sent — check your inbox", "success");
    } catch (e) {
      UI.showToast(`❌ EmailJS : ${e.message}`, "error");
    } finally {
      AlertManager.saveSettings(saved);
      if (testBtn) { testBtn.disabled = false; testBtn.textContent = "🧪 Send test email"; }
    }
  }

  async function testResend() {
    const isProd = (typeof CONFIG !== "undefined") && CONFIG.USE_API;
    const recipientEmail = _val("alert-resend-to");
    if (!isProd) {
      const key = _val("alert-resend-key");
      if (!key) { UI.showToast("Resend API key missing", "error"); return; }
    }
    if (!recipientEmail) { UI.showToast("Recipient email missing", "error"); return; }
    const s = {
      resendApiKey:  isProd ? "" : _val("alert-resend-key"),
      resendFrom:    _val("alert-resend-from"),
      recipientEmail,
      alertToken:    _val("alert-token") || AlertManager.loadSettings().alertToken || ""
    };
    await _runTest("resend", s, "🧪 Send test email", "#section-resend .btn-test");
  }

  async function testSendGrid() {
    const isProd = (typeof CONFIG !== "undefined") && CONFIG.USE_API;
    const recipientEmail = _val("alert-sg-to");
    if (!isProd) {
      const key = _val("alert-sg-key");
      if (!key) { UI.showToast("SendGrid API key missing", "error"); return; }
      const from = _val("alert-sg-from");
      if (!from) { UI.showToast("Sender address missing", "error"); return; }
    }
    if (!recipientEmail) { UI.showToast("Recipient email missing", "error"); return; }
    const s = {
      sendgridApiKey: isProd ? "" : _val("alert-sg-key"),
      sendgridFrom:   _val("alert-sg-from"),
      recipientEmail,
      alertToken:     _val("alert-sg-token") || AlertManager.loadSettings().alertToken || ""
    };
    await _runTest("sendgrid", s, "🧪 Send test email", "#section-sendgrid .btn-test");
  }

  async function _runTest(channel, overrides, btnLabel, btnSelector) {
    const btn = document.querySelector(btnSelector);
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Sending…"; }
    const fakeArticles = [{ id: `test-${channel}`, title: `✅ Test ThreatLens via ${channel}`, sourceName: "ThreatLens", criticality: "high", link: "https://example.com", pubDate: new Date(), description: `Test email via ${channel}.` }];
    const saved = AlertManager.loadSettings();
    AlertManager.saveSettings({ ...saved, ...overrides, channel, enabled: true, lastSentAt: 0, cooldownMs: 0 });
    try {
      await AlertManager.processNewArticles(fakeArticles);
      UI.showToast(`✅ ${channel} test email sent — check your inbox`, "success");
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
      btn.title = `Alerts enabled — channel: ${settings.channel}`;
    } else {
      btn.classList.remove("active");
      btn.title = "Email/webhook alert settings";
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
      statsEl.textContent = `${active} active · ${all.length} total`
        + (errors > 0 ? ` · ⚠ ${errors} error(s)` : "");
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
        filter === "error"  ? (allUnknown ? "No test performed — click ↺ Refresh to diagnose feeds" : "No feed errors 🎉") :
        filter === "active" ? "No active feeds" :
        "No feeds configured"
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
                      : f.lastStatus === "error" ? "✗ Error"
                      : neverTested              ? "— never tested"
                      :                            "? Inconnu";

    const lastTest  = f.lastTestAt ? _relTime(f.lastTestAt) : "never tested";
    const itemCount = f.lastItemCount !== null ? `${f.lastItemCount} art.` : "";
    const hostname  = (() => { try { return new URL(f.url).hostname; } catch { return (f.url || "").slice(0, 40); } })();

    const deleteBtn = f.isDefault ? "" :
      `<button class="fm-btn fm-btn-danger" title="Delete this feed" onclick="SettingsModal.deleteFeed('${f.id}')">🗑</button>`;
    const editBtn   = f.isDefault ? "" :
      `<button class="fm-btn" title="Edit this feed" onclick="SettingsModal.editFeedToggle('${f.id}')">✏️</button>`;

    const errorRow = (f.lastStatus === "error") ?
      `<div class="fm-error-row">❌ ${_esc(f.lastErrorMessage || "Unknown error")}</div>` : "";

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
          <button class="btn btn-primary" onclick="SettingsModal.saveEditFeed('${f.id}')">💾 Save</button>
          <button class="btn" onclick="SettingsModal.editFeedToggle('${f.id}')">Cancel</button>
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
              <span class="${f.isDefault ? "fm-badge-default" : "fm-badge-custom"}">${f.isDefault ? "default" : "custom"}</span>
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
            <button class="fm-btn fm-btn-test" title="Test this feed now" onclick="SettingsModal.testFeedUI('${f.id}')">🧪</button>
            ${editBtn}
            ${deleteBtn}
            <label class="fm-toggle-wrap" title="${f.enabled ? "Disable" : "Enable"}">
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

    UI.showToast(`🧪 Testing ${feed.name}…`, "info");

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
    if (!confirm(`Permanently delete feed « ${feed.name} »?`)) return;
    const r = FeedManager.removeFeed(feedId);
    if (r.ok) {
      _feedsDirty = true;
      Storage.clearCache();
      UI.showToast(`Feed « ${feed.name} » deleted`, "success");
      renderFeeds(_feedFilter);
      _syncCounters();
    } else {
      UI.showToast("Cannot delete this feed", "error");
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
    UI.showToast("✅ Feed updated", "success");
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
    UI.showToast(`✅ Feed « ${r.feed.name} » added`, "success");
    renderFeeds(_feedFilter);
    _syncCounters();
  }

  /** Réinitialise tous les flux personnalisés avec confirmation. */
  function resetCustomFeeds() {
    const custom = FeedManager.loadCustomFeeds();
    if (custom.length === 0) { UI.showToast("No custom feeds to delete", "info"); return; }
    if (!confirm(`Delete ${custom.length} custom feed(s)?`)) return;
    FeedManager.resetCustomFeeds();
    Storage.clearCache();
    UI.showToast("Custom feeds reset", "success");
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
    if (!confirm("Re-enable all disabled default feeds?")) return;
    FeedManager.restoreDefaultFeeds();
    Storage.clearCache();
    UI.showToast("Default feeds restored", "success");
    renderFeeds(_feedFilter);
    _syncCounters();
  }

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION 4 — Utilitaires privés
  // ══════════════════════════════════════════════════════════════════════════

  const MODE_HINTS = {
    immediate:      "Each alert is sent immediately, within the configured cooldown limit.",
    urgent_only:    "Only KEV active or EPSS ≥ 70% articles trigger an alert, without cooldown.",
    daily_digest:   "Alerts are accumulated and sent every day at the configured time.",
    weekly_digest:  "Alerts are accumulated and sent every week at the configured time."
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
        ? "The briefing will be sent once a week, on the configured day and time."
        : "The daily briefing will be sent every day at this time.";
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
      listEl.innerHTML = '<div class="ah-empty">No sent alert recorded.</div>';
      return;
    }

    const filtered = filter === "success" ? history.filter(e => e.success)
                   : filter === "error"   ? history.filter(e => !e.success)
                   : history;

    if (filtered.length === 0) {
      listEl.innerHTML = '<div class="ah-empty">No entry for this filter.</div>';
      return;
    }

    listEl.innerHTML = filtered.map(e => {
      const d  = new Date(e.sentAt);
      const ts = isNaN(d) ? (e.sentAt || "—")
        : `${d.toLocaleDateString("en-US", { day: "2-digit", month: "2-digit" })} ${d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}`;
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
    if (!confirm("Clear all alert history?")) return;
    AlertManager.clearAlertHistory();
    _renderAlertHistory("all");
    document.querySelectorAll(".ah-filter-btn").forEach(b =>
      b.classList.toggle("active", b.dataset.filter === "all"));
    UI.showToast("History cleared", "success");
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
    if (diff < 60_000)     return "just now";
    if (diff < 3_600_000)  return `${Math.floor(diff / 60_000)} min ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return `${Math.floor(diff / 86_400_000)}d ago`;
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

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION — Onglet Integrations (Jira)
  // ══════════════════════════════════════════════════════════════════════════

  function saveIntegrations() {
    if (typeof JiraConfig === 'undefined') return;
    const baseUrl    = (_val('jira-base-url')    || '').trim().replace(/\/+$/, '');
    const projectKey = (_val('jira-project-key') || '').trim().toUpperCase();
    JiraConfig.save({ baseUrl, projectKey });
    UI.showToast('🔗 Integrations saved', 'success');
  }

  // ══════════════════════════════════════════════════════════════════════════
  // SECTION — Trend Vision One Watchlist Sync
  // ══════════════════════════════════════════════════════════════════════════

  async function syncTV1Watchlist() {
    if (typeof TV1Sync === 'undefined') {
      UI.showToast('TV1 module not loaded', 'error');
      return;
    }

    // Persist the selected region
    const region = document.getElementById('tv1-region')?.value || 'us';
    TV1Sync.saveConfig({ region });

    const statusEl  = document.getElementById('tv1-sync-status');
    const previewEl = document.getElementById('tv1-preview');
    const btn       = document.getElementById('btn-tv1-sync');

    if (statusEl)  statusEl.textContent = '⏳ Fetching from TV1…';
    if (btn)       btn.disabled = true;
    if (previewEl) previewEl.style.display = 'none';

    try {
      const result = await TV1Sync.fetchPreview();
      if (statusEl) statusEl.textContent = '';

      if (!result.items?.length) {
        if (statusEl) statusEl.textContent = '⚠ No items returned from TV1.';
        if (btn) btn.disabled = false;
        return;
      }

      _renderTV1Preview(result, previewEl, btn);

    } catch (err) {
      if (statusEl) statusEl.textContent = `⚠ ${err.message}`;
      if (btn) btn.disabled = false;
    }
  }

  function _renderTV1Preview(result, container, triggerBtn) {
    if (!container) return;

    const isDemo  = result.source === 'tv1_demo';
    const typeIcon = { vendor: '🏢', product: '📦', technology: '⚙️', keyword: '🏷' };
    const _e = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    const existingValues = new Set(
      Contextualizer.getWatchlist().map(i => typeof i === 'string' ? i.toLowerCase() : (i.value || ''))
    );

    const itemsHTML = result.items.map(item => {
      const alreadyIn = existingValues.has(item.value);
      return `<div class="tv1-preview-item${alreadyIn ? ' tv1-preview-item-exists' : ''}">
        <span class="tv1-preview-type">${typeIcon[item.type] || '🏷'}</span>
        <span class="tv1-preview-label">${_e(item.label)}</span>
        ${alreadyIn ? '<span class="tv1-preview-exists-badge">already in watchlist</span>' : ''}
      </div>`;
    }).join('');

    const newCount = result.items.filter(i => !existingValues.has(i.value)).length;

    container.innerHTML = `
      <div class="tv1-preview-box">
        <div class="tv1-preview-header">
          ${isDemo
            ? '<span class="tv1-source-badge tv1-demo-badge">Demo data</span>'
            : '<span class="tv1-source-badge tv1-live-badge">● Live · Trend Vision One</span>'}
          <span class="tv1-preview-count">${result.items.length} items detected</span>
        </div>
        ${result._authWarning ? `<p class="settings-hint tv1-auth-warning">⚠ ${_e(result._authWarning)}</p>` : ''}
      ${result.note && !result._authWarning ? `<p class="settings-hint tv1-preview-note">${_e(result.note)}</p>` : ''}
        <div class="tv1-preview-list">${itemsHTML}</div>
        <div class="tv1-preview-actions">
          <button class="btn btn-primary" id="btn-tv1-confirm"
                  ${newCount === 0 ? 'disabled' : ''}>
            ✅ Import ${newCount} new item${newCount !== 1 ? 's' : ''} into watchlist
          </button>
          <button class="btn" id="btn-tv1-cancel">Cancel</button>
        </div>
      </div>`;

    container.style.display = 'block';

    document.getElementById('btn-tv1-confirm')?.addEventListener('click', () => {
      const stats = TV1Sync.syncFull(result);
      container.style.display = 'none';
      if (triggerBtn) triggerBtn.disabled = false;
      // Refresh last sync display
      const lastSyncEl = document.getElementById('tv1-last-sync');
      if (lastSyncEl && typeof TV1Sync !== 'undefined') {
        const tv1 = TV1Sync.loadConfig();
        if (tv1.lastSyncAt) {
          const d = new Date(tv1.lastSyncAt);
          const dateStr = d.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' });
          const srcLabel = tv1.lastSyncSource === 'tv1_live' ? 'live' : 'démo';
          const addedPart    = tv1.lastSyncAdded    > 0 ? ` · ${tv1.lastSyncAdded} ajouté(s)` : '';
          const disabledPart = tv1.lastSyncDisabled > 0 ? ` · ${tv1.lastSyncDisabled} désactivé(s)` : '';
          const resultIcon   = tv1.lastSyncResult === 'success' ? '✅' : tv1.lastSyncResult === 'demo' ? '🔵' : '⚠';
          lastSyncEl.textContent = `${resultIcon} Dernière sync : ${dateStr} (${srcLabel}${addedPart}${disabledPart})`;
        }
      }
      let msg = stats.added > 0
        ? `🔵 ${stats.added} item${stats.added !== 1 ? 's' : ''} ajouté(s) depuis TV1`
        : `ℹ Tous les items TV1 déjà présents`;
      if (stats.skipped)   msg += ` · ${stats.skipped} déjà présent(s)`;
      if (stats.disabled)  msg += ` · ${stats.disabled} désactivé(s) (obsolètes)`;
      UI.showToast(msg, stats.added > 0 ? 'success' : 'info');
    });

    document.getElementById('btn-tv1-cancel')?.addEventListener('click', () => {
      container.style.display = 'none';
      if (triggerBtn) triggerBtn.disabled = false;
    });
  }

  // ── Per-CVE VP status / toggle / test connection removed (2026-04) ──────────
  // TV1 public API does not expose an IPS rule catalog or CVE-to-rule mapping.
  // All candidate paths (/v3.0/ips/filters, /v3.0/ips/rules, etc.) return 404.
  // Global SWP posture (mode=swp) remains as a backend debug endpoint.

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
    addFeed, resetCustomFeeds, restoreDefaultFeeds, applyAndRefresh,
    // Integrations
    saveIntegrations,
    // TV1 Watchlist Sync
    syncTV1Watchlist,
    // TV1 VP toggle/test removed — per-CVE signal unsupported by TV1 API
  };
})();
