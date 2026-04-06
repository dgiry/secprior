// incident-panel.js — Panneau 🎯 Vue Incidents Consolidés (V1)
//
// Agrège les articles en incidents via Union-Find :
//   Phase 1 — CVE-based : articles partageant une CVE → même incident
//   Phase 2 — relatedArticles : liens calculés par deduplicator.js → même incident
//
// Aucun recalcul coûteux — réutilise les métadonnées déjà produites
// par le pipeline (cves, relatedArticles, vendors, isKEV, epssScore, …)
//
// Pattern identique à cve-panel.js et vendor-panel.js.

const IncidentPanel = (() => {

  let _articles      = [];        // dernière liste d'articles reçue
  let _filterBy      = "all";    // "all"|"multi"|"kev"|"watchlist"|"exploit"|"patch"|"high"|"ioc"|"prio"
  let _searchQuery   = "";       // filtre texte libre
  let _statusFilter  = "all";    // "all" | EntityStatus.VALID_STATUSES
  let _sortBy        = "default"; // "default" | "priority"
  let _lastIncidents = [];       // cache pour export IOC au clic
  let _remediationFilter = "all"; // "all"|"patch_available"|"virtual_patch"|"mitigation_only"|"no_patch"|"unknown"
  let _exploitationFilter = "all"; // "all"|"active_exploitation"|"kev"|"public_poc"|"campaign_activity"|"none"
  let _actionabilityFilter = "all"; // "all"|"with_ioc"|"patch_available"|"virtual_patch"|"mitigation_only"|"no_clear_action"
  let _recencyFilter = "all"; // "all"|"24h"|"72h"|"week"|"older"
  let _environmentFilter = "all"; // "all"|"watchlist"|"matches_you"|"exposed_vendor"|"no_environment_match"

  // ── Alias groups pour variantes de noms produit/technologie ────────────────
  // Ensemble intentionnellement petit d'alias haute-confiance.
  // Améliore la correspondance contextuelle sans basculer en fuzzy matching.
  // Appliqué UNIQUEMENT aux produits/technologies, non aux vendors.

  const PRODUCT_TECH_ALIASES = Object.freeze({
    // Productivité cloud Microsoft
    "office 365": ["office 365", "o365", "microsoft 365", "m365"],
    "o365": ["office 365", "o365", "microsoft 365", "m365"],
    "microsoft 365": ["office 365", "o365", "microsoft 365", "m365"],
    "m365": ["office 365", "o365", "microsoft 365", "m365"],

    // Identité Azure
    "azure ad": ["azure ad", "azure active directory", "entra id", "microsoft entra"],
    "azure active directory": ["azure ad", "azure active directory", "entra id", "microsoft entra"],
    "entra id": ["azure ad", "azure active directory", "entra id", "microsoft entra"],
    "microsoft entra": ["azure ad", "azure active directory", "entra id", "microsoft entra"],

    // Orchestration de conteneurs
    "kubernetes": ["kubernetes", "k8s"],
    "k8s": ["kubernetes", "k8s"],

    // Famille Windows Server (mapping précis uniquement)
    "windows server": ["windows server", "windows server 2016", "windows server 2019", "windows server 2022"],
    "windows server 2016": ["windows server", "windows server 2016", "windows server 2019", "windows server 2022"],
    "windows server 2019": ["windows server", "windows server 2016", "windows server 2019", "windows server 2022"],
    "windows server 2022": ["windows server", "windows server 2016", "windows server 2019", "windows server 2022"],
  });

  /**
   * Retourne tous les variants (alias) d'un nom produit/technologie.
   * Priorité : exact match d'abord, puis aliases du groupe.
   */
  function _getProductTechVariants(name) {
    const normalized = String(name).toLowerCase().trim();
    // Si le nom exact est dans les alias, retourner tous les variants du groupe
    if (PRODUCT_TECH_ALIASES[normalized]) {
      return PRODUCT_TECH_ALIASES[normalized];
    }
    // Sinon, retourner le nom seul (pas d'alias)
    return [normalized];
  }

  // ── Détermination du statut de remédiation (exclusive) ────────────────────
  // Priorité : no_patch > patch_available > virtual_patch > mitigation_only > unknown

  function _remediationStatus(incident) {
    const textAll = incident.articles.map(a => 
      ((a.title || "") + " " + (a.description || "")).toLowerCase()
    ).join(" ");

    // 1. no_patch — pas de correctif disponible
    if (/\b(no patch|no fix|not patched|unpatched|will not fix|won't fix|no solution|unavailable)\b/.test(textAll) ||
        /\b(no|not|un)\b.*\b(patch|fix|correctif)\b/.test(textAll) && !/\bfix(ed)?\b/.test(textAll)) {
      return "no_patch";
    }

    // 2. patch_available — correctif officiel disponible
    if (/\b(patch|hotfix|update|upgrade|fix|released|available|correctif)\b/.test(textAll) &&
        !/\b(no|not|un)\b.*\b(patch|fix|available)\b/.test(textAll)) {
      return "patch_available";
    }

    // 3. virtual_patch — mitigation technique (WAF, règles, etc.)
    if (/\b(virtual.?patch|mitigation|workaround|temporary fix|compensat|rule.?base|WAF|IPS.?(rule|signature))\b/.test(textAll)) {
      return "virtual_patch";
    }

    // 4. mitigation_only — seulement des mesures de mitigation
    if (/\b(mitigation|mitigate|mitigat(e|ion|ing)|workaround|compensat|reduce risk|limit exposure)\b/.test(textAll)) {
      return "mitigation_only";
    }

    // 5. unknown — impossible de déterminer
    return "unknown";
  }

  // ── Détermination du statut d'exploitation (exclusive) ────────────────────
  // Priorité : active_exploitation > kev > public_poc > campaign_activity > none
  // Retourne un seul état par incident basé sur les signaux disponibles.

  function _exploitationStatus(incident) {
    // 1. active_exploitation — exploitation active confirmée (KEV + angle exploitation)
    if (incident.kev && incident.angles.includes("exploitation")) {
      return "active_exploitation";
    }

    // 2. kev — CISA KEV confirmé (exploitation active mais pas d'angle exploitation dans les articles)
    if (incident.kev) {
      return "kev";
    }

    // 3. public_poc — PoC public disponible (angle PoC détecté)
    if (incident.angles.includes("poc")) {
      return "public_poc";
    }

    // 4. campaign_activity — activité de campagne/menace détectée (angle exploitation sans KEV)
    if (incident.angles.includes("exploitation")) {
      return "campaign_activity";
    }

    // 5. none — aucun signal d'exploitation
    return "none";
  }

  // ── Détermination du statut d'actionabilité (exclusive) ──────────────────
  // Priorité : with_ioc > patch_available > virtual_patch > mitigation_only > no_clear_action
  // Retourne un seul état par incident basé sur les signaux d'action disponibles.

  function _actionabilityStatus(incident) {
    // 1. with_ioc — incident a des IOCs extraits (action immédiate possible)
    if (incident.rawIocCount > 0) {
      return "with_ioc";
    }

    // 2. patch_available — correctif officiel disponible (action claire)
    const remStatus = _remediationStatus(incident);
    if (remStatus === "patch_available") {
      return "patch_available";
    }

    // 3. virtual_patch — mitigation technique disponible (action technique possible)
    if (remStatus === "virtual_patch") {
      return "virtual_patch";
    }

    // 4. mitigation_only — seulement des mesures de mitigation (action limitée)
    if (remStatus === "mitigation_only") {
      return "mitigation_only";
    }

    // 5. no_clear_action — aucune action claire identifiée
    return "no_clear_action";
  }

  // ── Détermination du statut de récence (exclusive) ────────────────────────
  // Priorité : 24h > 72h > week > older
  // Utilise lastSeen (timestamp le plus récent de l'incident)

  function _recencyStatus(incident) {
    if (!incident.lastSeen) return "older";

    const now = new Date();
    const lastSeenDate = new Date(incident.lastSeen);
    const diffMs = now - lastSeenDate;
    const diffHours = diffMs / (1000 * 60 * 60);
    const diffDays = diffHours / 24;

    // 1. < 24h — incident très récent
    if (diffHours < 24) {
      return "24h";
    }

    // 2. < 72h — incident récent (mais pas dans les 24h)
    if (diffDays < 3) {
      return "72h";
    }

    // 3. this_week — incident de cette semaine (mais pas dans les 72h)
    if (diffDays < 7) {
      return "week";
    }

    // 4. older — incident plus ancien que 7 jours
    return "older";
  }

  // ── Détermination du statut de contexte environnement (exclusive) ─────────
  // Priorité : watchlist > matches_you > exposed_vendor > no_environment_match
  // Réutilise les signaux existants pour déterminer la pertinence environnementale.

  function _environmentContextStatus(incident) {
    // 1. watchlist — incident a des correspondances explicites watchlist
    if (incident.watchlistHit && (incident.articles || []).some(a => a.watchlistMatches?.length > 0)) {
      return "watchlist";
    }

    // 2. matches_you — incident pertinent au profil actif (sans dupliquer Watchlist)
    // Signaux multiples pour meilleure contextualisation :
    //   - Correspondance vendor (vendor exact)
    //   - Correspondance produit/technologie (dans le texte des articles)
    // Résultat : moins axé sur le vendor seul, plus contextuel et granulaire.
    try {
      if (typeof ProfileManager !== "undefined") {
        const prof = ProfileManager.getActiveProfile();
        const items = prof?.watchlist || [];

        // Séparer les items suivis par type
        const tracked = {
          vendors: new Set(),
          products: new Set(),
          technologies: new Set()
        };
        items
          .filter(it => it && it.enabled !== false)
          .forEach(it => {
            const type = (it.type || "").toLowerCase();
            const value = String(it.value || "").toLowerCase();
            if (type === "vendor") tracked.vendors.add(value);
            else if (type === "product") tracked.products.add(value);
            else if (type === "technology") tracked.technologies.add(value);
          });

        const hasTrackedItems = tracked.vendors.size > 0 || tracked.products.size > 0 || tracked.technologies.size > 0;

        if (hasTrackedItems) {
          // Signal 1 : Correspondance vendor exacte (existant, mais maintenant contextuel)
          const incVendors = (incident.vendors || []).map(v => String(v).toLowerCase());
          if (incVendors.some(v => tracked.vendors.has(v))) {
            return "matches_you";
          }

          // Signal 2 : Correspondance produit/technologie dans le texte des articles
          // (Plus granulaire que le vendor seul, captures spécificité du produit/technologie)
          const articleText = (incident.articles || [])
            .map(a => ((a.title || "") + " " + (a.description || "")).toLowerCase())
            .join(" ");

          // Vérifier correspondance produits (ex: "Windows Server 2019", "Apache Log4j")
          // Avec support des alias pour variantes communes (ex: Office 365 / M365 / O365)
          if (tracked.products.size > 0) {
            for (const product of tracked.products) {
              // Obtenir tous les variants (alias) du produit
              const variants = _getProductTechVariants(product);
              for (const variant of variants) {
                // Utiliser des limites de mots pour éviter les faux positifs
                const wordBoundary = /\b/.test(variant.charAt(0)) ? "\\b" : "";
                const pattern = new RegExp(wordBoundary + variant.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + wordBoundary, "i");
                if (pattern.test(articleText)) {
                  return "matches_you";
                }
              }
            }
          }

          // Vérifier correspondance technologies (ex: "Kubernetes", "Docker", "SQL Server")
          // Avec support des alias pour variantes communes (ex: Kubernetes / K8s)
          if (tracked.technologies.size > 0) {
            for (const tech of tracked.technologies) {
              // Obtenir tous les variants (alias) de la technologie
              const variants = _getProductTechVariants(tech);
              for (const variant of variants) {
                // Limites de mots pour éviter faux positifs
                const wordBoundary = /\b/.test(variant.charAt(0)) ? "\\b" : "";
                const pattern = new RegExp(wordBoundary + variant.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + wordBoundary, "i");
                if (pattern.test(articleText)) {
                  return "matches_you";
                }
              }
            }
          }
        }
      }
    } catch { /* robuste si ProfileManager absent */ }

    // 3. exposed_vendor — incident implique un vendor/produit identifié comme exposé
    // Signal : présence de vendors + score élevé ou EPSS élevé indique exposition
    if ((incident.vendors || []).length > 0 &&
        ((incident.maxScore ?? 0) >= 70 || (incident.maxEpss ?? 0) >= 0.6)) {
      return "exposed_vendor";
    }

    // 4. no_environment_match — aucune correspondance environnementale identifiée
    return "no_environment_match";
  }

  // ── Vue par défaut — appliquée à chaque ouverture simple (sans contexte) ──
  //
  // Règle produit :
  //   • toggle() simple (clic bouton)   → _resetFilters() avant rendu → vue large
  //   • setFilters() depuis persona/preset → état filtré assumé, écrase le reset
  //   • saved-filter                    → toggle() puis setFilters() → filtré assumé
  //
  // Cela garantit qu'ouvrir l'onglet Incidents sans contexte spécial
  // affiche toujours tous les incidents sans filtre restrictif résiduel.

  const _DEFAULTS = Object.freeze({
    filterBy:    "all",
    searchQuery: "",
    statusFilter: "all",
    sortBy:      "default"
  });

  function _resetFilters() {
    _filterBy    = _DEFAULTS.filterBy;
    _searchQuery = _DEFAULTS.searchQuery;
    _statusFilter = _DEFAULTS.statusFilter;
    _sortBy      = _DEFAULTS.sortBy;
  }

  // ── Catégorisation d'angle (synchronisée avec cve-panel.js) ───────────────

  function _classifyAngle(a) {
    const text = ((a.title || "") + " " + (a.description || "")).toLowerCase();
    if (/\b(poc|proof.of.concept|proof of concept|working exploit|demo exploit)\b/.test(text))
      return "poc";
    if (/\b(exploit|actively exploit|in the wild|being exploit|mass exploit|ransomware|campaign|attack)\b/.test(text))
      return "exploitation";
    if (/\b(patch|fix|hotfix|update|upgrade|correc|mitigation|workaround|remediat)\b/.test(text))
      return "patch";
    if (/\b(advisory|warn|disclose|discloses|reveals|discover|found|announce|publishes|alert)\b/.test(text))
      return "advisory";
    return "news";
  }

  const _ANGLE_META = {
    poc:          { label: "PoC",      color: "#f85149", bg: "#2d1515" },
    exploitation: { label: "Exploit",  color: "#f85149", bg: "#2d1515" },
    patch:        { label: "Patch",    color: "#3fb950", bg: "#0d2818" },
    advisory:     { label: "Advisory", color: "#79c0ff", bg: "#0d1b2e" },
    news:         { label: "News",     color: "#8b949e", bg: "#21262d" }
  };

  function _dominantAngle(angles) {
    const order = ["exploitation", "poc", "patch", "advisory", "news"];
    return order.find(p => angles.includes(p)) || "news";
  }

  // ── Agrégation priorité incident ─────────────────────────────────────────
  // Remonte le niveau et le score les plus élevés parmi les articles de l'incident.
  // Tolère les articles anciens sans priorityLevel (ignorés dans l'agrégation).

  function _computeIncidentPriority(arts) {
    const LEVELS = ["critical_now", "investigate", "watch", "low"];
    const incidentPriorityScore = arts.reduce((m, a) => Math.max(m, a.priorityScore ?? 0), 0);
    let incidentPriorityLevel = "low";
    for (const lvl of LEVELS) {
      if (arts.some(a => a.priorityLevel === lvl)) { incidentPriorityLevel = lvl; break; }
    }
    const topArts = arts.filter(a => a.priorityLevel === incidentPriorityLevel);
    const priorityReasons = [...new Set(topArts.flatMap(a => a.priorityReasons || []))].slice(0, 4);
    return { incidentPriorityScore, incidentPriorityLevel, priorityReasons };
  }

  // ── Résumé lisible incident ───────────────────────────────────────────────
  // Phrase courte combinant l'angle dominant, les vendors/CVEs et les signaux clés.

  function _makeIncidentSummary(i) {
    const dominant  = _dominantAngle(i.angles);
    const ANGLE_TXT = {
      exploitation: "Active exploitation", poc: "PoC published",
      patch: "Patch available",            advisory: "Advisory", news: "Monitoring"
    };
    const parts = [];
    let lead = ANGLE_TXT[dominant] || "Incident";
    if (i.vendors.length) lead += ` — ${i.vendors.slice(0, 2).join(", ")}`;
    parts.push(lead);
    if (i.cves.length)
      parts.push(i.cves.slice(0, 2).join(" · ") + (i.cves.length > 2 ? ` +${i.cves.length - 2}` : ""));
    const sigs = [];
    if (i.kev)             sigs.push("KEV confirmed");
    if (i.watchlistHit)    sigs.push("Watchlist");
    if (i.maxEpss != null) sigs.push(`EPSS ${Math.round(i.maxEpss * 100)}%`);
    if (sigs.length) parts.push(sigs.join(", "));
    parts.push(
      `${i.articleCount} article${i.articleCount !== 1 ? "s" : ""}` +
      ` · ${i.sourceCount} source${i.sourceCount !== 1 ? "s" : ""}`
    );
    if (i.rawIocCount > 0) parts.push(`${i.rawIocCount} IOC`);
    return parts.join(" — ");
  }

  // ── Union-Find léger ──────────────────────────────────────────────────────

  function _makeUF(ids) {
    const p = new Map(ids.map(id => [id, id]));
    function find(id) {
      if (!p.has(id)) return id;
      if (p.get(id) !== id) p.set(id, find(p.get(id)));
      return p.get(id);
    }
    function union(a, b) {
      const ra = find(a), rb = find(b);
      if (ra !== rb) p.set(ra, rb);
    }
    return { find, union };
  }

  // ── Agrégation principale ─────────────────────────────────────────────────

  /**
   * buildIncidentIndex(articles) → Incident[]
   *
   * Regroupe les articles en incidents via deux signaux :
   *   1. CVE partagée       → forte confiance
   *   2. relatedArticles[]  → confiance deduplicator (same-cve-distinct-title, etc.)
   *
   * V1 prudente : on ne fusionne que sur signal explicite.
   * Les articles sans CVE ni lien restent des incidents solo.
   */
  function buildIncidentIndex(articles) {
    if (!articles.length) return [];

    const artMap = new Map(articles.map(a => [a.id, a]));
    const uf     = _makeUF(articles.map(a => a.id));

    // Phase 1 : Union par CVE partagée
    const cveFirst = new Map();
    articles.forEach(a => {
      (a.cveIds || a.cves || []).forEach(cve => {
        const key = cve.toUpperCase();
        if (cveFirst.has(key)) uf.union(a.id, cveFirst.get(key));
        else                   cveFirst.set(key, a.id);
      });
    });

    // Phase 2 : Union par relatedArticles (deduplicator.js)
    articles.forEach(a => {
      (a.relatedArticles || []).forEach(relId => {
        if (artMap.has(relId)) uf.union(a.id, relId);
      });
    });

    // Phase 3 : Union par vendor + attackTag dans une fenêtre de 7 jours
    // Cible : articles sans CVE couvrant la même surface d'attaque à courte distance.
    // Ex. : "Cisco — exploitation active" + "Patch Cisco Remote Exec." → même incident.
    // L'index est mis à jour vers l'article le plus récent pour permettre le chaînage.
    const vatIndex = new Map(); // "vendor|attacktag" → { id, date }
    articles.forEach(a => {
      if ((a.cveIds || a.cves || []).length > 0) return; // déjà traités en phase 1
      const aDate   = a.pubDate instanceof Date ? a.pubDate : new Date(a.pubDate || 0);
      const vendors = a.vendors || [];
      const attacks = (a.attackTags || []).map(t => t.label);
      vendors.forEach(v => {
        attacks.forEach(atk => {
          const key  = v.toLowerCase() + "|" + atk.toLowerCase();
          const prev = vatIndex.get(key);
          if (prev) {
            const diffDays = Math.abs(aDate - prev.date) / 86_400_000;
            if (diffDays <= 7) {
              uf.union(a.id, prev.id);
              // Avance l'index vers le plus récent pour permettre le chaînage
              if (aDate > prev.date) vatIndex.set(key, { id: a.id, date: aDate });
            }
            // Si > 7 jours : on ne fusionne pas mais on remplace l'index par cet article
            // pour ne pas bloquer les regroupements futurs sur la même clé
            else if (aDate > prev.date) {
              vatIndex.set(key, { id: a.id, date: aDate });
            }
          } else {
            vatIndex.set(key, { id: a.id, date: aDate });
          }
        });
      });
    });

    // Phase 4 : Grouper par racine Union-Find
    const groups = new Map();
    articles.forEach(a => {
      const root = uf.find(a.id);
      if (!groups.has(root)) groups.set(root, []);
      groups.get(root).push(a);
    });

    return [...groups.values()]
      .map(_makeIncident)
      .sort(_incidentSort);
  }

  function _makeIncident(arts) {
    // Timeline : plus récent en tête
    const sorted = [...arts].sort((a, b) => {
      const da = a.pubDate instanceof Date ? a.pubDate : new Date(a.pubDate || 0);
      const db = b.pubDate instanceof Date ? b.pubDate : new Date(b.pubDate || 0);
      return db - da;
    });

    const cves         = [...new Set(arts.flatMap(a => (a.cveIds || a.cves || []).map(c => c.toUpperCase())))];
    const vendors      = [...new Set(arts.flatMap(a => a.vendors || []))].slice(0, 5);
    const sources      = [...new Set(arts.map(a => a.sourceName || "?"))];
    const maxScore     = arts.reduce((m, a) => Math.max(m, a.score ?? 0), 0);
    const maxEpss      = arts.reduce((m, a) => a.epssScore != null && a.epssScore > (m ?? -1) ? a.epssScore : m, null);
    const kev          = arts.some(a => a.isKEV);
    const watchlistHit = arts.some(a => a.watchlistMatches?.length > 0);
    const trending     = arts.some(a => a.isTrending);
    const attackTags   = [...new Set(arts.flatMap(a => (a.attackTags || []).map(t => t.label)))];
    const angles       = [...new Set(arts.map(_classifyAngle))];

    const dates = arts
      .map(a => a.pubDate instanceof Date ? a.pubDate : (a.pubDate ? new Date(a.pubDate) : null))
      .filter(d => d && !isNaN(d));
    const firstSeen = dates.length ? new Date(Math.min(...dates.map(d => d.getTime()))).toISOString() : null;
    const lastSeen  = dates.length ? new Date(Math.max(...dates.map(d => d.getTime()))).toISOString() : null;

    const title = _makeTitle(cves, vendors, angles, sorted[0]);

    // ID stable : CVE principale, vendor+artKey, ou artKey seul.
    // Pour les incidents sans CVE, on inclut un fragment de l'ID du premier
    // article afin d'éviter les collisions entre plusieurs incidents sans CVE
    // survenus le même jour (ex. plusieurs CISA ICS advisories sans vendor).
    const artKey = sorted[0].id
      .replace(/[^a-z0-9]/gi, "").slice(-12) || "x";
    const baseKey = cves[0]
      || `${vendors[0] || artKey}-${(lastSeen || "").slice(0, 10)}`;
    const slug = baseKey
      .toLowerCase().replace(/[^a-z0-9]/g, "-").replace(/-+/g, "-").slice(0, 44);
    const incidentId = `inc_${slug}`;

    // Comptage brut des IOCs (somme articles, doublons possibles — utilisé pour filtre/badge)
    const rawIocCount = arts.reduce((n, a) => n + (a.iocCount || 0), 0);

    // Priorité agrégée + résumé lisible
    const { incidentPriorityScore, incidentPriorityLevel, priorityReasons } =
      _computeIncidentPriority(arts);

    const incident = {
      incidentId, title,
      articleCount: arts.length, sourceCount: sources.length,
      articles: sorted, cves, vendors, sources,
      maxScore, maxEpss, kev, watchlistHit, trending, attackTags, angles,
      firstSeen, lastSeen, rawIocCount,
      incidentPriorityScore, incidentPriorityLevel, priorityReasons
    };
    incident.summary = _makeIncidentSummary(incident);
    return incident;
  }

  function _makeTitle(cves, vendors, angles, primaryArticle) {
    const dominant = _dominantAngle(angles);
    const angleLabel = {
      exploitation: "active exploitation",
      poc:          "PoC published",
      patch:        "patch available",
      advisory:     "advisory"
    };

    if (cves.length > 0 && vendors.length > 0) return `${vendors[0]} — ${cves[0]}`;
    if (cves.length > 0) return cves.length > 1 ? `${cves[0]} +${cves.length - 1}` : cves[0];
    if (vendors.length > 0) {
      const suffix = dominant !== "news" ? ` — ${angleLabel[dominant] || dominant}` : "";
      return vendors.length > 1 ? `${vendors[0]} / ${vendors[1]}${suffix}` : `${vendors[0]}${suffix}`;
    }
    return (primaryArticle?.title || "Incident").slice(0, 70);
  }

  function _incidentSort(a, b) {
    if (a.kev !== b.kev)                   return a.kev ? -1 : 1;
    if (b.articleCount !== a.articleCount) return b.articleCount - a.articleCount;
    if (b.maxScore !== a.maxScore)         return b.maxScore - a.maxScore;
    return new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0);
  }

  // ── Helpers UI ────────────────────────────────────────────────────────────

  function _fmtDate(iso) {
    if (!iso) return "—";
    try { return new Date(iso).toLocaleDateString("en-US", { day: "2-digit", month: "2-digit" }); }
    catch { return "—"; }
  }

  function _fmtDateTime(pubDate) {
    const d = pubDate instanceof Date ? pubDate : (pubDate ? new Date(pubDate) : null);
    if (!d || isNaN(d)) return "—";
    return d.toLocaleDateString("en-US", { day: "2-digit", month: "2-digit" })
         + " " + d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
  }

  // ── Rendu ─────────────────────────────────────────────────────────────────

  function _render() {
    const list = document.getElementById("incident-list");
    if (!list) return;

    const allIncidents = buildIncidentIndex(_articles);
    _lastIncidents = allIncidents; // cache pour export IOC
    let incidents = [...allIncidents];

    // Filtre statut analyste
    if (typeof EntityStatus !== "undefined" && _statusFilter !== "all")
      incidents = EntityStatus.filterByStatus(incidents, "incident", _statusFilter, i => i.incidentId);

    // Filtres
    if (_filterBy === "multi")     incidents = incidents.filter(i => i.articleCount > 1);
    if (_filterBy === "kev")       incidents = incidents.filter(i => i.kev);
    if (_filterBy === "watchlist") incidents = incidents.filter(i => i.watchlistHit);
    if (_filterBy === "exploit")   incidents = incidents.filter(i => i.angles.includes("exploitation"));
    if (_filterBy === "high")      incidents = incidents.filter(i => i.maxScore >= 70);
    if (_filterBy === "ioc")       incidents = incidents.filter(i => i.rawIocCount > 0);
    if (_filterBy === "prio")      incidents = incidents.filter(i => i.incidentPriorityLevel === "critical_now");

    // Filtre remédiation (appliqué en AND avec les autres filtres)
    if (_remediationFilter !== "all") {
      incidents = incidents.filter(i => _remediationStatus(i) === _remediationFilter);
    }

    // Filtre exploitation (appliqué en AND avec les autres filtres)
    if (_exploitationFilter !== "all") {
      incidents = incidents.filter(i => _exploitationStatus(i) === _exploitationFilter);
    }

    // Filtre actionabilité (appliqué en AND avec les autres filtres)
    if (_actionabilityFilter !== "all") {
      incidents = incidents.filter(i => _actionabilityStatus(i) === _actionabilityFilter);
    }

    // Filtre récence (appliqué en AND avec les autres filtres)
    if (_recencyFilter !== "all") {
      incidents = incidents.filter(i => _recencyStatus(i) === _recencyFilter);
    }

    // Filtre contexte environnement (appliqué en AND avec les autres filtres)
    if (_environmentFilter !== "all") {
      incidents = incidents.filter(i => _environmentContextStatus(i) === _environmentFilter);
    }

    // Tri priorité
    if (_sortBy === "priority") {
      incidents = incidents.slice().sort((a, b) =>
        (b.incidentPriorityScore ?? 0) - (a.incidentPriorityScore ?? 0)
      );
    }

    // Filtre texte
    if (_searchQuery) {
      const q = _searchQuery.toLowerCase();
      incidents = incidents.filter(i =>
        i.title.toLowerCase().includes(q) ||
        i.cves.some(c  => c.toLowerCase().includes(q)) ||
        i.vendors.some(v => v.toLowerCase().includes(q)) ||
        i.articles.some(a => (a.title || "").toLowerCase().includes(q))
      );
    }

    // Meta
    const meta = document.getElementById("incident-meta");
    if (meta) {
      const kc = allIncidents.filter(i => i.kev).length;
      const multiCount = allIncidents.filter(i => i.articleCount > 1).length;
      meta.textContent = (incidents.length === allIncidents.length)
        ? `${allIncidents.length} incident${allIncidents.length !== 1 ? "s" : ""} · ${multiCount} multi-source · ${kc} KEV`
        : `${incidents.length} / ${allIncidents.length} incident${allIncidents.length !== 1 ? "s" : ""}`;
    }

    list.innerHTML = `
      ${_controlsHTML()}
      ${incidents.length === 0
        ? `<p class="ip-empty">No matching incident${_searchQuery ? ` for "${_searchQuery}"` : ""}.</p>`
        : `<table class="ip-table">
            <thead>
              <tr class="ip-thead">
                <th>Incident</th>
                <th class="ip-th-num">Art.</th>
                <th class="ip-th-num">Score</th>
                <th class="ip-th-num">EPSS</th>
                <th>Signals</th>
                <th>CVE / Angles</th>
                <th class="ip-th-num">Seen</th>
              </tr>
            </thead>
            <tbody>
              ${incidents.map(i => _rowHTML(i)).join("")}
            </tbody>
           </table>`
      }`;

    // Filtres
    list.querySelectorAll(".ip-filter-btn").forEach(btn => {
      btn.addEventListener("click", () => { _filterBy = btn.dataset.filter; _render(); });
    });

    // Tri
    list.querySelectorAll(".ip-sort-btn").forEach(btn => {
      btn.addEventListener("click", () => { _sortBy = btn.dataset.sort; _render(); });
    });

    // Filtres statut analyste
    list.querySelectorAll(".ip-status-btn").forEach(btn => {
      btn.addEventListener("click", () => { _statusFilter = btn.dataset.status; _render(); });
    });

    // Filtre Remediation — select
    list.querySelectorAll(".ip-remediation-select").forEach(sel => {
      sel.addEventListener("change", e => { _remediationFilter = e.target.value; _render(); });
    });

    // Filtre Exploitation — select
    list.querySelectorAll(".ip-exploitation-select").forEach(sel => {
      sel.addEventListener("change", e => { _exploitationFilter = e.target.value; _render(); });
    });

    // Filtre Actionability — select
    list.querySelectorAll(".ip-actionability-select").forEach(sel => {
      sel.addEventListener("change", e => { _actionabilityFilter = e.target.value; _render(); });
    });

    // Filtre Recency — select
    list.querySelectorAll(".ip-recency-select").forEach(sel => {
      sel.addEventListener("change", e => { _recencyFilter = e.target.value; _render(); });
    });

    // Filtre Environment — select
    list.querySelectorAll(".ip-environment-select").forEach(sel => {
      sel.addEventListener("change", e => { _environmentFilter = e.target.value; _render(); });
    });

    // Statut analyste — changement select (mise à jour badge ciblée, pas de re-render)
    if (typeof EntityStatus !== "undefined") {
      list.querySelectorAll(".es-block .es-select").forEach(sel => {
        sel.addEventListener("change", e => {
          const block   = e.target.closest(".es-block");
          const eid     = block.dataset.eid;
          const safeEid = block.dataset.safeEid;
          EntityStatus.setStatus("incident", eid, e.target.value);
          const slot = document.getElementById("es-slot-incident-" + safeEid);
          if (slot) slot.innerHTML = EntityStatus.badgeHTML("incident", eid);
        });
      });
      list.querySelectorAll(".es-block .es-note-input").forEach(inp => {
        inp.addEventListener("blur", e => {
          const block = e.target.closest(".es-block");
          EntityStatus.updateNote("incident", block.dataset.eid, e.target.value);
        });
        inp.addEventListener("keydown", e => { if (e.key === "Enter") e.target.blur(); });
      });
      list.querySelectorAll(".es-block .es-owner-input").forEach(inp => {
        inp.addEventListener("blur", e => {
          const block = e.target.closest(".es-block");
          EntityStatus.updateOwner("incident", block.dataset.eid, e.target.value);
        });
        inp.addEventListener("keydown", e => { if (e.key === "Enter") e.target.blur(); });
      });
    }

    // Recherche — restaure curseur (évite l'inversion de saisie)
    const searchInput = list.querySelector(".ip-search-input");
    if (searchInput) {
      searchInput.value = _searchQuery;
      searchInput.addEventListener("input", e => {
        const pos = e.target.selectionStart;
        _searchQuery = e.target.value;
        _render();
        requestAnimationFrame(() => {
          const inp = document.querySelector(".ip-search-input");
          if (inp) { inp.focus(); inp.setSelectionRange(pos, pos); }
        });
      });
    }

    // ── IOC — copier un indicateur individuel ───────────────────────────────
    list.querySelectorAll(".ioc-copy-one").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        if (typeof IOCUtils !== "undefined")
          IOCUtils.copyOne(btn.dataset.iocType, btn.dataset.iocVal);
      });
    });

    // ── IOC — copier un groupe ou tout copier ────────────────────────────────
    list.querySelectorAll(".ioc-copy-group, .ioc-copy-all").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        if (typeof IOCUtils === "undefined") return;
        const vals  = (btn.dataset.iocVals || "").split("||").filter(Boolean);
        const label = btn.dataset.iocLabel || "IOC";
        IOCUtils.copyGroup(label, vals);
      });
    });

    // ── IOC — export JSON / TXT ──────────────────────────────────────────────
    list.querySelectorAll(".ioc-export-json, .ioc-export-txt").forEach(btn => {
      btn.addEventListener("click", e => {
        e.stopPropagation();
        if (typeof IOCUtils === "undefined") return;
        const iid      = btn.dataset.iid;
        const incident = _lastIncidents.find(i => i.incidentId === iid);
        if (!incident) return;
        const iocs = IOCUtils.aggregateIOCs(incident.articles);
        const fmt  = btn.classList.contains("ioc-export-json") ? "json" : "txt";
        IOCUtils.exportIOC(iocs, fmt, incident.title);
      });
    });

    // ── Actions rapides — résumés analyste / exécutif / export JSON ────────
    if (typeof QuickActions !== "undefined")
      QuickActions.bindIncidentPanel(list, _lastIncidents);

    // Toggle détail sur clic ligne
    list.querySelectorAll(".ip-row").forEach(row => {
      row.addEventListener("click", () => {
        const iid    = row.dataset.iid;
        const detail = document.getElementById(`ip-detail-${iid}`);
        if (!detail) return;
        const isOpen = detail.style.display !== "none";
        list.querySelectorAll(".ip-detail-row").forEach(d => { d.style.display = "none"; });
        list.querySelectorAll(".ip-row").forEach(r => r.classList.remove("ip-row-open"));
        if (!isOpen) {
          detail.style.display = "table-row";
          row.classList.add("ip-row-open");
        }
      });
    });
  }

  function _controlsHTML() {
    const f  = _filterBy;
    const sf = _statusFilter;
    const rf = _remediationFilter;
    const ef = _exploitationFilter;
    const af = _actionabilityFilter;
    const recf = _recencyFilter;
    const envf = _environmentFilter;

    let statusBarHTML = "";
    if (typeof EntityStatus !== "undefined") {
      const btns = ["all", ...EntityStatus.VALID_STATUSES].map(s => {
        const m     = EntityStatus.STATUS_META[s];
        const label = s === "all" ? "All statuses" : m.emoji + "\u00a0" + m.label;
        return `<button class="ip-status-btn${sf === s ? " active" : ""}" data-status="${s}">${label}</button>`;
      }).join("");
      statusBarHTML = `<div class="ip-status-bar">${btns}</div>`;
    }

    const critCount = _lastIncidents.filter(i => i.incidentPriorityLevel === "critical_now").length;
    const iocCount  = _lastIncidents.filter(i => i.rawIocCount > 0).length;

    // Options du select Remediation
    const remediationOptions = [
      { value: "all", label: "Remediation" },
      { value: "no_patch", label: "No patch" },
      { value: "patch_available", label: "Patch available" },
      { value: "virtual_patch", label: "Virtual patch" },
      { value: "mitigation_only", label: "Mitigation only" },
      { value: "unknown", label: "Unknown" }
    ].map(o => `<option value="${o.value}"${rf === o.value ? " selected" : ""}>${o.label}</option>`).join("");

    // Options du select Exploitation
    const exploitationOptions = [
      { value: "all", label: "Exploitation" },
      { value: "active_exploitation", label: "🔴 Active exploitation" },
      { value: "kev", label: "🟠 KEV" },
      { value: "public_poc", label: "🟡 Public PoC" },
      { value: "campaign_activity", label: "🔵 Campaign / threat activity" },
      { value: "none", label: "⚪ No exploitation signal" }
    ].map(o => `<option value="${o.value}"${ef === o.value ? " selected" : ""}>${o.label}</option>`).join("");

    // Options du select Actionability
    const actionabilityOptions = [
      { value: "all", label: "Actionability" },
      { value: "with_ioc", label: "With IOC" },
      { value: "patch_available", label: "Patch available" },
      { value: "virtual_patch", label: "Virtual patch" },
      { value: "mitigation_only", label: "Mitigation only" },
      { value: "no_clear_action", label: "No clear action" }
    ].map(o => `<option value="${o.value}"${af === o.value ? " selected" : ""}>${o.label}</option>`).join("");

    // Options du select Recency
    const recencyOptions = [
      { value: "all", label: "Recency" },
      { value: "24h", label: "< 24h" },
      { value: "72h", label: "< 72h" },
      { value: "week", label: "This week" },
      { value: "older", label: "Older" }
    ].map(o => `<option value="${o.value}"${recf === o.value ? " selected" : ""}>${o.label}</option>`).join("");

    // Options du select Environment
    const environmentOptions = [
      { value: "all", label: "Environment" },
      { value: "watchlist", label: "Watchlist" },
      { value: "matches_you", label: "Matches you" },
      { value: "exposed_vendor", label: "Exposed vendor" },
      { value: "no_environment_match", label: "No environment match" }
    ].map(o => `<option value="${o.value}"${envf === o.value ? " selected" : ""}>${o.label}</option>`).join("");

    return `
      <div class="ip-controls">
        <div class="ip-search-bar">
          <input type="search" class="ip-search-input"
                 placeholder="🔎 Search incident, CVE, vendor, product..."
                 value='${(_searchQuery || "").replace(/'/g, "")}'>
        </div>
        <div class="ip-filter-bar">
          <button class="ip-filter-btn${f==="all"       ?" active":""}" data-filter="all">All</button>
          <button class="ip-filter-btn${f==="prio"      ?" active":""}" data-filter="prio">🔴 Critical${critCount ? ` (${critCount})` : ""}</button>
          <button class="ip-filter-btn${f==="multi"     ?" active":""}" data-filter="multi">📎 Multi-source</button>
          <button class="ip-filter-btn${f==="kev"       ?" active":""}" data-filter="kev">🚨 KEV</button>
          <button class="ip-filter-btn${f==="watchlist" ?" active":""}" data-filter="watchlist">👁 Watchlist</button>
          <button class="ip-filter-btn${f==="exploit"   ?" active":""}" data-filter="exploit">💀 Exploit</button>
          <button class="ip-filter-btn${f==="high"      ?" active":""}" data-filter="high">📊 Score ≥ 70</button>
          <button class="ip-filter-btn${f==="ioc"       ?" active":""}" data-filter="ioc">🔗 With IOC${iocCount ? ` (${iocCount})` : ""}</button>
          <select class="ip-remediation-select">${remediationOptions}</select>
          <select class="ip-exploitation-select">${exploitationOptions}</select>
          <select class="ip-actionability-select">${actionabilityOptions}</select>
          <select class="ip-recency-select">${recencyOptions}</select>
          <select class="ip-environment-select">${environmentOptions}</select>
        </div>
        <div class="ip-sort-bar">
          <span class="ip-dim ip-sort-label">Sort:</span>
          <button class="ip-sort-btn${_sortBy==="default"  ?" active":""}" data-sort="default">📅 Default</button>
          <button class="ip-sort-btn${_sortBy==="priority" ?" active":""}" data-sort="priority">🔺 Priority</button>
        </div>
        ${statusBarHTML}
      </div>`;
  }

  function _rowHTML(i) {
    const safeId   = i.incidentId.replace(/[^a-z0-9\-_]/g, "-");
    const epssStr  = i.maxEpss != null ? `${Math.round(i.maxEpss * 100)}%` : "—";
    const scoreStr = i.maxScore > 0    ? i.maxScore : "—";

    // Agrégation dédupliquée (une seule fois — sert au badge + au détail)
    let iocTotal   = 0;
    let iocSection = "";
    if (typeof IOCUtils !== "undefined") {
      const iocs = IOCUtils.aggregateIOCs(i.articles);
      iocTotal   = IOCUtils.total(iocs);
      iocSection = iocTotal > 0
        ? IOCUtils.iocBlockHTML(iocs, i.incidentId)
        : `<p class="ip-ioc-empty">🔗 No IOC detected for this incident.</p>`;
    }

    const signals = [
      i.kev          ? `<span class="ip-badge ip-kev">🚨 KEV</span>`              : "",
      i.watchlistHit ? `<span class="ip-badge ip-wl">👁 WL</span>`               : "",
      i.trending     ? `<span class="ip-badge ip-tr">🔥</span>`                   : "",
      iocTotal > 0   ? `<span class="ip-badge ip-ioc">🔗 ${iocTotal} IOC</span>` : ""
    ].filter(Boolean).join(" ");

    const cveHTML = i.cves.slice(0, 2).map(c =>
      `<code class="ip-cve-code">${c}</code>`).join(" ")
      + (i.cves.length > 2 ? ` <span class="ip-dim">+${i.cves.length - 2}</span>` : "");

    const anglesHTML = i.angles
      .filter(g => g !== "news" || i.angles.length === 1).slice(0, 3)
      .map(g => {
        const m = _ANGLE_META[g];
        return `<span class="ip-badge" style="color:${m.color};background:${m.bg}">${m.label}</span>`;
      }).join(" ");

    const cveCellHTML = [cveHTML, anglesHTML].filter(Boolean).join(" ");

    // Ligne de priorité (uniquement si non-low et données disponibles)
    const _pm = typeof getPriorityMeta === "function"
      ? getPriorityMeta(i.incidentPriorityLevel)
      : { icon: "⚪", label: i.incidentPriorityLevel || "—", css: "low" };
    // Afficher jusqu'à 2 raisons dans la ligne de résumé de la rangée incident.
    // Le détail complet (Why / Key signals / Focus) reste dans _reasoningBlockHTML().
    const prioLine = (i.incidentPriorityLevel && i.incidentPriorityLevel !== "low")
      ? `<div class="ip-prio-line prio-${_pm.css}">${_pm.icon} <strong>${_pm.label}</strong>${
          i.incidentPriorityScore > 0
            ? ` <span class="ip-prio-score">${i.incidentPriorityScore} pts</span>` : ""
        }${
          i.priorityReasons.slice(0, 2).map((r, idx) =>
            ` · <span class="ip-prio-reason${idx > 0 ? " ip-prio-reason-dim" : ""}">${r}</span>`
          ).join("")
        }</div>`
      : "";

    return `
      <tr class="ip-row" data-iid="${safeId}" title="Click to see timeline">
        <td class="ip-title-cell">
          <span id="es-slot-incident-${safeId}" class="es-badge-slot">${typeof EntityStatus !== "undefined" ? EntityStatus.badgeHTML("incident", i.incidentId) : ""}</span>
          ${prioLine}
          <span class="ip-title">${i.title}</span>
          ${i.vendors.length
            ? `<span class="ip-dim ip-vendors-sub">${i.vendors.slice(0, 3).join(" · ")}</span>` : ""}
        </td>
        <td class="ip-num">${i.articleCount}</td>
        <td class="ip-num">${scoreStr}</td>
        <td class="ip-num">${epssStr}</td>
        <td>${signals || '<span class="ip-dim">—</span>'}</td>
        <td class="ip-cve-cell">${cveCellHTML || '<span class="ip-dim">—</span>'}</td>
        <td class="ip-num ip-dim">${_fmtDate(i.lastSeen)}</td>
      </tr>
      <tr class="ip-detail-row" id="ip-detail-${safeId}" style="display:none">
        <td colspan="7">
          <div class="ip-detail-inner">
            ${_detailHeaderHTML(i)}
            ${typeof QuickActions !== "undefined" ? QuickActions.incidentButtonsHTML(i.incidentId) : ""}
            ${typeof Recommender !== "undefined" ? Recommender.renderHTML(i, 'incident') : ""}
            ${typeof EntityStatus !== "undefined" ? EntityStatus.statusBlockHTML("incident", i.incidentId) : ""}
            ${iocSection}
            <div class="ip-timeline">
              ${i.articles.map(a => _timelineRowHTML(a)).join("")}
            </div>
          </div>
        </td>
      </tr>`;
  }

  // ── Compact reasoning block — Why / Signals / Focus ─────────────────────
  function _reasoningBlockHTML(i) {

    // Section 1: Why this matters — use priorityReasons[] or derive from signals
    let reasons = (i.priorityReasons || []).slice(0, 4);
    if (!reasons.length) {
      if (i.kev)
        reasons.push("Active exploitation confirmed (CISA KEV)");
      if (i.maxEpss != null && i.maxEpss >= 0.70)
        reasons.push(`EPSS ${Math.round(i.maxEpss * 100)}% — high exploitation probability`);
      else if (i.maxEpss != null && i.maxEpss >= 0.40)
        reasons.push(`EPSS ${Math.round(i.maxEpss * 100)}% — moderate exploitation probability`);
      if (i.watchlistHit)
        reasons.push("Matches asset watchlist");
      if (i.sourceCount >= 3)
        reasons.push(`Confirmed by ${i.sourceCount} independent sources`);
      if (i.attackTags && i.attackTags.length)
        reasons.push(`ATT&CK: ${i.attackTags.slice(0, 2).join(", ")}`);
      if (!reasons.length && i.cves.length)
        reasons.push("CVE identified — assess exposure");
      if (!reasons.length)
        reasons.push("Signal detected — monitor for updates");
    }
    const whyHTML = reasons
      .map(r => `<span class="ip-rsn-why-item">${r}</span>`)
      .join("");

    // Section 2: Key signals — compact badge row
    const signalTags = [
      i.kev
        ? `<span class="ip-badge ip-kev">🚨 KEV</span>` : "",
      i.maxEpss != null
        ? `<span class="ip-badge ip-epss">EPSS ${Math.round(i.maxEpss * 100)}%</span>` : "",
      i.watchlistHit
        ? `<span class="ip-badge ip-wl">👁 WL</span>` : "",
      i.maxScore > 0
        ? `<span class="ip-badge ip-rsn-score">⚡ ${i.maxScore}</span>` : "",
      ...i.cves.slice(0, 2).map(c => `<code class="ip-cve-code">${c}</code>`),
      i.cves.length > 2
        ? `<span class="ip-dim">+${i.cves.length - 2}</span>` : "",
      `<span class="ip-rsn-src">${i.sourceCount} src · ${i.articleCount} art.</span>`
    ].filter(Boolean).join(" ");

    // Section 3: Recommended focus — deterministic 1-sentence from signals
    const lv = i.incidentPriorityLevel;
    let focus;
    if (i.kev) {
      focus = "Verify exposure immediately and apply the vendor patch — active exploitation confirmed (CISA KEV).";
    } else if (lv === "critical_now" && i.maxEpss != null && i.maxEpss >= 0.7) {
      focus = "Prioritize patching within 24h — high exploitation probability confirmed by score and EPSS.";
    } else if (lv === "critical_now" && i.watchlistHit) {
      focus = "Investigate watchlisted assets immediately — elevated risk confirmed across multiple signals.";
    } else if (lv === "critical_now") {
      focus = "Escalate to infrastructure team and confirm patch availability.";
    } else if (lv === "investigate" && i.watchlistHit) {
      focus = "Investigate exposure on watchlisted assets and confirm scope before next patch cycle.";
    } else if (lv === "investigate") {
      focus = "Assign for investigation — assess exposed systems and confirm scope.";
    } else if (lv === "watch") {
      focus = "Monitor for updates and enrich with additional context.";
    } else {
      focus = "Track in standard reporting cycle.";
    }

    return `
    <div class="ip-reasoning">
      <div class="ip-rsn-row">
        <span class="ip-rsn-lbl">Why this matters</span>
        <div class="ip-rsn-why">${whyHTML}</div>
      </div>
      <div class="ip-rsn-row">
        <span class="ip-rsn-lbl">Key signals</span>
        <div class="ip-rsn-tags">${signalTags}</div>
      </div>
      <div class="ip-rsn-row">
        <span class="ip-rsn-lbl">Recommended focus</span>
        <span class="ip-rsn-focus">${focus}</span>
      </div>
    </div>`;
  }

  function _detailHeaderHTML(i) {
    const pm = typeof getPriorityMeta === "function"
      ? getPriorityMeta(i.incidentPriorityLevel)
      : { icon: "⚪", label: "—", css: "low" };

    // Priority anchor — level + score (reasons now live in the reasoning block)
    const prioHeader = `
      <div class="ip-prio-header prio-${pm.css}">
        <span class="ip-prio-badge">${pm.icon} <strong>${pm.label}</strong></span>
        ${i.incidentPriorityScore > 0
          ? `<span class="ip-dim ip-prio-pts">Score&nbsp;${i.incidentPriorityScore}&nbsp;pts</span>` : ""}
      </div>`;

    // Readable summary
    const summaryLine = i.summary
      ? `<p class="ip-summary">${i.summary}</p>` : "";

    return `${prioHeader}${summaryLine}${_reasoningBlockHTML(i)}`;
  }

  function _timelineRowHTML(a) {
    const angle = _classifyAngle(a);
    const m     = _ANGLE_META[angle];
    const criBadge = a.criticality === "high"
      ? `<span style="color:#f85149">🔴</span>`
      : `<span style="color:#f0883e">🟠</span>`;

    const badges = [
      `<span class="ip-badge" style="color:${m.color};background:${m.bg};min-width:4.2rem;text-align:center">${m.label}</span>`,
      a.isKEV                        ? `<span class="ip-badge ip-kev">KEV</span>`  : "",
      a.epssScore != null            ? `<span class="ip-badge ip-epss">EPSS ${Math.round(a.epssScore * 100)}%</span>` : "",
      a.watchlistMatches?.length > 0 ? `<span class="ip-badge ip-wl">WL</span>`   : "",
      (a.score ?? 0) > 0             ? `<span class="ip-badge ip-score">⚡${a.score}</span>` : ""
    ].filter(Boolean).join(" ");

    const href = a.link ? `href="${a.link}" target="_blank" rel="noopener noreferrer"` : "";

    return `
      <div class="ip-tl-row">
        <span class="ip-tl-date ip-dim">${_fmtDateTime(a.pubDate)}</span>
        <span class="ip-tl-cri">${criBadge}</span>
        <span class="ip-tl-src ip-dim">${a.sourceName || "?"}</span>
        <span class="ip-tl-badges">${badges}</span>
        <a ${href} class="ip-tl-title">${a.title || "(no title)"}</a>
      </div>`;
  }

  // ── API publique ──────────────────────────────────────────────────────────

  function init() {
    document.getElementById("btn-incidents")?.addEventListener("click", toggle);
  }

  function toggle() {
    const panel = document.getElementById("incident-panel");
    const btn   = document.getElementById("btn-incidents");
    if (!panel) return;
    const nowVisible = panel.style.display === "none";
    panel.style.display = nowVisible ? "block" : "none";
    btn?.classList.toggle("active", nowVisible);
    if (nowVisible) {
      // Vue large par défaut à chaque ouverture sans contexte explicite.
      // Si une persona ou un saved-filter appelle setFilters() juste après,
      // celui-ci écrase cet état et re-rend avec les filtres assumés.
      _resetFilters();
      _render();
    }
  }

  function update(articles) {
    _articles = articles;
    const panel = document.getElementById("incident-panel");
    if (panel?.style.display !== "none") _render();
  }

  // ── API publique filtres (pour SavedFilters) ──────────────────────────────
  function getFilters() {
    return { filterBy: _filterBy, searchQuery: _searchQuery, statusFilter: _statusFilter, sortBy: _sortBy };
  }
  function setFilters(f) {
    if (f.filterBy     !== undefined) _filterBy     = f.filterBy;
    if (f.searchQuery  !== undefined) _searchQuery  = f.searchQuery;
    if (f.statusFilter !== undefined) _statusFilter = f.statusFilter;
    if (f.sortBy       !== undefined) _sortBy       = f.sortBy;
    // Re-rendre seulement si le panneau est ouvert (persona/saved-filter ouvrent le
    // panneau via toggle() avant d'appeler setFilters(), donc il sera visible ici).
    const panel = document.getElementById("incident-panel");
    if (panel && panel.style.display !== "none") _render();
  }

  // ── Statistiques de signal (pour Ops panel) ───────────────────────────────
  // Retourne les comptages d'incidents par statut de contexte environnement.
  // Utile pour valider la pertinence contextuelle en temps réel.
  function getEnvironmentContextStats() {
    const stats = {
      watchlist: 0,
      matches_you: 0,
      exposed_vendor: 0,
      no_environment_match: 0
    };

    // Compter les incidents par statut de contexte
    (_lastIncidents || []).forEach(incident => {
      const status = _environmentContextStatus(incident);
      if (status in stats) stats[status]++;
    });

    return stats;
  }

  return { init, toggle, update, buildIncidentIndex, getFilters, setFilters, getEnvironmentContextStats };
})();
