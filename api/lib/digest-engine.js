// api/lib/digest-engine.js — Moteur de génération du briefing (Node.js, sans DOM)
//
// Port côté serveur de la logique présente dans :
//   • js/scorer.js       → digestPriorityScore()
//   • js/email-alerts.js → selectTopArticles(), formatBriefingHTML/Text(), helpers
//
// Toute modification du template ou du scoring doit être répercutée ici ET côté front.

"use strict";

// ── Score de priorité digest ──────────────────────────────────────────────────

/**
 * Calcule un score de priorité pour le tri du briefing.
 * Identique à digestPriorityScore() dans scorer.js.
 * @returns {{ score, base, bonus, breakdown }}
 */
function digestPriorityScore(article) {
  const base = article.score ?? 50; // score composite déjà calculé ou défaut 50

  const bd = {};
  bd.watchlist = Math.min((Array.isArray(article.watchlistMatches) ? article.watchlistMatches.length : 0) * 25, 75);
  bd.kev       = article.isKEV ? 50 : 0;
  const epss   = article.epssScore ?? null;
  bd.epss      = epss != null ? (epss >= 0.70 ? 35 : epss >= 0.40 ? 15 : 0) : 0;
  // CVSS — signal fort quand extrait par enricher.js (regex ou NVD futur)
  const cvss   = article.cvssScore ?? null;
  bd.cvss      = cvss != null ? (cvss >= 9 ? 30 : cvss >= 7 ? 15 : cvss >= 4 ? 5 : 0) : 0;
  bd.trending  = article.isTrending ? 20 : 0;
  bd.sources   = Math.min(((article.sourceCount || 1) - 1) * 5, 20);
  bd.zeroDay   = /zero.?day|0.?day/i.test(article.title || "") ? 30 : 0;

  const bonus = Object.values(bd).reduce((s, v) => s + v, 0);
  return { score: base + bonus, base, bonus, breakdown: bd };
}

// ── Sélection des top articles ────────────────────────────────────────────────

/**
 * Sélectionne les 3–5 articles les plus critiques via digestPriorityScore.
 * Identique à _selectTopArticles() dans email-alerts.js.
 */
function selectTopArticles(queue, max = 5) {
  const scored = queue.map(a => ({ ...a, _p: digestPriorityScore(a).score }));
  scored.sort((a, b) => b._p - a._p);
  return scored.slice(0, Math.max(3, Math.min(max, scored.length)));
}

// ── Helpers d'analyse (miroir de email-alerts.js) ────────────────────────────

function _whyImportant(a) {
  const r = [];
  if (a.isKEV)
    r.push("activement exploitée dans la nature (CISA KEV)");
  if (a.epssScore != null && a.epssScore >= 0.70)
    r.push(`à très haute probabilité d'exploitation (EPSS ${Math.round(a.epssScore * 100)} %)`);
  else if (a.epssScore != null && a.epssScore >= 0.40)
    r.push(`à risque d'exploitation modéré (EPSS ${Math.round(a.epssScore * 100)} %)`);
  if (a.cvssScore != null && a.cvssScore >= 9.0)
    r.push(`de score CVSS ${a.cvssScore} (critique)`);
  else if (a.cvssScore != null && a.cvssScore >= 7.0)
    r.push(`de score CVSS ${a.cvssScore}`);
  else if (a.score != null && a.score >= 90) r.push("de criticité maximale");
  else if (a.score != null && a.score >= 80) r.push("de très haute criticité");
  if (a.isTrending)     r.push("en forte circulation sur les plateformes de threat intel");
  if (a.cveIds?.length) r.push(`référencée sous ${a.cveIds.slice(0, 2).join(", ")}`);
  if (r.length === 0)
    return a.criticality === "high"
      ? "Classée haute criticité par l'analyse automatique."
      : "Identifiée comme menace potentielle.";
  return "Cette vulnérabilité est " + r.join(", ") + ".";
}

function _affectedProducts(a) {
  return a.tags?.length ? a.tags.slice(0, 4).join(" · ") : a.sourceName;
}

function _watchpoints(a) {
  const pts = [];
  if (a.isKEV)
    pts.push("Appliquer les correctifs en urgence (délai CISA : 3 semaines)");
  if (a.epssScore != null && a.epssScore >= 0.70)
    pts.push("Surveiller les logs d'exploitation sur les systèmes exposés");
  if (a.cvssScore != null && a.cvssScore >= 9.0 && !a.isKEV)
    pts.push(`Score CVSS ${a.cvssScore} — évaluer et réduire la fenêtre d'exposition immédiatement`);
  if (pts.length === 0 && a.criticality === "high")
    pts.push("Vérifier l'exposition de vos actifs concernés");
  if (a.isTrending)
    pts.push("Consulter les IoCs publiés par la communauté threat intel");
  if (a.cveIds?.length)
    pts.push(`Vérifier le statut de patch pour ${a.cveIds[0]}`);
  if (pts.length === 0)
    pts.push("Surveiller l'évolution et appliquer les recommandations du fournisseur");
  return pts;
}

// ── Formatage HTML ────────────────────────────────────────────────────────────

/**
 * Génère l'email HTML du briefing matinal.
 * Identique à _formatBriefingHTML() dans email-alerts.js.
 */
function formatBriefingHTML(top, rest, label) {
  const now = new Date().toLocaleDateString("fr-FR",
    { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  const total     = top.length + rest.length;
  const kevCount  = [...top, ...rest].filter(a => a.isKEV).length;
  const highCount = [...top, ...rest].filter(a => a.criticality === "high").length;

  let exec = `${total} menace(s) détectée(s) durant cette période`;
  if (kevCount  > 0) exec += `, dont ${kevCount} vulnérabilité(s) KEV activement exploitée(s)`;
  if (highCount > 0) exec += `. ${highCount} alerte(s) haute criticité nécessitent votre attention`;
  exec += ".";

  const topHTML = top.map(a => {
    const color = a.criticality === "high" ? "#f85149" : "#f0883e";
    const badge = a.criticality === "high" ? "🔴 HAUTE" : "🟠 MOYENNE";
    const meta  = [
      a.isKEV             ? "🚨 KEV ACTIF"                              : "",
      a.epssScore != null ? `EPSS ${Math.round(a.epssScore * 100)} %`  : "",
      a.score     != null ? `Score ${a.score}`                          : ""
    ].filter(Boolean).join(" · ");
    const pts = _watchpoints(a).map(p => `<li style="margin:4px 0;color:#e6edf3">${p}</li>`).join("");

    return `
      <div style="border:1px solid ${color};border-radius:8px;padding:16px;margin-bottom:16px;background:#161b22">
        <div style="margin-bottom:8px;overflow:hidden">
          <span style="color:#8b949e;font-size:12px;float:right">${a.sourceName}</span>
          <span style="color:${color};font-weight:700;font-size:13px">${badge}</span>
          ${meta ? `<span style="color:#8b949e;font-size:12px"> · ${meta}</span>` : ""}
        </div>
        <h3 style="margin:0 0 8px;font-size:15px;line-height:1.4;word-break:break-word">
          <a href="${a.link}" style="color:#58a6ff;text-decoration:none">${a.title}</a>
        </h3>
        <p style="margin:0 0 8px;font-size:12px;color:#8b949e">🏷️ ${_affectedProducts(a)}</p>
        <p style="margin:0 0 12px;font-size:13px;color:#cdd9e5;background:#0d1117;
                  padding:10px;border-radius:4px;border-left:3px solid ${color}">
          📌 <strong>Pourquoi c'est important :</strong> ${_whyImportant(a)}
        </p>
        <div style="font-size:12px">
          <p style="margin:0 0 6px;color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.5px">⚡ Watchpoints immédiats</p>
          <ul style="margin:0;padding-left:16px">${pts}</ul>
        </div>
      </div>`;
  }).join("");

  const restHTML = rest.length === 0 ? "" : `
    <h3 style="color:#8b949e;font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin:24px 0 12px">
      📋 Autres alertes (${rest.length})
    </h3>
    <table style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace">
      <tbody>
        ${rest.map(a => {
          const c = a.criticality === "high" ? "#f85149" : "#f0883e";
          const b = a.criticality === "high" ? "🔴" : "🟠";
          return `<tr>
            <td style="padding:5px 8px;border-bottom:1px solid #21262d;color:${c};white-space:nowrap">${b} ${(a.criticality||"").toUpperCase()}</td>
            <td style="padding:5px 8px;border-bottom:1px solid #21262d;color:#8b949e">${a.sourceName}</td>
            <td style="padding:5px 8px;border-bottom:1px solid #21262d;word-break:break-word">
              <a href="${a.link}" style="color:#58a6ff;text-decoration:none">${a.title}</a>
            </td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>`;

  return `
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
                background:#0d1117;color:#e6edf3;padding:24px;border-radius:10px;max-width:680px;margin:0 auto">
      <div style="border-bottom:1px solid #30363d;padding-bottom:16px;margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:20px;color:#e6edf3">☀️ Briefing Cybersécurité — ${now}</h1>
        <p style="margin:0;color:#8b949e;font-size:13px">CyberVeille Pro · Digest ${label}</p>
      </div>
      <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;margin-bottom:24px">
        <p style="margin:0 0 4px;color:#8b949e;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px">RÉSUMÉ EXÉCUTIF</p>
        <p style="margin:0;font-size:14px;color:#cdd9e5">${exec}</p>
      </div>
      <h2 style="font-size:15px;font-weight:700;color:#e6edf3;margin:0 0 16px;text-transform:uppercase;letter-spacing:.5px">
        🎯 Top ${top.length} Alertes Prioritaires
      </h2>
      ${topHTML}
      ${restHTML}
      <div style="border-top:1px solid #30363d;margin-top:24px;padding-top:16px;text-align:center">
        <p style="margin:0;color:#8b949e;font-size:11px">
          CyberVeille Pro · ${new Date().toLocaleString("fr-FR")} ·
          <a href="https://cyberveille-pro.vercel.app" style="color:#58a6ff">Ouvrir l'app</a>
        </p>
      </div>
    </div>`;
}

// ── Formatage texte brut ──────────────────────────────────────────────────────

/**
 * Génère la version texte brut du briefing.
 * Identique à _formatBriefingText() dans email-alerts.js.
 */
function formatBriefingText(top, rest, label) {
  const now      = new Date().toLocaleDateString("fr-FR",
    { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  const total    = top.length + rest.length;
  const kevCount = [...top, ...rest].filter(a => a.isKEV).length;
  const sep      = "=".repeat(60);

  let t = `☀️ BRIEFING CYBERSÉCURITÉ — ${now.toUpperCase()}\nCyberVeille Pro · Digest ${label}\n${sep}\n\n`;
  t += `RÉSUMÉ EXÉCUTIF\n${"-".repeat(30)}\n${total} menace(s) détectée(s)`;
  if (kevCount > 0) t += `, dont ${kevCount} KEV activement exploitée(s)`;
  t += `.\n\n🎯 TOP ${top.length} ALERTES PRIORITAIRES\n${sep}\n\n`;

  top.forEach((a, i) => {
    const badge = a.criticality === "high" ? "🔴 HAUTE" : "🟠 MOYENNE";
    const kev   = a.isKEV ? " | 🚨 KEV ACTIF" : "";
    const epss  = a.epssScore != null ? ` | EPSS ${Math.round(a.epssScore * 100)} %` : "";
    t += `${i + 1}. ${badge}${kev}${epss}\n`;
    t += `   ${a.title}\n   Source : ${a.sourceName} — ${_affectedProducts(a)}\n`;
    t += `   Lien   : ${a.link}\n   ► ${_whyImportant(a)}\n`;
    _watchpoints(a).forEach(p => { t += `   • ${p}\n`; });
    t += "\n";
  });

  if (rest.length > 0) {
    t += `📋 AUTRES ALERTES (${rest.length})\n${"-".repeat(60)}\n`;
    rest.forEach(a => {
      t += `${a.criticality === "high" ? "🔴" : "🟠"} [${a.sourceName}] ${a.title}\n   ${a.link}\n`;
    });
    t += "\n";
  }

  t += `${sep}\nGénéré par CyberVeille Pro le ${new Date().toLocaleString("fr-FR")}\n`;
  return t;
}

module.exports = {
  digestPriorityScore,
  selectTopArticles,
  formatBriefingHTML,
  formatBriefingText,
  // Helpers d'explication exposés pour le mode preview de scheduled-digest.js
  whyImportant: _whyImportant,
  watchpoints:  _watchpoints
};
