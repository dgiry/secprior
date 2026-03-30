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
    r.push("actively exploited in the wild (CISA KEV)");
  if (a.epssScore != null && a.epssScore >= 0.70)
    r.push(`with very high exploitation probability (EPSS ${Math.round(a.epssScore * 100)} %)`);
  else if (a.epssScore != null && a.epssScore >= 0.40)
    r.push(`with moderate exploitation risk (EPSS ${Math.round(a.epssScore * 100)} %)`);
  if (a.cvssScore != null && a.cvssScore >= 9.0)
    r.push(`with CVSS score ${a.cvssScore} (critical)`);
  else if (a.cvssScore != null && a.cvssScore >= 7.0)
    r.push(`with CVSS score ${a.cvssScore}`);
  else if (a.score != null && a.score >= 90) r.push("of maximum criticality");
  else if (a.score != null && a.score >= 80) r.push("of very high criticality");
  if (a.isTrending)     r.push("trending across threat intel platforms");
  if (a.cveIds?.length) r.push(`referenced as ${a.cveIds.slice(0, 2).join(", ")}`);
  if (r.length === 0)
    return a.criticality === "high"
      ? "Classified as high criticality by automated analysis."
      : "Identified as a potential threat.";
  return "This vulnerability is " + r.join(", ") + ".";
}

function _affectedProducts(a) {
  return a.tags?.length ? a.tags.slice(0, 4).join(" · ") : a.sourceName;
}

function _watchpoints(a) {
  const pts = [];
  if (a.isKEV)
    pts.push("Apply patches immediately (CISA deadline: 3 weeks)");
  if (a.epssScore != null && a.epssScore >= 0.70)
    pts.push("Monitor exploitation logs on exposed systems");
  if (a.cvssScore != null && a.cvssScore >= 9.0 && !a.isKEV)
    pts.push(`CVSS ${a.cvssScore} — assess and reduce exposure window immediately`);
  if (pts.length === 0 && a.criticality === "high")
    pts.push("Check exposure of affected assets");
  if (a.isTrending)
    pts.push("Review IoCs published by the threat intel community");
  if (a.cveIds?.length)
    pts.push(`Check patch status for ${a.cveIds[0]}`);
  if (pts.length === 0)
    pts.push("Monitor developments and apply vendor recommendations");
  return pts;
}

// ── Formatage HTML ────────────────────────────────────────────────────────────

/**
 * Génère l'email HTML du briefing matinal.
 * Identique à _formatBriefingHTML() dans email-alerts.js.
 */
function formatBriefingHTML(top, rest, label) {
  const now = new Date().toLocaleDateString("en-CA",
    { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  const total     = top.length + rest.length;
  const kevCount  = [...top, ...rest].filter(a => a.isKEV).length;
  const highCount = [...top, ...rest].filter(a => a.criticality === "high").length;

  let exec = `${total} threat(s) detected during this period`;
  if (kevCount  > 0) exec += `, including ${kevCount} actively exploited KEV vulnerability/vulnerabilities`;
  if (highCount > 0) exec += `. ${highCount} high-criticality alert(s) require your attention`;
  exec += ".";

  const topHTML = top.map(a => {
    const color = a.criticality === "high" ? "#f85149" : "#f0883e";
    const badge = a.criticality === "high" ? "🔴 HIGH" : "🟠 MEDIUM";
    const meta  = [
      a.isKEV             ? "🚨 KEV ACTIVE"                             : "",
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
          📌 <strong>Why it matters:</strong> ${_whyImportant(a)}
        </p>
        <div style="font-size:12px">
          <p style="margin:0 0 6px;color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.5px">⚡ Immediate watchpoints</p>
          <ul style="margin:0;padding-left:16px">${pts}</ul>
        </div>
      </div>`;
  }).join("");

  const restHTML = rest.length === 0 ? "" : `
    <h3 style="color:#8b949e;font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin:24px 0 12px">
      📋 Other alerts (${rest.length})
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
        <h1 style="margin:0 0 4px;font-size:20px;color:#e6edf3">☀️ Security Briefing — ${now}</h1>
        <p style="margin:0;color:#8b949e;font-size:13px">ThreatLens · Digest ${label}</p>
      </div>
      <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;margin-bottom:24px">
        <p style="margin:0 0 4px;color:#8b949e;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px">EXECUTIVE SUMMARY</p>
        <p style="margin:0;font-size:14px;color:#cdd9e5">${exec}</p>
      </div>
      <h2 style="font-size:15px;font-weight:700;color:#e6edf3;margin:0 0 16px;text-transform:uppercase;letter-spacing:.5px">
        🎯 Top ${top.length} Priority Alerts
      </h2>
      ${topHTML}
      ${restHTML}
      <div style="border-top:1px solid #30363d;margin-top:24px;padding-top:16px;text-align:center">
        <p style="margin:0;color:#8b949e;font-size:11px">
          ThreatLens · ${new Date().toLocaleString("en-CA")} ·
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
  const now      = new Date().toLocaleDateString("en-CA",
    { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  const total    = top.length + rest.length;
  const kevCount = [...top, ...rest].filter(a => a.isKEV).length;
  const sep      = "=".repeat(60);

  let t = `☀️ SECURITY BRIEFING — ${now.toUpperCase()}\nThreatLens · Digest ${label}\n${sep}\n\n`;
  t += `EXECUTIVE SUMMARY\n${"-".repeat(30)}\n${total} threat(s) detected`;
  if (kevCount > 0) t += `, including ${kevCount} actively exploited KEV vulnerability/vulnerabilities`;
  t += `.\n\n🎯 TOP ${top.length} PRIORITY ALERTS\n${sep}\n\n`;

  top.forEach((a, i) => {
    const badge = a.criticality === "high" ? "🔴 HIGH" : "🟠 MEDIUM";
    const kev   = a.isKEV ? " | 🚨 KEV ACTIVE" : "";
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

  t += `${sep}\nGenerated by ThreatLens on ${new Date().toLocaleString("en-CA")}\n`;
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
