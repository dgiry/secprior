// ioc-utils.js — Utilitaires IOC analyste — V1
//
// Fournit des helpers de haut niveau pour affichage, copie et export
// des IOCs détectés dans les articles.
//
// Réutilise les données produites par ioc-extractor.js (article.iocs)
// sans recalcul — agrégation et présentation uniquement.
//
// API publique :
//   aggregateIOCs(articles)            → { ips, domains, urls, hashes }
//   total(iocs)                        → number
//   copyOne(typeLabel, value)          → Promise (clipboard + toast)
//   copyGroup(label, values)           → Promise (clipboard + toast)
//   exportIOC(iocs, format, label)     → déclenche téléchargement (json|txt)
//   iocBlockHTML(iocs, incidentId)     → string HTML

const IOCUtils = (() => {

  // ── Agrégation sans doublons ─────────────────────────────────────────────
  //
  // Parcourt les articles d'un incident et fusionne leurs IOCs.
  // · ips / domains / urls : dédupliqués via Set
  // · hashes : Map(value → type) pour conserver le type (SHA256/SHA1/MD5)

  function aggregateIOCs(articles) {
    const ips     = new Set();
    const domains = new Set();
    const urls    = new Set();
    const hashMap = new Map();  // value → type

    for (const a of articles) {
      if (!a.iocs) continue;
      (a.iocs.ips     || []).forEach(v => ips.add(v));
      (a.iocs.domains || []).forEach(v => domains.add(v));
      (a.iocs.urls    || []).forEach(v => urls.add(v));
      (a.iocs.hashes  || []).forEach(h => {
        if (h && h.value && !hashMap.has(h.value)) hashMap.set(h.value, h.type || 'hash');
      });
    }

    return {
      ips:     [...ips],
      domains: [...domains],
      urls:    [...urls],
      hashes:  [...hashMap.entries()].map(([value, type]) => ({ value, type }))
    };
  }

  function total(iocs) {
    return (iocs.ips?.length     || 0)
         + (iocs.domains?.length || 0)
         + (iocs.urls?.length    || 0)
         + (iocs.hashes?.length  || 0);
  }

  // ── Presse-papier ────────────────────────────────────────────────────────

  async function _write(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = Object.assign(document.createElement('textarea'), {
        value: text,
        style: 'position:fixed;top:-9999px;opacity:0'
      });
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
  }

  async function copyOne(typeLabel, value) {
    await _write(value);
    const short = value.length > 28 ? value.slice(0, 14) + '…' + value.slice(-8) : value;
    if (window.UI) UI.showToast(`📋 ${typeLabel} copied: ${short}`, 'success');
  }

  async function copyGroup(label, values) {
    if (!values.length) return;
    await _write(values.join('\n'));
    if (window.UI) UI.showToast(
      `📋 ${values.length} ${label} copied`, 'success'
    );
  }

  // ── Export ───────────────────────────────────────────────────────────────

  function exportIOC(iocs, format, contextLabel) {
    const slug = (contextLabel || 'iocs').replace(/[^a-zA-Z0-9\-]/g, '_').slice(0, 40);
    const ts   = new Date().toISOString().slice(0, 10);
    const name = `iocs_${slug}_${ts}`;

    let content, mime, ext;

    if (format === 'json') {
      content = JSON.stringify({
        context:    contextLabel,
        exportedAt: new Date().toISOString(),
        total:      total(iocs),
        iocs
      }, null, 2);
      mime = 'application/json';
      ext  = 'json';
    } else {
      // Format TXT : un IOC par ligne, sections commentées
      const lines = [
        `# IOCs — ${contextLabel}`,
        `# Exported on ${new Date().toLocaleString('en-US')}`,
        `# Total : ${total(iocs)} indicateur${total(iocs) > 1 ? 's' : ''}`,
        ''
      ];
      if (iocs.ips.length) {
        lines.push(`## IPs (${iocs.ips.length})`, ...iocs.ips, '');
      }
      if (iocs.domains.length) {
        lines.push(`## Domaines (${iocs.domains.length})`, ...iocs.domains, '');
      }
      if (iocs.urls.length) {
        lines.push(`## URLs (${iocs.urls.length})`, ...iocs.urls, '');
      }
      if (iocs.hashes.length) {
        lines.push(`## Hashes (${iocs.hashes.length})`);
        iocs.hashes.forEach(h => lines.push(`${h.type}:${h.value}`));
        lines.push('');
      }
      content = lines.join('\n');
      mime    = 'text/plain';
      ext     = 'txt';
    }

    const blob = new Blob([content], { type: mime });
    const a    = Object.assign(document.createElement('a'), {
      href:     URL.createObjectURL(blob),
      download: `${name}.${ext}`
    });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  // ── Rendu HTML ────────────────────────────────────────────────────────────

  function _esc(s) {
    return String(s || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Construit le bloc d'une catégorie (ips / domains / urls / hashes)
  // values    : tableau de strings (valeurs brutes)
  // displayFn : (value) → string affiché (troncature pour longues URLs/hashes)
  function _typeSection(icon, label, values, displayFn) {
    if (!values.length) return '';

    // Séparateur || est absent des IPs, domaines et hashes hex.
    // Pour les URLs, || n'est pas un caractère URL valide — séparateur sûr.
    const packedVals = _esc(values.join('||'));

    return `
      <div class="ioc-section">
        <div class="ioc-section-head">
          <span class="ioc-type-icon">${icon}</span>
          <span class="ioc-type-label">${_esc(label)}</span>
          <span class="ioc-type-count">(${values.length})</span>
          <button class="ioc-copy-group"
                  data-ioc-label="${_esc(label)}"
                  data-ioc-vals="${packedVals}"
                  title="Copy all ${_esc(label)}">📋 Copy all</button>
        </div>
        <div class="ioc-list">
          ${values.map(v => {
            const pivotUrl = 'https://dgiry.github.io/ioc-pivot?ioc=' + encodeURIComponent(v);
            return `
            <span class="ioc-item">
              <code class="ioc-val" title="${_esc(v)}">${_esc(displayFn ? displayFn(v) : v)}</code>
              <a href="${pivotUrl}" target="_blank" rel="noopener"
                 class="pipeline-link" title="Pivot in IOC Pivot Hub">🔭</a>
              <button class="ioc-copy-one"
                      data-ioc-type="${_esc(label)}"
                      data-ioc-val="${_esc(v)}"
                      title="Copy ${_esc(v)}">📋</button>
            </span>`;
          }).join('')}
        </div>
      </div>`;
  }

  function iocBlockHTML(iocs, incidentId) {
    const t = total(iocs);
    if (t === 0) return '';

    // Valeurs all-in-one pour "Tout copier" (toutes catégories)
    const allVals = [
      ...iocs.ips,
      ...iocs.domains,
      ...iocs.urls,
      ...iocs.hashes.map(h => `${h.type}:${h.value}`)
    ];

    // Hashes : on affiche le type + valeur tronquée, on copie la valeur brute
    const hashDisplayFn = v => {
      const h = iocs.hashes.find(x => x.value === v);
      const t = h?.type || '';
      const s = v.length > 20 ? v.slice(0, 10) + '…' + v.slice(-6) : v;
      return `${t}:${s}`;
    };

    const urlDisplayFn = v => v.length > 58 ? v.slice(0, 55) + '…' : v;

    const safeIid = _esc(incidentId);

    return `
      <div class="ioc-block" data-iid="${safeIid}">
        <div class="ioc-block-head">
          <span class="ioc-block-title">🔗 Detected IOCs</span>
          <span class="ioc-block-count">${t} indicator${t > 1 ? 's' : ''}</span>
          <div class="ioc-block-actions">
            <button class="ioc-copy-all"
                    data-ioc-vals="${_esc(allVals.join('||'))}"
                    title="Copy all IOCs to clipboard">📋 Copy all</button>
            <button class="ioc-export-json" data-iid="${safeIid}" title="Export JSON">⬇ JSON</button>
            <button class="ioc-export-txt"  data-iid="${safeIid}" title="Export TXT">⬇ TXT</button>
          </div>
        </div>
        ${_typeSection('🌐', 'IP',      iocs.ips,                      null)}
        ${_typeSection('🏠', 'Domain',  iocs.domains,                  null)}
        ${_typeSection('🔗', 'URL',     iocs.urls,                     urlDisplayFn)}
        ${_typeSection('#',  'Hash',    iocs.hashes.map(h => h.value), hashDisplayFn)}
      </div>`;
  }

  return { aggregateIOCs, total, copyOne, copyGroup, exportIOC, iocBlockHTML };
})();
