// ioc-extractor.js — Extraction automatique d'Indicateurs de Compromission (IOCs)
//
// Extrait depuis le titre + description de chaque article :
//   • IPv4 publiques (filtre RFC1918, loopback, multicast)
//   • Hashes cryptographiques : SHA256 (64), SHA1 (40), MD5 (32)
//   • Domaines suspects (whitelist agences/médias sécu)
//   • URLs malveillantes (hors sources connues)
//
// Support "defanging" : hxxp://, evil[.]com, 1.2.3[.]4, (.) — courant
//   dans les rapports Threat Intel pour éviter les clics accidentels.
//
// API :  IOCExtractor.enrichArticle(article) → article + { iocs, iocCount }
//         IOCExtractor.enrichAll(articles)   → array enrichi
//         IOCExtractor.copyIOC(type, value)  → copie + toast

const IOCExtractor = (() => {

  // ── Whitelist : domaines légitimes à ne pas signaler comme IOCs ────────────
  // (sources RSS, agences sécu, CDNs, infrastructure)
  const LEGIT_DOMAINS = new Set([
    // Infrastructure
    'google.com','googleapis.com','gstatic.com','googlesyndication.com',
    'microsoft.com','microsoftonline.com','windows.com','azure.com',
    'apple.com','icloud.com','amazon.com','amazonaws.com','cloudfront.net',
    'github.com','githubusercontent.com','gitlab.com','bitbucket.org',
    'cloudflare.com','cloudflare-dns.com','fastly.com','akamai.com','akamaized.net',
    'twitter.com','x.com','linkedin.com','youtube.com','facebook.com','instagram.com',
    // Agences / Organismes sécu
    'nist.gov','cisa.gov','nvd.nist.gov','us-cert.gov','first.org','mitre.org',
    'sans.org','cert.ssi.gouv.fr','ncsc.gov.uk','bsi.bund.de','enisa.europa.eu',
    'attack.mitre.org','cve.org','cve.mitre.org',
    // Médias cybersécurité (sources RSS du projet)
    'bleepingcomputer.com','thehackernews.com','krebsonsecurity.com','zataz.com',
    'talosintelligence.com','blog.talosintelligence.com','talos.blog',
    'securelist.com','kaspersky.com','unit42.paloaltonetworks.com','paloaltonetworks.com',
    'zerodayinitiative.com','exploit-db.com','packetstormsecurity.com',
    'securityweek.com','threatpost.com','darkreading.com','cyberscoop.com',
    'recordedfuture.com','mandiant.com','crowdstrike.com','sentinelone.com',
    // Proxies / utils du projet
    'allorigins.win','api.first.org','services.nvd.nist.gov','feedburner.com',
    // Web commun
    'w3.org','schema.org','jquery.com','bootstrapcdn.com','cdnjs.com',
    'mozilla.org','firefox.com','chromium.org','webkit.org'
  ]);

  // ── Plages IP privées / locales à exclure ─────────────────────────────────
  const PRIVATE_IP = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^169\.254\./,
    /^0\./,
    /^255\./,
    /^224\./,    // multicast
    /^240\./     // réservé
  ];

  // ── Défanging ──────────────────────────────────────────────────────────────
  // Réécrit les IOCs obfusqués en forme canonique avant l'extraction
  function _defang(text) {
    return text
      .replace(/hxxps?/gi,  m => m.replace('hxxp', 'http'))  // hxxp:// → http://
      .replace(/\[\.]/g,    '.')   // evil[.]com
      .replace(/\[\.\]/g,   '.')   // evil[.]com (variante)
      .replace(/\(\.\)/g,   '.')   // evil(.)com
      .replace(/\[ \. ]/g,  '.')   // evil[ . ]com
      .replace(/\[\/\/]/g,  '//')  // hxxp[://]...
      .replace(/\[@]/g,     '@');  // user[@]domain.com
  }

  // ── Extraction IPv4 ───────────────────────────────────────────────────────
  function _extractIPs(text) {
    const seen = new Set();
    // Regex stricte pour IPv4 valide (0-255 par octet)
    const re = /\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))\b/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const ip = m[1];
      if (!PRIVATE_IP.some(r => r.test(ip))) seen.add(ip);
    }
    return [...seen];
  }

  // ── Extraction hashes cryptographiques ────────────────────────────────────
  // Ordre : SHA256 → SHA1 → MD5 (du plus long au plus court pour éviter les sous-matches)
  function _extractHashes(text) {
    const hashes = [];
    const seen   = new Set();

    // On strip les 0x prefix pour ne pas confondre avec pointeurs/adresses mémoire
    // \b garantit qu'on ne prend pas un substring d'un hash plus long
    const patterns = [
      { type: 'SHA256', re: /(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])/gi },
      { type: 'SHA1',   re: /(?<![0-9a-f])([0-9a-f]{40})(?![0-9a-f])/gi },
      { type: 'MD5',    re: /(?<![0-9a-f])([0-9a-f]{32})(?![0-9a-f])/gi }
    ];

    for (const { type, re } of patterns) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const val = m[1].toLowerCase();
        if (!seen.has(val)) {
          seen.add(val);
          hashes.push({ type, value: val });
        }
      }
    }
    return hashes;
  }

  // ── Extraction domaines suspects ──────────────────────────────────────────
  function _extractDomains(text, sourceLink) {
    const seen = new Set();
    // TLDs couverts : communs + ceux sur-représentés dans la cybercriminalité
    const tlds = 'com|net|org|io|gov|fr|ru|cn|mil|edu|cc|biz|info|xyz|top|' +
                 'club|online|site|shop|store|app|dev|cloud|tech|ai|tk|pw|ws|su|gg|me|co|us';
    const re   = new RegExp(
      `\\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${tlds}))\\b`, 'gi'
    );

    // Domaine de la source (à exclure)
    let srcHost = '';
    try { srcHost = new URL(sourceLink || '').hostname.replace(/^www\./, ''); } catch {}

    let m;
    while ((m = re.exec(text)) !== null) {
      const d = m[1].toLowerCase().replace(/^www\./, '');
      if (d === srcHost) continue;
      if (_isDomainLegit(d)) continue;
      seen.add(d);
    }
    return [...seen].slice(0, 8);
  }

  function _isDomainLegit(domain) {
    if (LEGIT_DOMAINS.has(domain)) return true;
    // Vérifier les domaines parents (ex: sub.google.com → google.com)
    const parts = domain.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      if (LEGIT_DOMAINS.has(parts.slice(i).join('.'))) return true;
    }
    return false;
  }

  // ── Extraction URLs suspectes ─────────────────────────────────────────────
  function _extractURLs(text, sourceLink) {
    const seen = new Set();
    const re   = /https?:\/\/[^\s<>"')\]},;|\\]+/gi;
    let m;
    while ((m = re.exec(text)) !== null) {
      // Nettoyer la ponctuation de fin
      let url = m[0].replace(/[.,;:!?'")\]|]+$/, '');
      if (url === sourceLink) continue;
      if (url.startsWith(sourceLink || '☒')) continue;  // sous-URL de la source
      try {
        const host = new URL(url).hostname.replace(/^www\./, '');
        if (_isDomainLegit(host)) continue;
      } catch { continue; }
      seen.add(url);
    }
    return [...seen].slice(0, 5);
  }

  // ── Enrichissement d'un article ───────────────────────────────────────────

  function enrichArticle(article) {
    // Construire le texte brut (titre + description)
    const rawText = [article.title, article.description].filter(Boolean).join(' ');
    // Appliquer le défanging avant extraction
    const text    = _defang(rawText);

    const ips     = _extractIPs(text);
    const hashes  = _extractHashes(text);
    const domains = _extractDomains(text, article.link);
    const urls    = _extractURLs(text, article.link);

    const iocs     = { ips, hashes, domains, urls };
    const iocCount = ips.length + hashes.length + domains.length + urls.length;

    return { ...article, iocs, iocCount };
  }

  function enrichAll(articles) {
    return articles.map(enrichArticle);
  }

  // ── Copier un IOC dans le presse-papier ───────────────────────────────────

  async function copyIOC(type, value) {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const ta = Object.assign(document.createElement('textarea'), {
        value, style: 'position:fixed;top:-9999px;opacity:0'
      });
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    const short = value.length > 24 ? value.slice(0, 12) + '…' + value.slice(-8) : value;
    if (window.UI) UI.showToast(`📋 ${type} copied: ${short}`, 'success');
  }

  // ── Formater un IOC pour affichage ────────────────────────────────────────

  function formatForDisplay(type, value) {
    switch (type) {
      case 'SHA256': return 'SHA256:' + value.slice(0, 8) + '…' + value.slice(-4);
      case 'SHA1':   return 'SHA1:'   + value.slice(0, 8) + '…' + value.slice(-4);
      case 'MD5':    return 'MD5:'    + value.slice(0, 8) + '…' + value.slice(-4);
      case 'ip':     return value;
      case 'domain': return value;
      case 'url':    return value.length > 35 ? value.slice(0, 32) + '…' : value;
      default:       return value;
    }
  }

  return { enrichArticle, enrichAll, copyIOC, formatForDisplay };
})();
