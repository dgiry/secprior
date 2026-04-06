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
    // Microsoft — domaines produits fréquemment cités dans des CVEs
    'microsoft.com','microsoftonline.com','windows.com','azure.com',
    'outlook.com','office.com','office365.com','office.net',
    'live.com','hotmail.com','msn.com','bing.com',
    'onedrive.com','sharepoint.com','onenote.com','teams.live.com',
    'skype.com','xbox.com','visualstudio.com','nuget.org',
    'azureedge.net','azurewebsites.net','msftconnecttest.com','windowsupdate.com',
    'apple.com','icloud.com','amazon.com','amazonaws.com','cloudfront.net',
    'github.com','githubusercontent.com','gitlab.com','bitbucket.org',
    'cloudflare.com','cloudflare-dns.com','fastly.com','akamai.com','akamaized.net',
    'twitter.com','x.com','linkedin.com','youtube.com','facebook.com','instagram.com',
    // Éditeurs fréquemment cités dans des CVEs (domaines produits, pas IOCs)
    'adobe.com','acrobat.com',
    'oracle.com','java.com','sun.com',
    'cisco.com','webex.com','duo.com',
    'vmware.com','broadcom.com','bmc.com',
    'fortinet.com','fortigate.com','forticlient.com',
    'juniper.net','pulsesecure.net','ivanti.com',
    'citrix.com','netscaler.com',
    'sap.com','servicenow.com','salesforce.com',
    'atlassian.com','jira.com','confluence.atlassian.com',
    'zoom.us','dropbox.com','box.com','slack.com',
    'redhat.com','centos.org','fedoraproject.org','debian.org','ubuntu.com','suse.com',
    'kernel.org','gnu.org','apache.org','nginx.org','openssl.org','openssh.com',
    'nodejs.org','python.org','php.net','ruby-lang.org','golang.org',
    // Domaines gouvernementaux (TLDs restreints aux entités officielles)
    // Couvre tous les sous-domaines : cyber.gouv.fr, ncsc.gov.uk, etc.
    'gouv.fr','gov.uk','bund.de','gc.ca','gov.au','govt.nz',
    'europa.eu','consilium.europa.eu',
    // Agences / Organismes sécu (entrées explicites conservées pour compatibilité)
    'nist.gov','cisa.gov','nvd.nist.gov','us-cert.gov','first.org','mitre.org',
    'sans.org','cert.ssi.gouv.fr','cyber.gouv.fr','ssi.gouv.fr','anssi.fr',
    'ncsc.gov.uk','bsi.bund.de','enisa.europa.eu','ccn-cert.cni.es',
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
    'mozilla.org','firefox.com','chromium.org','webkit.org',
    // IOC feed infrastructure (abuse.ch) — self-referential links, not IOCs
    'abuse.ch','urlhaus.abuse.ch','bazaar.abuse.ch','feodotracker.abuse.ch',
    'threatfox.abuse.ch','sslbl.abuse.ch'
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
  //
  // Filtering pipeline (V2 — editorial URL exclusion):
  //   1. Same-domain as article source → self-referential link, not an IOC
  //   2. Known legitimate / infrastructure domain whitelist
  //   3. Obvious editorial / navigation paths (homepage, category, archive…)
  //
  // IPs, domains, hashes are unaffected by these rules.

  // Path segments that identify editorial / navigation pages — never IOCs.
  // Applied regardless of hostname (a /category/ path is not a C2 endpoint
  // on any domain). Conservative set: only clear-cut editorial patterns.
  const _EDITORIAL_PATH_RE = /^\/(category|categories|tag|tags|author|authors|archive|archives|search|page|feed|rss|podcast|podcasts|episodes?|about|contact|privacy|terms|subscribe|newsletter)(\/|$|\?|#)/i;

  function _extractURLs(text, sourceLink) {
    const seen = new Set();
    const re   = /https?:\/\/[^\s<>"')\]},;|\\]+/gi;

    // Derive source hostname once — used for same-domain exclusion
    let srcHost = '';
    try { srcHost = new URL(sourceLink || '').hostname.replace(/^www\./, ''); } catch {}

    let m;
    while ((m = re.exec(text)) !== null) {
      // Strip trailing punctuation artefacts
      const url = m[0].replace(/[.,;:!?'")\]|]+$/, '');
      if (url === sourceLink) continue;

      let host, pathname;
      try {
        const parsed = new URL(url);
        host     = parsed.hostname.replace(/^www\./, '');
        pathname = parsed.pathname;
      } catch { continue; }

      // 1. Same-domain as article source — editorial / navigation link, not an IOC
      //    (covers homepage, other articles, category pages from the same site)
      if (srcHost && host === srcHost) continue;

      // 2. Known legitimate infrastructure / media domain whitelist
      if (_isDomainLegit(host)) continue;

      // 3. Editorial path patterns: homepage or well-known navigation segments
      if (pathname === '/' || pathname === '' || _EDITORIAL_PATH_RE.test(pathname)) continue;

      seen.add(url);
    }
    return [...seen].slice(0, 5);
  }

  // ── Source de vérité : comptage depuis les arrays réels ──────────────────
  //
  // Toutes les surfaces UI doivent appeler getRealIOCCount / hasRealIOCs
  // plutôt que lire article.iocCount directement.
  // article.iocCount peut dériver des arrays (cache LocalStorage 30 min,
  // changements de whitelist entre sessions, etc.).
  // Ces fonctions lisent toujours les arrays en temps réel.

  function getRealIOCCount(article) {
    const iocs = article.iocs;
    if (!iocs) return 0;
    return (iocs.ips?.length     || 0)
         + (iocs.domains?.length || 0)
         + (iocs.hashes?.length  || 0)
         + (iocs.urls?.length    || 0);
  }

  function hasRealIOCs(article) {
    return getRealIOCCount(article) > 0;
  }

  // ── Enrichissement d'un article ───────────────────────────────────────────
  //
  // @param {object} article   - article ThreatLens enrichi
  // @param {string} fullText  - corps complet de l'article (optionnel).
  //                             Fourni par /api/article-body pour le deep scan.
  //                             Si absent, seuls title + description sont analysés.

  function enrichArticle(article, fullText = '') {
    // Construire le texte brut (titre + description + corps optionnel)
    const rawText = [article.title, article.description, fullText].filter(Boolean).join(' ');
    // Appliquer le défanging avant extraction
    const text    = _defang(rawText);

    const ips     = _extractIPs(text);
    const hashes  = _extractHashes(text);
    const domains = _extractDomains(text, article.link);
    const urls    = _extractURLs(text, article.link);

    const iocs = { ips, hashes, domains, urls };
    // iocCount est TOUJOURS dérivé des arrays réels via getRealIOCCount
    // pour garantir la cohérence entre la valeur stockée et les données réelles.
    const iocCount = getRealIOCCount({ iocs });

    // ── URLhaus cross-reference ───────────────────────────────────────────────
    // If URLhausIOC is loaded and ready, check every extracted domain / URL / IP
    // against the live URLhaus malicious-URL map.  Matches are stored in
    // article.urlhausMatches and rendered as ☣️ badges in the IOC panel.
    const urlhausMatches = {};
    if (typeof URLhausIOC !== 'undefined' && URLhausIOC.isReady()) {
      domains.forEach(d => {
        const m = URLhausIOC.lookupDomain(d);
        if (m) urlhausMatches[d] = m;
      });
      urls.forEach(u => {
        const m = URLhausIOC.lookupUrl(u);
        if (m) urlhausMatches[u] = m;
      });
      ips.forEach(ip => {
        const m = URLhausIOC.lookupDomain(ip);
        if (m) urlhausMatches[ip] = m;
      });
    }

    return { ...article, iocs, iocCount, urlhausMatches };
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

  return { enrichArticle, enrichAll, copyIOC, formatForDisplay, getRealIOCCount, hasRealIOCs };
})();
