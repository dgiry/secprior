// demo-data.js — Articles de démo réalistes pour preview/tests offline
//
// Utilisé automatiquement si tous les fetches RSS échouent (réseau bloqué)
//
// Pré-enrichissement complet :
//   • isKEV, epssScore, cvssScore, cvssVector, cves  → pour filtres KEV / EPSS
//   • demo_t1 + demo_t2 sont des doublons proches de demo1 → le déduplicateur les
//     fusionne en mode pipeline réel, ce qui donne sourceCount=3 → isTrending=true
//   • IOCs réalistes dans les descriptions → filtre IOCs opérationnel
//   • 0-Day détecté via _detectAttack() du Contextualizer (pas besoin de pré-setter)
//
// Pour tester le filtre Watchlist : ajouter "ivanti" ou "lockbit" dans la Watchlist.

const DEMO_ARTICLES = [

  // ── HIGH — Ivanti VPN zero-day activement exploité ──────────────────────────
  {
    id: "demo1",
    source: "thehackernews", sourceName: "The Hacker News", sourceIcon: "🔴",
    title: "Critical Zero-Day in Ivanti VPN Actively Exploited by Nation-State Actors",
    description: "A critical unauthenticated remote code execution vulnerability (CVE-2024-21887) " +
      "in Ivanti Connect Secure VPN is being actively exploited by suspected Chinese APT groups. " +
      "Over 1,700 devices have been compromised globally. C2 infrastructure observed at " +
      "45.142.212[.]100 and 185.220.101[.]45. Malware sample hash: " +
      "1a2b3c4d5e6f7a8b1a2b3c4d5e6f7a8b1a2b3c4d5e6f7a8b1a2b3c4d5e6f7a8b. " +
      "Indicators also include beacon domain update-ivanti[.]com.",
    link: "https://thehackernews.com",
    criticality: "high",
    cves:       ["CVE-2024-21887"],
    isKEV:      true,
    epssScore:  0.953,
    cvssScore:  9.1,
    cvssVector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    pubDate: new Date(Date.now() - 1.2 * 3600000),
    starred: false
  },

  // ── TRENDING DUPLICATE A — même histoire Ivanti (sera fusionné dans demo1) ──
  // Titre très proche de demo1 + même CVE → R3 du déduplicateur → DUPLICATE
  // → demo1.sourceCount passe à 2 après fusion de celui-ci
  {
    id: "demo_t1",
    source: "bleepingcomputer", sourceName: "Bleeping Computer", sourceIcon: "🟣",
    title: "Ivanti VPN Zero-Day Exploited Nation-State Actors CVE-2024-21887 Active Campaign",
    description: "Bleeping Computer confirms active exploitation of CVE-2024-21887 in Ivanti " +
      "Connect Secure VPN. Over 1,700 exposed devices worldwide. Attributed to Chinese APT UNC5221.",
    link: "https://bleepingcomputer.com/ivanti-vpn-zero-day-nation-state",
    criticality: "high",
    cves:      ["CVE-2024-21887"],
    isKEV:     true,
    epssScore: 0.953,
    cvssScore: 9.1,
    pubDate: new Date(Date.now() - 1.4 * 3600000),
    starred: false
  },

  // ── TRENDING DUPLICATE B — même histoire Ivanti (sera fusionné dans demo1) ──
  // sameCve=true + score Jaccard ≥ RELATED (0.65) → R3 → DUPLICATE
  // → demo1.sourceCount passe à 3 → isTrending = true
  {
    id: "demo_t2",
    source: "unit42", sourceName: "Unit 42 (Palo Alto)", sourceIcon: "🔭",
    title: "Ivanti VPN Zero-Day Exploited by Nation-State Actors CVE-2024-21887",
    description: "Unit 42 threat intelligence confirms nation-state exploitation of CVE-2024-21887. " +
      "Attackers deployed custom webshells on Ivanti gateways before deploying lateral movement tools.",
    link: "https://unit42.paloaltonetworks.com/ivanti-vpn-zero-day",
    criticality: "high",
    cves:      ["CVE-2024-21887"],
    isKEV:     true,
    epssScore: 0.953,
    cvssScore: 9.1,
    pubDate: new Date(Date.now() - 1.6 * 3600000),
    starred: false
  },

  // ── HIGH — LockBit ransomware (IOCs inclus) ──────────────────────────────────
  {
    id: "demo2",
    source: "bleepingcomputer", sourceName: "Bleeping Computer", sourceIcon: "🟣",
    title: "LockBit Ransomware Targets Healthcare Sector with New Encryptor Variant",
    description: "LockBit 3.0 operators have deployed a new ransomware variant targeting hospital " +
      "networks across Europe and North America, with ransom demands exceeding $10M. " +
      "Sample MD5: a1b2c3d4e5f6789012345678901234ab. " +
      "C2 callback domain: lockbit-panel[.]xyz. Ransom portal: payments.lockbit3[.]xyz.",
    link: "https://bleepingcomputer.com",
    criticality: "high",
    cves:      [],
    isKEV:     false,
    epssScore: 0.724,
    pubDate: new Date(Date.now() - 2.5 * 3600000),
    starred: false
  },

  // ── HIGH — CERT-FR : Windows ─────────────────────────────────────────────────
  {
    id: "demo3",
    source: "certfr", sourceName: "CERT-FR", sourceIcon: "🇫🇷",
    title: "CERTFR-2024-AVI-0892 : Multiples vulnérabilités dans Microsoft Windows",
    description: "De multiples vulnérabilités ont été découvertes dans Microsoft Windows. " +
      "Certaines permettent une élévation de privilèges, d'autres une exécution de code arbitraire " +
      "à distance. Un correctif d'urgence est disponible.",
    link: "https://cert.ssi.gouv.fr",
    criticality: "high",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 3 * 3600000),
    starred: false
  },

  // ── HIGH — CISA KEV : CVE-2024-38112 ────────────────────────────────────────
  {
    id: "demo4",
    source: "cisa", sourceName: "CISA Alerts", sourceIcon: "🦅",
    title: "CISA Adds CVE-2024-38112 to Known Exploited Vulnerabilities Catalog",
    description: "CISA has added a Windows MSHTML Platform Spoofing vulnerability (CVE-2024-38112) " +
      "to its KEV catalog. Federal agencies must patch by the next business day. " +
      "The flaw allows attackers to execute arbitrary code via malicious .url files.",
    link: "https://cisa.gov",
    criticality: "high",
    cves:       ["CVE-2024-38112"],
    isKEV:      true,
    epssScore:  0.891,
    cvssScore:  7.8,
    cvssVector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    pubDate: new Date(Date.now() - 4 * 3600000),
    starred: false
  },

  // ── HIGH — AT&T data breach ──────────────────────────────────────────────────
  {
    id: "demo5",
    source: "krebsonsecurity", sourceName: "Krebs on Security", sourceIcon: "🔵",
    title: "AT&T Data Breach Exposes Call Records of ~110 Million Customers",
    description: "AT&T confirmed a massive data breach involving call and text records for " +
      "~110 million customers. Stolen data stored on a third-party cloud platform includes " +
      "phone numbers and call durations from May–October 2022.",
    link: "https://krebsonsecurity.com",
    criticality: "high",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 5.5 * 3600000),
    starred: false
  },

  // ── MEDIUM — Phishing Google Docs ───────────────────────────────────────────
  {
    id: "demo6",
    source: "thehackernews", sourceName: "The Hacker News", sourceIcon: "🔴",
    title: "New Phishing Campaign Abuses Google Docs to Bypass Email Security Filters",
    description: "Security researchers at Cofense identified a sophisticated phishing campaign " +
      "leveraging legitimate Google Docs URLs to bypass corporate email security gateways, " +
      "targeting Office 365 credentials.",
    link: "https://thehackernews.com",
    criticality: "medium",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 6 * 3600000),
    starred: false
  },

  // ── MEDIUM — Apache CVE CVSS 9.1 ────────────────────────────────────────────
  {
    id: "demo7",
    source: "bleepingcomputer", sourceName: "Bleeping Computer", sourceIcon: "🟣",
    title: "Apache HTTP Server Patch Released for CVE-2024-38476 (CVSS 9.1)",
    description: "The Apache Software Foundation released version 2.4.62 addressing " +
      "CVE-2024-38476, a critical vulnerability (CVSS 9.1) allowing backend-induced " +
      "HTTP response splitting and request smuggling attacks.",
    link: "https://bleepingcomputer.com",
    criticality: "medium",
    cves:       ["CVE-2024-38476"],
    isKEV:      false,
    epssScore:  0.453,
    cvssScore:  9.1,
    cvssVector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    pubDate: new Date(Date.now() - 8 * 3600000),
    starred: false
  },

  // ── HIGH — Fuite médicale France ─────────────────────────────────────────────
  {
    id: "demo8",
    source: "zataz", sourceName: "Zataz", sourceIcon: "🟠",
    title: "Fuite de données : 3 millions de dossiers médicaux français en vente sur le darkweb",
    description: "Un acteur malveillant propose sur un forum cybercriminel russophone la vente de " +
      "3 millions de dossiers médicaux appartenant à des patients français, incluant diagnostics, " +
      "traitements et données d'assurance maladie.",
    link: "https://zataz.com",
    criticality: "high",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 10 * 3600000),
    starred: false
  },

  // ── MEDIUM — CERT-FR phishing collectivités ──────────────────────────────────
  {
    id: "demo9",
    source: "certfr", sourceName: "CERT-FR", sourceIcon: "🇫🇷",
    title: "CERTFR-2024-ACT-047 : Campagne d'hameçonnage ciblant les collectivités territoriales",
    description: "Le CERT-FR observe une recrudescence des attaques de phishing ciblant les " +
      "collectivités territoriales françaises, usurpant l'identité de la DGFiP pour voler des " +
      "identifiants d'accès.",
    link: "https://cert.ssi.gouv.fr",
    criticality: "medium",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 12 * 3600000),
    starred: false
  },

  // ── MEDIUM — SIM-Swap ────────────────────────────────────────────────────────
  {
    id: "demo10",
    source: "krebsonsecurity", sourceName: "Krebs on Security", sourceIcon: "🔵",
    title: "Inside the Cybercrime Ecosystem Powering SIM-Swap Attacks",
    description: "An in-depth investigation reveals how organized crime groups coordinate " +
      "SIM-swapping operations against US telecom carriers, monetizing access through " +
      "cryptocurrency theft and account takeovers.",
    link: "https://krebsonsecurity.com",
    criticality: "medium",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 15 * 3600000),
    starred: false
  },

  // ── MEDIUM — CISA advisory OT/ransomware ────────────────────────────────────
  {
    id: "demo11",
    source: "cisa", sourceName: "CISA Alerts", sourceIcon: "🦅",
    title: "Advisory: Securing Operational Technology (OT) Environments Against Ransomware",
    description: "CISA and FBI released a joint advisory with updated guidance for critical " +
      "infrastructure operators to defend industrial control systems against ransomware groups " +
      "increasingly targeting OT environments.",
    link: "https://cisa.gov",
    criticality: "medium",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 18 * 3600000),
    starred: false
  },

  // ── MEDIUM — Chrome 127 ──────────────────────────────────────────────────────
  {
    id: "demo12",
    source: "thehackernews", sourceName: "The Hacker News", sourceIcon: "🔴",
    title: "Google Chrome 127 Patches 24 Security Vulnerabilities Including 3 High-Severity",
    description: "Google released Chrome 127.0.6533.88/89 addressing 24 security issues " +
      "including three high-severity use-after-free bugs in audio, graphics, and the V8 engine.",
    link: "https://thehackernews.com",
    criticality: "medium",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 22 * 3600000),
    starred: false
  },

  // ── MEDIUM — FakeUpdate / ClearFake ─────────────────────────────────────────
  {
    id: "demo13",
    source: "bleepingcomputer", sourceName: "Bleeping Computer", sourceIcon: "🟣",
    title: "New 'FakeUpdate' Campaign Targets French Users via Compromised WordPress Sites",
    description: "A social engineering campaign dubbed ClearFake injects fake browser update " +
      "popups on compromised WordPress sites to deliver Atomic Stealer malware to French-speaking " +
      "users. Distribution domain: fakechrome-update[.]fr.",
    link: "https://bleepingcomputer.com",
    criticality: "medium",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 26 * 3600000),
    starred: false
  },

  // ── LOW — Rapport PME françaises ─────────────────────────────────────────────
  {
    id: "demo14",
    source: "zataz", sourceName: "Zataz", sourceIcon: "🟠",
    title: "Rapport : L'état de la cybersécurité des PME françaises en 2024",
    description: "Une étude de l'ANSSI révèle que 60% des PME françaises n'ont pas de plan de " +
      "réponse aux incidents, et que le délai moyen de détection d'une intrusion reste supérieur " +
      "à 200 jours.",
    link: "https://zataz.com",
    criticality: "low",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 30 * 3600000),
    starred: false
  },

  // ── HIGH — MS Patch Tuesday 0-Days (KEV) ────────────────────────────────────
  {
    id: "demo15",
    source: "krebsonsecurity", sourceName: "Krebs on Security", sourceIcon: "🔵",
    title: "Microsoft Patch Tuesday — August 2024: 90 Fixes Including 6 Zero-Days",
    description: "Microsoft's August Patch Tuesday addresses 90 vulnerabilities, including " +
      "six zero-days actively exploited in the wild across Windows SmartScreen (CVE-2024-38213), " +
      "MSHTML (CVE-2024-38178) and the Windows Task Scheduler (CVE-2024-21412).",
    link: "https://krebsonsecurity.com",
    criticality: "high",
    cves:       ["CVE-2024-38213", "CVE-2024-38178", "CVE-2024-21412"],
    isKEV:      true,
    epssScore:  0.812,
    cvssScore:  8.8,
    cvssVector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    pubDate: new Date(Date.now() - 36 * 3600000),
    starred: false
  },

  // ── LOW — CISA guide logging ─────────────────────────────────────────────────
  {
    id: "demo16",
    source: "cisa", sourceName: "CISA Alerts", sourceIcon: "🦅",
    title: "Best Practices for Event Logging and Threat Detection",
    description: "CISA published a new guide outlining recommended logging practices for " +
      "enterprise environments, including centralized SIEM configuration, retention policies, " +
      "and detection rule priorities for common TTPs.",
    link: "https://cisa.gov",
    criticality: "low",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 48 * 3600000),
    starred: false
  },

  // ── HIGH — Kimsuky APT (IOCs inclus) ────────────────────────────────────────
  {
    id: "demo17",
    source: "thehackernews", sourceName: "The Hacker News", sourceIcon: "🔴",
    title: "Kimsuky APT Uses New 'HappyDoor' Backdoor in Spear-Phishing Campaigns",
    description: "North Korean threat actor Kimsuky has been observed deploying a new custom " +
      "backdoor called HappyDoor via spear-phishing emails targeting South Korean government " +
      "officials and defense contractors. Malicious domains include nk-report[.]info and " +
      "update.kimsuky[.]to. SHA-256 of dropper: " +
      "2b4c6d8e0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e. " +
      "C2 beacon observed at 91.219.236[.]18.",
    link: "https://thehackernews.com",
    criticality: "high",
    cves:      [],
    isKEV:     false,
    epssScore: 0.382,
    pubDate: new Date(Date.now() - 52 * 3600000),
    starred: false
  },

  // ── LOW — Side-channel HSM ───────────────────────────────────────────────────
  {
    id: "demo18",
    source: "bleepingcomputer", sourceName: "Bleeping Computer", sourceIcon: "🟣",
    title: "Researchers Discover New Technique to Extract Private Keys from Encrypted HSMs",
    description: "Security researchers at ETH Zürich demonstrated a side-channel attack capable " +
      "of extracting RSA private keys from Hardware Security Modules under specific conditions, " +
      "affecting several enterprise-grade products.",
    link: "https://bleepingcomputer.com",
    criticality: "low",
    cves:      [],
    isKEV:     false,
    epssScore: null,
    pubDate: new Date(Date.now() - 60 * 3600000),
    starred: false
  }

];
