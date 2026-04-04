// api/lib/feeds.js — SOURCE CANONIQUE UNIQUE des flux RSS (front + back)
//
// Ce fichier est la seule source de vérité pour la liste des flux.
// Il est servi au front via GET /api/feeds (api/feeds.js).
// Il est importé directement par le cron (api/scheduled-digest.js).
//
// ⚠️  NE PLUS modifier CONFIG.FEEDS dans js/config.js — modifier uniquement ici.
//     CONFIG.FEEDS dans config.js sert uniquement de FALLBACK si /api/feeds est
//     indisponible (mode statique Hostinger ou erreur réseau).

"use strict";

const FEEDS = [
  // ── Operational: Official advisories & alerts ──────────────────────────────
  { id: "certfr-alertes",   name: "CERT-FR Alertes",        url: "https://www.cert.ssi.gouv.fr/alerte/feed/",                      lang: "fr", icon: "🇫🇷" },
  { id: "certfr-bulletins", name: "CERT-FR Bulletins",      url: "https://www.cert.ssi.gouv.fr/actualite/feed/",                   lang: "fr", icon: "🇫🇷" },
  { id: "certfr",           name: "CERT-FR",                url: "https://www.cert.ssi.gouv.fr/feed/",                              lang: "fr", icon: "🇫🇷" },
  { id: "cisa",             name: "CISA Advisories",        url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",           lang: "en", icon: "🦅" },
  { id: "cisa-ics",         name: "CISA ICS Advisories",    url: "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", lang: "en", icon: "🦅" },
  { id: "ncsc",             name: "NCSC UK",                url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",     lang: "en", icon: "🇬🇧" },
  { id: "certeu",           name: "CERT-EU",                url: "https://www.cert.europa.eu/publications/security-advisories-rss", lang: "en", icon: "🇪🇺" },
  { id: "cyber-centre",     name: "Cyber Centre Canada",    url: "https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en",                            lang: "en", icon: "🇨🇦" },
  { id: "zdi",              name: "Zero Day Initiative",    url: "https://www.zerodayinitiative.com/rss/published/",                lang: "en", icon: "💀" },
  { id: "sans",             name: "SANS ISC",               url: "https://isc.sans.edu/rssfeed_full.xml",                          lang: "en", icon: "⚡" },
  { id: "bleepingcomputer", name: "Bleeping Computer",      url: "https://www.bleepingcomputer.com/feed/",                          lang: "en", icon: "🟣" },
  { id: "securityweek",     name: "SecurityWeek",           url: "https://www.securityweek.com/feed/",                              lang: "en", icon: "📰" },

  // ── CTI / Campaigns: Threat intelligence & research ─────────────────────────
  { id: "thehackernews",    name: "The Hacker News",        url: "https://feeds.feedburner.com/TheHackersNews",                     lang: "en", icon: "🔴" },
  { id: "krebsonsecurity",  name: "Krebs on Security",      url: "https://krebsonsecurity.com/feed/",                               lang: "en", icon: "🔵" },
  { id: "talos",            name: "Cisco Talos",            url: "https://blog.talosintelligence.com/rss/",                        lang: "en", icon: "🔬" },
  { id: "unit42",           name: "Unit 42 (Palo Alto)",    url: "https://unit42.paloaltonetworks.com/feed/",                      lang: "en", icon: "🔭" },
  { id: "securelist",       name: "Securelist (Kaspersky)", url: "https://securelist.com/feed/",                                   lang: "en", icon: "🕵️" },
  { id: "welivesecurity",   name: "WeLiveSecurity (ESET)",  url: "https://www.welivesecurity.com/feed/",                           lang: "en", icon: "🧨" },

  // ── Strategic: Broader intelligence & analysis ──────────────────────────────
  { id: "zataz",            name: "Zataz",                  url: "https://www.zataz.com/feed/",                                     lang: "fr", icon: "🟠" }
];

module.exports = { FEEDS };
