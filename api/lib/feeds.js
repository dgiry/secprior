// api/lib/feeds.js — Source canonique des flux RSS côté serveur
//
// ⚠️  Si vous ajoutez ou modifiez un flux ici, répercutez-le dans CONFIG.FEEDS
//     de js/config.js (front) pour que l'interface et le cron restent synchrones.
//
// Les champs icon / lang sont omis (inutiles côté serveur).

"use strict";

const FEEDS = [
  { id: "thehackernews",    name: "The Hacker News",        url: "https://feeds.feedburner.com/TheHackersNews" },
  { id: "krebsonsecurity",  name: "Krebs on Security",      url: "https://krebsonsecurity.com/feed/" },
  { id: "bleepingcomputer", name: "Bleeping Computer",      url: "https://www.bleepingcomputer.com/feed/" },
  { id: "zataz",            name: "Zataz",                  url: "https://www.zataz.com/feed/" },
  { id: "certfr",           name: "CERT-FR",                url: "https://www.cert.ssi.gouv.fr/feed/" },
  { id: "cisa",             name: "CISA Advisories",        url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { id: "zdi",              name: "Zero Day Initiative",    url: "https://www.zerodayinitiative.com/rss/published/" },
  { id: "welivesecurity",   name: "WeLiveSecurity (ESET)",  url: "https://www.welivesecurity.com/feed/" },
  { id: "sans",             name: "SANS ISC",               url: "https://isc.sans.edu/rssfeed_full.xml" },
  { id: "talos",            name: "Cisco Talos",            url: "https://blog.talosintelligence.com/rss/" },
  { id: "securelist",       name: "Securelist (Kaspersky)", url: "https://securelist.com/feed/" },
  { id: "unit42",           name: "Unit 42 (Palo Alto)",    url: "https://unit42.paloaltonetworks.com/feed/" },
  { id: "ncsc",             name: "NCSC UK",                url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml" }
];

module.exports = { FEEDS };
