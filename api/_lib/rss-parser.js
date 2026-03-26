// api/lib/rss-parser.js — Parseur RSS/Atom minimal, sans dépendance externe
// Compatible Node.js 18+. Pas de DOM, pas de DOMParser.

"use strict";

/**
 * Extrait le texte brut entre deux balises XML (première occurrence).
 * Gère CDATA et supprime les balises HTML résiduelles.
 */
function _tag(xml, name) {
  const re = new RegExp(`<${name}[^>]*>([\\s\\S]*?)<\\/${name}>`, "i");
  const m  = xml.match(re);
  if (!m) return "";
  return m[1]
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#?\w+;/g, "")
    .trim();
}

/** Extrait l'URL du lien (Atom href ou texte RSS). */
function _link(itemXml) {
  const atom = itemXml.match(/<link[^>]+href="([^"]+)"/i);
  if (atom) return atom[1].trim();
  const rss  = itemXml.match(/<link[^>]*>([^<]+)<\/link>/i);
  return rss ? rss[1].trim() : "";
}

/** Extrait les identifiants CVE depuis un texte. */
function _extractCVEs(text) {
  return [...new Set((text.match(/CVE-\d{4}-\d{4,}/gi) || []).map(s => s.toUpperCase()))];
}

/**
 * Parse un flux RSS 2.0 ou Atom 1.0 et retourne un tableau d'articles normalisés.
 * Champs retournés : { id, title, link, description, pubDate, sourceName,
 *                      cveIds, isKEV, epssScore, cvssScore, score,
 *                      sourceCount, isTrending, watchlistMatches, attackTags, tags }
 * @param {string} xmlText   - contenu XML brut du flux
 * @param {string} sourceName - nom de la source (affiché dans l'email)
 * @returns {Array}
 */
function parseRSS(xmlText, sourceName) {
  if (!xmlText || xmlText.length < 50) return [];

  const isAtom  = /<feed\b/i.test(xmlText);
  const itemTag = isAtom ? "entry" : "item";
  const items   = [];

  const re = new RegExp(`<${itemTag}[\\s>][\\s\\S]*?<\\/${itemTag}>`, "gi");
  let match;

  while ((match = re.exec(xmlText)) !== null && items.length < 50) {
    const item = match[0];

    const title = _tag(item, "title") || "(sans titre)";
    const link  = _link(item);
    if (!link) continue;

    const dateStr = _tag(item, "pubDate") || _tag(item, "published") || _tag(item, "updated") || "";
    const pubDate = dateStr ? new Date(dateStr) : new Date();

    const description = (_tag(item, "description") || _tag(item, "summary") || _tag(item, "content"))
      .substring(0, 500);

    const rawId = _tag(item, "guid") || _tag(item, "id") || link;
    const id    = rawId.replace(/\s+/g, "").substring(0, 300);

    const cveIds = _extractCVEs(title + " " + description);

    items.push({
      id,
      title:            title.substring(0, 200),
      link,
      description,
      pubDate:          isNaN(pubDate) ? new Date() : pubDate,
      sourceName:       sourceName || "Unknown",
      cveIds,
      // Champs enrichis (remplis par le pipeline front ou laissés à null ici)
      isKEV:            false,
      epssScore:        null,
      cvssScore:        null,
      score:            null,
      sourceCount:      1,
      isTrending:       false,
      watchlistMatches: [],
      attackTags:       [],
      tags:             []
    });
  }

  return items;
}

module.exports = { parseRSS };
