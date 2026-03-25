// feeds.js — Agrégateur RSS multi-sources avec proxy CORS
// Fetch, parse, normalise et déduplique les articles de tous les feeds

/**
 * Génère un ID stable depuis une URL (hash court base64)
 */
function makeId(link) {
  const str = (link || Math.random().toString()).trim();
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}

/**
 * Extrait le texte d'un élément XML par nom de tag (support RSS + Atom)
 */
function getXMLText(item, ...tags) {
  for (const tag of tags) {
    const el = item.querySelector(tag);
    if (el && el.textContent.trim()) {
      return el.textContent.trim();
    }
  }
  return "";
}

/**
 * Extrait le lien d'un item RSS ou Atom
 */
function extractLink(item) {
  // Atom: <link href="..."> ou <link>url</link>
  const linkEl = item.querySelector("link");
  if (linkEl) {
    return linkEl.getAttribute("href") || linkEl.textContent.trim();
  }
  return "";
}

/**
 * Nettoie le HTML d'une description RSS (balises, CDATA)
 */
function stripHTML(str) {
  return (str || "")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 300);
}

/**
 * Parse un document XML RSS/Atom en tableau d'articles normalisés
 */
function parseXML(xmlDoc, feed) {
  // Support RSS (<item>) et Atom (<entry>)
  let items = Array.from(xmlDoc.querySelectorAll("item"));
  if (items.length === 0) {
    items = Array.from(xmlDoc.querySelectorAll("entry"));
  }

  return items.map(item => {
    const title = getXMLText(item, "title");
    const rawDesc = getXMLText(item, "description", "summary", "content");
    const desc = stripHTML(rawDesc);
    const link = extractLink(item) || getXMLText(item, "link", "guid");
    const pubDateStr = getXMLText(item, "pubDate", "published", "updated", "dc\\:date");
    const pubDate = new Date(pubDateStr);

    const id = makeId(link);
    const criticality = scoreItem(title, desc);

    return {
      id,
      title: title || "Sans titre",
      description: desc,
      link,
      pubDate: isNaN(pubDate.getTime()) ? new Date() : pubDate,
      source: feed.id,
      sourceName: feed.name,
      sourceIcon: feed.icon,
      criticality,
      starred: Storage.isFavorite(id)
    };
  }).filter(a => a.title && a.link);
}

// Proxies CORS publics tentés en séquence (mode statique / Hostinger)
const CORS_PROXIES = [
  { url: "https://api.rss2json.com/v1/api.json?rss_url=", format: "rss2json", timeout: 12_000 },
  { url: "https://corsproxy.io/?",                    format: "raw",      timeout: 10_000 },
  { url: "https://api.allorigins.win/get?url=",       format: "json",     timeout: 12_000 },
  { url: "https://api.codetabs.com/v1/proxy/?quest=", format: "raw",      timeout: 10_000 },
  { url: "https://api.cors.lol/?url=",                format: "raw",      timeout: 10_000 },
];

/**
 * Tente de récupérer le contenu d'une URL RSS via plusieurs proxies CORS.
 * Essaie chaque proxy dans l'ordre et retourne le premier résultat valide.
 */
async function _fetchViaProxies(feedUrl, feedName) {
  const errors = [];
  for (const proxy of CORS_PROXIES) {
    try {
      const res = await fetch(proxy.url + encodeURIComponent(feedUrl), {
        signal: AbortSignal.timeout(proxy.timeout)
      });
      if (!res.ok) { errors.push(`${proxy.url}: HTTP ${res.status}`); continue; }

      let text;
      if (proxy.format === "json") {
        const json = await res.json();
        if (!json.contents) { errors.push(`${proxy.url}: contenu vide`); continue; }
        text = json.contents;
      } else if (proxy.format === "rss2json") {
        const json = await res.json();
        if (json.status !== "ok" || !json.items?.length) {
          errors.push(`${proxy.url}: ${json.message || "réponse vide"}`); continue;
        }
        // Reconstruction RSS minimal depuis le JSON rss2json
        const items = json.items.map(i => `<item>
          <title><![CDATA[${i.title || ""}]]></title>
          <link>${i.link || i.guid || ""}</link>
          <description><![CDATA[${i.description || ""}]]></description>
          <pubDate>${i.pubDate || ""}</pubDate>
        </item>`).join("");
        text = `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>${json.feed?.title || ""}</title>${items}</channel></rss>`;
      } else {
        text = await res.text();
      }

      if (!text || text.length < 50) { errors.push(`${proxy.url}: réponse trop courte`); continue; }
      // Supprimer le BOM UTF-8 si présent
      if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
      // Rejeter les réponses HTML
      const t = text.trimStart();
      if (t.startsWith("<!") || t.toLowerCase().startsWith("<html")) {
        errors.push(`${proxy.url}: réponse HTML`); continue;
      }
      // Valider que le contenu est du XML parseable avant de retourner
      const testDoc = new DOMParser().parseFromString(text, "text/xml");
      if (testDoc.querySelector("parsererror")) {
        errors.push(`${proxy.url}: XML invalide`); continue;
      }
      return text;
    } catch (e) {
      errors.push(`${proxy.url}: ${e.message}`);
    }
  }
  throw new Error(`Tous les proxies ont échoué pour ${feedName} (${errors.join(" | ")})`);
}

/**
 * Fetch un seul feed :
 *   - Sur Vercel  → GET /api/fetch-feeds?url=...  (proxy serveur, XML direct)
 *   - En statique → essaie 3 proxies CORS publics en séquence
 */
async function fetchFeed(feed) {
  let xmlText;

  if (CONFIG.USE_API) {
    // ── Mode Vercel : proxy serverless → XML brut ──────────────────────────
    const proxyUrl = `/api/fetch-feeds?url=${encodeURIComponent(feed.url)}`;
    const res = await fetch(proxyUrl, { signal: AbortSignal.timeout(12_000) });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status} pour ${feed.name}`);
    }
    xmlText = await res.text();
  } else {
    // ── Mode statique : multi-proxy CORS ────────────────────────────────────
    xmlText = await _fetchViaProxies(feed.url, feed.name);
  }

  // Normaliser la déclaration d'encodage → UTF-8 pour éviter les échecs du parser strict
  const normalizedXml = xmlText.replace(/(<\?xml[^?]*?)\s+encoding="[^"]*"/i, '$1');
  const parser = new DOMParser();
  let xmlDoc = parser.parseFromString(normalizedXml, "text/xml");

  // Si parseerror, retenter sans la déclaration XML entière
  if (xmlDoc.querySelector("parsererror")) {
    const stripped = xmlText.replace(/<\?xml[^?]*?\?>\s*/i, "");
    xmlDoc = parser.parseFromString(stripped, "text/xml");
  }

  // Détecter les erreurs de parsing XML
  const parseError = xmlDoc.querySelector("parsererror");
  if (parseError) throw new Error(`Erreur XML pour ${feed.name}`);

  return parseXML(xmlDoc, feed);
}

/**
 * Fetch tous les feeds en séquence par petits lots pour éviter le rate-limit
 * des proxies CORS publics. Fusionne et déduplique.
 * Utilise le cache si disponible et non périmé.
 */
async function fetchAllFeeds(forceRefresh = false) {
  // Retourner le cache si frais et pas de forçage
  if (!forceRefresh && !Storage.isCacheStale()) {
    const cache = Storage.getCache();
    if (cache && cache.items && cache.items.length > 0) {
      console.log("[Feeds] Cache utilisé (%d articles)", cache.items.length);
      // Réhydrater les dates (JSON.parse les strings en string)
      return cache.items.map(a => ({ ...a, pubDate: new Date(a.pubDate) }));
    }
  }

  // Utiliser FeedManager.getActiveFeeds() pour inclure les flux custom
  // et respecter les flux désactivés par l'utilisateur
  const activeFeeds = FeedManager.getActiveFeeds();
  console.log("[Feeds] Fetch des %d sources actives (séquentiel)...", activeFeeds.length);

  // Fetch séquentiel par lots de 3 avec 800ms entre chaque lot
  // → évite le rate-limit des proxies CORS publics (notamment rss2json 60 req/h)
  const BATCH_SIZE = 3;
  const BATCH_DELAY = 800; // ms
  const settled = [];
  for (let i = 0; i < activeFeeds.length; i += BATCH_SIZE) {
    const batch = activeFeeds.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.allSettled(batch.map(feed => fetchFeed(feed)));
    settled.push(...batchResults.map((r, j) => ({ result: r, feed: batch[j] })));
    if (i + BATCH_SIZE < activeFeeds.length) {
      await new Promise(res => setTimeout(res, BATCH_DELAY));
    }
  }

  const results = settled.map(s => s.result);
  // réordonner activeFeeds pour correspondre à settled
  const orderedFeeds = settled.map(s => s.feed);

  const allArticles = [];
  const errors = [];

  results.forEach((result, i) => {
    const feed = orderedFeeds[i];
    if (result.status === "fulfilled") {
      allArticles.push(...result.value);
      console.log("[Feeds] ✓ %s : %d articles", feed.name, result.value.length);
      // Mise à jour santé : succès
      FeedManager.recordFetchResult(feed, true, result.value.length, "");
    } else {
      errors.push(feed.name);
      const msg = result.reason?.message || "Erreur inconnue";
      console.warn("[Feeds] ✗ %s : %s", feed.name, msg);
      // Mise à jour santé : erreur
      FeedManager.recordFetchResult(feed, false, 0, msg);
    }
  });

  if (errors.length > 0) {
    console.warn("[Feeds] Sources en erreur :", errors.join(", "));
  }

  // Si tous les feeds ont échoué → utiliser les données de démo
  if (allArticles.length === 0 && typeof DEMO_ARTICLES !== "undefined") {
    console.info("[Feeds] Aucun article récupéré. Mode démo activé.");
    return DEMO_ARTICLES.map(a => ({ ...a, pubDate: new Date(a.pubDate) }));
  }

  // Dédupliquer par id
  const seen = new Set();
  const unique = allArticles.filter(a => {
    if (seen.has(a.id)) return false;
    seen.add(a.id);
    return true;
  });

  // Trier par date décroissante
  unique.sort((a, b) => b.pubDate - a.pubDate);

  // Mettre en cache
  Storage.setCache(unique);

  return unique;
}
