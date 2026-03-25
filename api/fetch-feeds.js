// api/fetch-feeds.js — Proxy RSS Vercel Serverless
// Remplace allorigins.win : fetch le flux RSS côté serveur et renvoie le XML brut
// Avantage : pas de dépendance externe, cache CDN Vercel 5 min, aucune clé API exposée

module.exports = async (req, res) => {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Paramètre 'url' requis" });

  // Sécurité : autoriser uniquement les URLs http/https
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({ error: "Protocole non autorisé" });
    }
  } catch {
    return res.status(400).json({ error: "URL invalide" });
  }

  try {
    const response = await fetch(url, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; CyberVeille-Pro/2.0; +https://github.com/cyberveille)",
        Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"
      },
      signal: AbortSignal.timeout(10_000)
    });

    if (!response.ok) {
      return res.status(502).json({
        error: `Flux RSS inaccessible (HTTP ${response.status})`,
        feedUrl: url
      });
    }

    const contentType = response.headers.get("content-type") || "application/xml";
    const body = await response.text();

    // Cache CDN Vercel 5 minutes, stale-while-revalidate 1 heure
    res.setHeader("Cache-Control", "s-maxage=300, stale-while-revalidate=3600");
    res.setHeader("Content-Type", "application/xml; charset=utf-8");
    res.status(200).send(body);
  } catch (err) {
    const isTimeout = err.name === "TimeoutError" || err.message?.includes("timeout");
    res.status(isTimeout ? 504 : 502).json({
      error: isTimeout
        ? `Délai dépassé pour ${url}`
        : `Erreur proxy : ${err.message}`
    });
  }
};
