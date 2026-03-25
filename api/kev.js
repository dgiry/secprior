// api/kev.js — Proxy CISA KEV (Known Exploited Vulnerabilities)
// Source officielle : https://www.cisa.gov/known-exploited-vulnerabilities-catalog
// ~1 200 CVE exploités activement confirmés par CISA
// Cache CDN 24h — la liste est mise à jour plusieurs fois par semaine

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const KEV_URL =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

  try {
    const response = await fetch(KEV_URL, {
      headers: {
        Accept: "application/json",
        "User-Agent": "CyberVeille-Pro/2.0"
      },
      signal: AbortSignal.timeout(15_000)
    });

    if (!response.ok) {
      return res.status(response.status).json({
        error: `CISA KEV inaccessible (HTTP ${response.status})`
      });
    }

    const json = await response.json();

    // Statistiques de debug
    const count = json.vulnerabilities?.length ?? 0;
    console.log(`[KEV] ${count} vulnérabilités chargées depuis CISA`);

    // Cache CDN 24h
    res.setHeader("Cache-Control", "s-maxage=86400, stale-while-revalidate=7200");
    res.status(200).json(json);
  } catch (err) {
    res.status(502).json({ error: `Erreur CISA KEV : ${err.message}` });
  }
};
