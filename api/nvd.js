// api/nvd.js — Proxy NVD (NIST National Vulnerability Database)
// Avantage : clé API NVD stockée côté serveur (env var), rate-limit mutualisé,
//            cache CDN 24h → 50× moins de requêtes NVD vs client direct

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const { cveId } = req.query;
  if (!cveId) return res.status(400).json({ error: "Paramètre 'cveId' requis" });

  // Valider le format CVE
  if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
    return res.status(400).json({ error: "Format CVE invalide (attendu: CVE-YYYY-NNNNN)" });
  }

  const apiKey = process.env.NVD_API_KEY || "";
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(
    cveId.toUpperCase()
  )}`;

  const headers = { Accept: "application/json" };
  if (apiKey) headers["apiKey"] = apiKey; // 50 req/30s avec clé vs 5 sans

  try {
    const response = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(12_000)
    });

    if (!response.ok) {
      return res.status(response.status).json({
        error: `NVD API : HTTP ${response.status}`,
        cveId
      });
    }

    const json = await response.json();

    // Cache CDN 24h — les données NVD changent rarement
    res.setHeader("Cache-Control", "s-maxage=86400, stale-while-revalidate=3600");
    res.status(200).json(json);
  } catch (err) {
    res.status(502).json({ error: `Erreur NVD : ${err.message}`, cveId });
  }
};
