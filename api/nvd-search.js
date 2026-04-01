// api/nvd-search.js — Recherche CVE par mots-clés via NVD API v2
// Utilisé pour enrichir les articles qui n'ont pas de CVE ID dans leur texte RSS.
// La clé API NVD (optionnelle) est stockée côté serveur → 50 req/30s vs 5 sans clé.

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const { q } = req.query;
  if (!q || q.trim().length < 3) {
    return res.status(400).json({ error: "Paramètre 'q' requis (min 3 chars)" });
  }

  const apiKey = process.env.NVD_API_KEY || "";
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(q.slice(0, 150))}&resultsPerPage=5`;

  const headers = {
    Accept: "application/json",
    "User-Agent": "CyberVeille-Pro/2.0 (+https://github.com/dgiry/cyberveille-pro)"
  };
  if (apiKey) headers["apiKey"] = apiKey;

  try {
    const response = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(12_000)
    });

    if (!response.ok) {
      // Graceful handling for 403/429: include hint, add short CDN cache to reduce hammering
      if (response.status === 429) {
        res.setHeader("Cache-Control", "s-maxage=60, stale-while-revalidate=60");
        res.setHeader("Retry-After", "30");
      }
      const hint = response.status === 403
        ? "Forbidden: missing or invalid NVD API key, or request blocked. Configure NVD_API_KEY."
        : response.status === 429
          ? "Rate limit: too many requests to NVD. Please retry later."
          : "Upstream error";
      return res.status(response.status).json({ error: `NVD API: HTTP ${response.status} — ${hint}`, query: q });
    }

    const json = await response.json();

    // Format simplifié : liste de { id, description, published, cvss }
    const cves = (json.vulnerabilities || []).map(v => {
      const cve     = v.cve;
      const metrics = cve.metrics?.cvssMetricV31?.[0]
                   || cve.metrics?.cvssMetricV30?.[0]
                   || cve.metrics?.cvssMetricV2?.[0];
      return {
        id:          cve.id,
        description: (cve.descriptions?.find(d => d.lang === "en")?.value || "").slice(0, 200),
        published:   cve.published,
        cvss:        metrics?.cvssData?.baseScore ?? null
      };
    });

    // Cache CDN 6h — les résultats de recherche changent peu
    res.setHeader("Cache-Control", "s-maxage=21600, stale-while-revalidate=3600");
    res.status(200).json({ cves, total: json.totalResults ?? cves.length, query: q });

  } catch (err) {
    res.status(502).json({ error: `Erreur NVD search : ${err.message}`, query: q });
  }
};
