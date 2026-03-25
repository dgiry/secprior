// api/epss.js — Proxy EPSS (Exploit Prediction Scoring System) — api.first.org
// EPSS = probabilité d'exploitation d'un CVE dans les 30 prochains jours (0 à 1)
// Cache CDN 24h — les scores EPSS sont mis à jour quotidiennement par FIRST

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const { cves } = req.query;
  if (!cves) return res.status(400).json({ error: "Paramètre 'cves' requis (liste CVE séparés par virgule)" });

  // Valider chaque CVE ID (sécurité basique)
  const ids = cves
    .split(",")
    .map(s => s.trim().toUpperCase())
    .filter(s => /^CVE-\d{4}-\d{4,}$/.test(s));

  if (ids.length === 0) {
    return res.status(400).json({ error: "Aucun CVE valide dans la liste" });
  }

  // Limite EPSS API : 1000 CVE par requête (on logue si on dépasse)
  if (ids.length > 1000) {
    console.warn(`[EPSS] Batch trop grand : ${ids.length} CVE (max 1000)`);
  }

  const url = `https://api.first.org/data/v1/epss?cve=${ids.slice(0, 1000).join(",")}`;

  try {
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(12_000)
    });

    if (!response.ok) {
      return res.status(response.status).json({
        error: `EPSS API : HTTP ${response.status}`
      });
    }

    const json = await response.json();

    // Cache CDN 24h (scores EPSS publiés 1×/jour)
    res.setHeader("Cache-Control", "s-maxage=86400, stale-while-revalidate=3600");
    res.status(200).json(json);
  } catch (err) {
    res.status(502).json({ error: `Erreur EPSS : ${err.message}` });
  }
};
