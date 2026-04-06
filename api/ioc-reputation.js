// api/ioc-reputation.js — IOC reputation lookup via AlienVault OTX
//
// Option C of the IOC enrichment strategy:
//   For each extracted IOC (IP, domain, hash, URL), query the OTX public API
//   to determine if it is known in the threat intelligence community.
//
// GET /api/ioc-reputation?type=ip|domain|hash|url&value=<value>
// → { verdict: "malicious"|"suspicious"|"clean", pulses: N, labels: [...], source: "otx" }
//
// Prerequisites:
//   • Set OTX_API_KEY in Vercel environment variables (free account: otx.alienvault.com)
//   • Optional: VT_API_KEY for VirusTotal cross-reference (free tier: 4 req/min)
//
// Verdict logic (OTX):
//   pulses === 0        → "clean"     (not seen in any threat feed)
//   1 ≤ pulses < 3      → "suspicious" (mentioned in a few feeds)
//   pulses ≥ 3          → "malicious"  (widely known indicator)
//
// Cache: 30 min per IOC (CDN + client) — reputation data is reasonably stable.

"use strict";

// OTX indicator type mapping
const OTX_TYPE = {
  ip:     "IPv4",
  domain: "domain",
  hash:   "file",
  url:    "url"
};

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET")
    return res.status(405).json({ error: "Method not allowed" });

  const { type, value } = req.query;
  if (!type || !value)
    return res.status(400).json({ error: "Missing required params: type, value" });

  const otxType = OTX_TYPE[type];
  if (!otxType)
    return res.status(400).json({ error: `Unknown IOC type: ${type}. Use: ip, domain, hash, url` });

  // ── OTX ─────────────────────────────────────────────────────────────────────
  const otxKey = process.env.OTX_API_KEY;
  if (!otxKey) {
    return res.status(503).json({
      error: "OTX_API_KEY not configured — add it to Vercel Environment Variables"
    });
  }

  // Build OTX endpoint — URL type must be encoded in the path
  const indicator = type === "url"
    ? encodeURIComponent(value)
    : encodeURIComponent(value);
  const otxUrl = `https://otx.alienvault.com/api/v1/indicators/${otxType}/${indicator}/general`;

  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 8_000);

    const resp = await fetch(otxUrl, {
      headers: { "X-OTX-API-KEY": otxKey },
      signal:  controller.signal
    });
    clearTimeout(timeout);

    // OTX returns 404 for completely unknown indicators — treat as clean
    if (resp.status === 404) {
      res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=7200");
      return res.status(200).json({ verdict: "clean", pulses: 0, labels: [], source: "otx" });
    }

    if (!resp.ok)
      return res.status(resp.status).json({ error: `OTX returned HTTP ${resp.status}` });

    const data = await resp.json();

    const pulses = data.pulse_info?.count || 0;
    // Collect up to 5 pulse names as human-readable labels
    const labels = (data.pulse_info?.pulses || [])
      .slice(0, 5)
      .map(p => p.name)
      .filter(Boolean);

    const verdict = pulses === 0 ? "clean"
                  : pulses  <  3 ? "suspicious"
                  :                "malicious";

    // Cache 30 min — OTX data is updated regularly but not real-time
    res.setHeader("Cache-Control", "s-maxage=1800, stale-while-revalidate=3600");
    return res.status(200).json({ verdict, pulses, labels, source: "otx" });

  } catch (err) {
    const msg = err.name === "AbortError"
      ? "OTX did not respond within 8 s"
      : err.message;
    return res.status(500).json({ error: msg });
  }
};
