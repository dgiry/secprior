// api/trend-vp.js — Trend Vision One Virtual Patch availability proxy
//
// GET /api/trend-vp?cveId=CVE-2025-XXXX[&region=us|eu|au|in|sg|jp]
//
// Behaviour:
//   • TV1_API_KEY not set → returns { status: "unknown", reason: "not_configured" }
//   • TV1_API_KEY set     → queries Vision One IPS filter catalog for the CVE
//
// Returns: { cveId, status, filterId?, filterName?, publishedAt?, source, cachedAt }
//   status: "available" | "not_available" | "unknown"
//
// Security:
//   • TV1_API_KEY never logged or forwarded to client
//   • Region validated against allowlist
//   • cveId validated by regex before use in URL

"use strict";

const REGION_BASES = {
  us: "https://api.xdr.trendmicro.com",
  eu: "https://api.eu.xdr.trendmicro.com",
  au: "https://api.au.xdr.trendmicro.com",
  in: "https://api.in.xdr.trendmicro.com",
  sg: "https://api.sg.xdr.trendmicro.com",
  jp: "https://api.jp.xdr.trendmicro.com"
};

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const { cveId, region = "us" } = req.query;

  // Validate cveId
  if (!cveId) return res.status(400).json({ error: "Parameter 'cveId' required" });
  if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
    return res.status(400).json({ error: "Invalid CVE format (expected: CVE-YYYY-NNNNN)" });
  }

  // Validate region
  const base = REGION_BASES[region] || REGION_BASES.us;

  const apiKey = process.env.TV1_API_KEY || "";
  if (!apiKey) {
    return res.status(200).json({
      cveId:     cveId.toUpperCase(),
      status:    "unknown",
      reason:    "not_configured",
      source:    "trend_v1",
      cachedAt:  Date.now()
    });
  }

  const url = `${base}/v3.0/ips/filters?cveId=${encodeURIComponent(cveId.toUpperCase())}`;

  try {
    const response = await fetch(url, {
      headers: {
        "TMV1-Authorization": `Bearer ${apiKey}`,
        "Accept":             "application/json",
        "User-Agent":         "CyberVeille-Pro/2.0 (+https://github.com/dgiry/cyberveille-pro)"
      },
      signal: AbortSignal.timeout(12_000)
    });

    if (response.status === 429) {
      const retryAfter = response.headers.get("Retry-After") || "60";
      res.setHeader("Retry-After", retryAfter);
      res.setHeader("Cache-Control", "s-maxage=60");
      return res.status(429).json({ error: "Rate limited by Vision One API", retryAfter });
    }

    if (!response.ok) {
      return res.status(200).json({
        cveId:    cveId.toUpperCase(),
        status:   "unknown",
        reason:   `tv1_http_${response.status}`,
        source:   "trend_v1",
        cachedAt: Date.now()
      });
    }

    const json = await response.json();
    const items = json?.items || [];
    const upper = cveId.toUpperCase();
    const hit   = items.find(f =>
      (f.cveIds || []).some(c => c.toUpperCase() === upper)
    );

    // Cache 24h on CDN — VP catalog changes slowly
    res.setHeader("Cache-Control", "s-maxage=86400, stale-while-revalidate=3600");

    if (!hit) {
      return res.status(200).json({
        cveId:    upper,
        status:   "not_available",
        source:   "trend_v1",
        cachedAt: Date.now()
      });
    }

    return res.status(200).json({
      cveId:       upper,
      status:      "available",
      filterId:    String(hit.id   || ""),
      filterName:  hit.name        || "",
      publishedAt: hit.publishedAt || null,
      source:      "trend_v1",
      cachedAt:    Date.now()
    });

  } catch (err) {
    const reason = err.name === "TimeoutError" ? "timeout" : "network_error";
    return res.status(200).json({
      cveId:    cveId.toUpperCase(),
      status:   "unknown",
      reason,
      source:   "trend_v1",
      cachedAt: Date.now()
    });
  }
};
