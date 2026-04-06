// api/nvd.js — Proxy NVD (NIST National Vulnerability Database)
//
// Merged from api/nvd.js + api/nvd-search.js
// (Vercel Hobby plan: 12 serverless function limit)
//
// Dispatch via query parameter:
//
//   GET /api/nvd?cveId=CVE-2024-XXXX
//   → Full NVD JSON for one CVE (cached 24h CDN)
//
//   GET /api/nvd?q=<keyword>
//   → { cves: [...], total, query } — keyword search, max 5 results (cached 6h CDN)
//
// Advantage: NVD_API_KEY stored server-side → 50 req/30s vs 5 without key.

"use strict";

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const { cveId, q } = req.query;

  if (cveId)           return _handleLookup(req, res, cveId);
  if (q?.trim()?.length >= 3) return _handleSearch(req, res, q);

  return res.status(400).json({
    error: "Paramètre 'cveId' ou 'q' (min 3 chars) requis"
  });
};

// ── Shared helpers ────────────────────────────────────────────────────────────

function _nvdHeaders() {
  const apiKey  = process.env.NVD_API_KEY || "";
  const headers = {
    Accept:        "application/json",
    "User-Agent":  "CyberVeille-Pro/2.0 (+https://github.com/dgiry/cyberveille-pro)"
  };
  if (apiKey) headers["apiKey"] = apiKey;
  return headers;
}

function _errHint(status) {
  if (status === 403) return "Forbidden: missing/invalid NVD API key. Set NVD_API_KEY.";
  if (status === 429) return "Rate limit reached. Please retry later.";
  return "Upstream error";
}

// ── GET /api/nvd?cveId= ───────────────────────────────────────────────────────

async function _handleLookup(req, res, cveId) {
  if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId))
    return res.status(400).json({ error: "Format CVE invalide (attendu: CVE-YYYY-NNNNN)" });

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId.toUpperCase())}`;

  try {
    const response = await fetch(url, {
      headers: _nvdHeaders(),
      signal:  AbortSignal.timeout(12_000)
    });

    if (!response.ok) {
      if (response.status === 429) {
        res.setHeader("Cache-Control", "s-maxage=300, stale-while-revalidate=600");
        res.setHeader("Retry-After",   "60");
      }
      return res.status(response.status).json({
        error: `NVD API: HTTP ${response.status} — ${_errHint(response.status)}`,
        cveId
      });
    }

    const json = await response.json();
    res.setHeader("Cache-Control", "s-maxage=86400, stale-while-revalidate=3600");
    return res.status(200).json(json);

  } catch (err) {
    return res.status(502).json({ error: `Erreur NVD : ${err.message}`, cveId });
  }
}

// ── GET /api/nvd?q= ───────────────────────────────────────────────────────────

async function _handleSearch(req, res, q) {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(q.slice(0, 150))}&resultsPerPage=5`;

  try {
    const response = await fetch(url, {
      headers: _nvdHeaders(),
      signal:  AbortSignal.timeout(12_000)
    });

    if (!response.ok) {
      if (response.status === 429) {
        res.setHeader("Cache-Control", "s-maxage=60, stale-while-revalidate=60");
        res.setHeader("Retry-After",   "30");
      }
      return res.status(response.status).json({
        error: `NVD API: HTTP ${response.status} — ${_errHint(response.status)}`,
        query: q
      });
    }

    const json = await response.json();

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

    res.setHeader("Cache-Control", "s-maxage=21600, stale-while-revalidate=3600");
    return res.status(200).json({ cves, total: json.totalResults ?? cves.length, query: q });

  } catch (err) {
    return res.status(502).json({ error: `Erreur NVD search : ${err.message}`, query: q });
  }
}
