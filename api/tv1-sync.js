// api/tv1-sync.js — Trend Vision One unified endpoint (v3)
//
// MODE 1 — Watchlist Sync (default)
//   GET /api/tv1-sync?region=us|eu|au|in|sg|jp[&demo=1]
//   • demo=1 OR TV1_API_KEY not set → curated demo dataset
//   • TV1_API_KEY configured        → calls TV1 V3.0 endpoint inventory API
//   Returns: { items, source, count, fetchedAt, note?, errorCode? }
//
// MODE 2 — Virtual Patch lookup
//   GET /api/tv1-sync?mode=vp&cveId=CVE-YYYY-NNNNN[&region=us]
//   • TV1_API_KEY not set → { status: "unknown", reason: "not_configured" }
//   • TV1_API_KEY set     → queries IPS filter catalog
//   Returns: { cveId, status, filterId?, filterName?, publishedAt?, source, cachedAt }
//     status: "available" | "not_available" | "unknown"
//
// Security:
//   • TV1_API_KEY never logged or forwarded to client
//   • Region validated against allowlist
//   • cveId validated by regex

"use strict";

// Curated demo dataset — representative of a real mid-size enterprise TV1 environment.
// Selected for high match-rate against typical CVE/threat intel feeds.
const TV1_DEMO_ITEMS = [
  { type: "vendor",     label: "Microsoft",            value: "microsoft" },
  { type: "vendor",     label: "VMware",               value: "vmware" },
  { type: "vendor",     label: "Cisco",                value: "cisco" },
  { type: "vendor",     label: "Fortinet",             value: "fortinet" },
  { type: "product",    label: "Windows Server",       value: "windows server" },
  { type: "product",    label: "Exchange Server",      value: "exchange" },
  { type: "product",    label: "Active Directory",     value: "active directory" },
  { type: "technology", label: "Remote Desktop (RDP)", value: "rdp" },
  { type: "technology", label: "PowerShell",           value: "powershell" },
];

// TV1 regional base URLs (V3.0 API)
const TV1_BASE = {
  us: "https://api.xdr.trendmicro.com",
  eu: "https://api.eu.xdr.trendmicro.com",
  au: "https://api.au.xdr.trendmicro.com",
  in: "https://api.in.xdr.trendmicro.com",
  sg: "https://api.sg.xdr.trendmicro.com",
  jp: "https://api.jp.xdr.trendmicro.com",
};

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET")     return res.status(405).json({ error: "Method not allowed" });

  // ── Route to Virtual Patch mode ───────────────────────────────────────────
  if (req.query.mode === "vp")     return _handleVP(req, res);
  if (req.query.mode === "search") return _handleSearch(req, res);

  const forceDemo = req.query.demo === "1";
  const apiKey    = process.env.TV1_API_KEY;
  const region    = ((req.query.region || process.env.TV1_REGION || "us")).toLowerCase();

  // ── Demo / unconfigured mode ──────────────────────────────────────────────
  if (forceDemo || !apiKey) {
    return res.status(200).json({
      items:     TV1_DEMO_ITEMS,
      source:    "tv1_demo",
      count:     TV1_DEMO_ITEMS.length,
      fetchedAt: new Date().toISOString(),
      note: apiKey
        ? undefined
        : "TV1_API_KEY not configured in Vercel — returning demo dataset. " +
          "Add TV1_API_KEY (and optionally TV1_REGION) to Vercel environment variables to enable live sync."
    });
  }

  // ── Live mode — call TV1 V3.0 endpoint inventory ──────────────────────────
  const baseUrl  = TV1_BASE[region] || TV1_BASE.us;
  const endpoint = `${baseUrl}/v3.0/endpointSecurity/endpoints?top=200`;

  let tv1Res;
  try {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), 14_000);
    tv1Res = await fetch(endpoint, {
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type":  "application/json"
        // Note: TV1-Filter header omitted — sending an empty value breaks some API versions
      },
      signal: controller.signal
    });
    clearTimeout(timer);
  } catch (e) {
    if (e.name === "AbortError") {
      // Do NOT log the full error — it could expose the constructed URL with region
      console.warn("[tv1-sync] timeout reaching TV1 API (region:", region, ")");
      return res.status(504).json({
        error:     "Délai TV1 dépassé",
        errorCode: "TIMEOUT"
      });
    }
    // Network-level error: log message only (never the full error object)
    console.warn("[tv1-sync] network error:", e.message);
    return res.status(502).json({
      error:     "Impossible de joindre TV1 API",
      errorCode: "NETWORK_ERROR"
    });
  }

  if (!tv1Res.ok) {
    // SECURITY: consume body but do NOT forward it — TV1 error bodies can contain
    // internal details (tenant IDs, stack traces, internal URLs).
    await tv1Res.text().catch(() => ""); // drain to avoid keep-alive issues
    console.warn("[tv1-sync] TV1 HTTP error:", tv1Res.status, "— region:", region);

    // 401 — invalid API key: graceful demo fallback + explicit errorCode
    if (tv1Res.status === 401) {
      return res.status(200).json({
        items:     TV1_DEMO_ITEMS,
        source:    "tv1_demo",
        count:     TV1_DEMO_ITEMS.length,
        fetchedAt: new Date().toISOString(),
        errorCode: "AUTH_INVALID",
        note:      "Clé API TV1 invalide (HTTP 401). Vérifiez TV1_API_KEY dans les variables d'environnement Vercel."
      });
    }

    // 403 — insufficient scope: graceful demo fallback + explicit errorCode
    if (tv1Res.status === 403) {
      return res.status(200).json({
        items:     TV1_DEMO_ITEMS,
        source:    "tv1_demo",
        count:     TV1_DEMO_ITEMS.length,
        fetchedAt: new Date().toISOString(),
        errorCode: "AUTH_SCOPE",
        note:      "Scope insuffisant (HTTP 403). Le token TV1 doit avoir le scope endpoint-security:read."
      });
    }

    // 429 — rate limit: do NOT fall back to demo, signal client to retry later
    if (tv1Res.status === 429) {
      const retryAfter = parseInt(tv1Res.headers.get("Retry-After") || "60", 10);
      return res.status(429).json({
        error:              "TV1 rate limit atteint",
        errorCode:          "RATE_LIMITED",
        retryAfterSeconds:  isNaN(retryAfter) ? 60 : retryAfter
      });
    }

    // Other TV1 errors — generic, no body leak
    return res.status(502).json({
      error:     "Erreur TV1 API",
      errorCode: "TV1_ERROR",
      httpStatus: tv1Res.status
    });
  }

  const data  = await tv1Res.json();
  const items = _normalizeEndpoints(data.items || []);

  // If normalization returned nothing, fall back to demo so the UI always has something useful
  if (items.length === 0) {
    return res.status(200).json({
      items:     TV1_DEMO_ITEMS,
      source:    "tv1_demo",
      count:     TV1_DEMO_ITEMS.length,
      fetchedAt: new Date().toISOString(),
      note:      "Live sync returned 0 normalizable items — showing demo data as fallback."
    });
  }

  return res.status(200).json({
    items,
    source:    "tv1_live",
    count:     items.length,
    fetchedAt: new Date().toISOString()
  });
};

// ── Search handler ────────────────────────────────────────────────────────────
// GET /api/tv1-sync?mode=search&q=<indicator>&type=cve|ip|hash|domain[&region=us]
//
// Queries Workbench alerts with TMV1-Filter: indicatorValue eq '<q>'
// Returns: { query, type, status, alertCount, topSeverity, latestAlert, source, cachedAt }
//   status: "found" | "not_found" | "unknown"

const _SEV_ORDER = ["critical", "high", "medium", "low"];

async function _handleSearch(req, res) {
  const { q, type = "cve" } = req.query;
  if (!q) return res.status(400).json({ error: "Parameter 'q' required" });

  const ALLOWED_TYPES = ["cve", "ip", "hash", "domain"];
  if (!ALLOWED_TYPES.includes(type))
    return res.status(400).json({ error: "Invalid type" });

  // Sanitize: strip quotes/control chars, cap length
  const sanitized = q.trim().replace(/['"\\]/g, "").slice(0, 256);
  if (!sanitized) return res.status(400).json({ error: "Empty query" });

  const _unknown = (reason) => res.status(200).json({
    query: sanitized, type, status: "unknown", reason,
    alertCount: null, topSeverity: null, latestAlert: null,
    source: "trend_v1", cachedAt: Date.now()
  });

  const apiKey = process.env.TV1_API_KEY || "";
  if (!apiKey) return _unknown("not_configured");

  const region  = ((req.query.region || process.env.TV1_REGION || "us")).toLowerCase();
  const base    = TV1_BASE[region] || TV1_BASE.us;
  // Fetch top 5 alerts matching the indicator — enough to extract severity/latest
  const url     = `${base}/v3.0/workbench/alerts?orderBy=createdDateTime%20desc&top=5`;

  try {
    const tv1Res = await fetch(url, {
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "TMV1-Filter":   `indicatorValue eq '${sanitized}'`,
        "Accept":        "application/json",
        "User-Agent":    "CyberVeille-Pro/2.0"
      },
      signal: AbortSignal.timeout(10_000)
    });

    if (tv1Res.status === 429) {
      const ra = tv1Res.headers.get("Retry-After") || "60";
      res.setHeader("Retry-After", ra);
      return res.status(429).json({ error: "Rate limited", retryAfter: ra });
    }
    if (!tv1Res.ok) return _unknown(`tv1_http_${tv1Res.status}`);

    const json  = await tv1Res.json();
    const total = typeof json.totalCount === "number" ? json.totalCount : (json.items || []).length;
    const items = json.items || [];

    res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=300");

    if (total === 0) {
      return res.status(200).json({
        query: sanitized, type, status: "not_found",
        alertCount: 0, topSeverity: null, latestAlert: null,
        source: "trend_v1", cachedAt: Date.now()
      });
    }

    // Top severity across returned items
    const topSeverity = items.reduce((best, item) => {
      const sev = (item.severity || "").toLowerCase();
      const idx = _SEV_ORDER.indexOf(sev);
      if (idx === -1) return best;
      return best === null || idx < _SEV_ORDER.indexOf(best) ? sev : best;
    }, null);

    const latest = items[0] || null;

    return res.status(200).json({
      query: sanitized, type, status: "found",
      alertCount: total, topSeverity,
      latestAlert: latest ? {
        id:        latest.id || null,
        name:      (latest.name || latest.description || "").slice(0, 120),
        severity:  latest.severity || null,
        createdAt: latest.createdDateTime || null
      } : null,
      source: "trend_v1", cachedAt: Date.now()
    });

  } catch (err) {
    return _unknown(err.name === "TimeoutError" ? "timeout" : "network_error");
  }
}

// ── Virtual Patch handler ─────────────────────────────────────────────────────
// GET /api/tv1-sync?mode=vp&cveId=CVE-YYYY-NNNNN[&region=us]

async function _handleVP(req, res) {
  const { cveId, region = "us" } = req.query;

  if (!cveId) return res.status(400).json({ error: "Parameter 'cveId' required" });
  if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId))
    return res.status(400).json({ error: "Invalid CVE format (expected: CVE-YYYY-NNNNN)" });

  const apiKey = process.env.TV1_API_KEY || "";
  if (!apiKey) {
    return res.status(200).json({
      cveId: cveId.toUpperCase(), status: "unknown",
      reason: "not_configured", source: "trend_v1", cachedAt: Date.now()
    });
  }

  const base = TV1_BASE[region] || TV1_BASE.us;
  const url  = `${base}/v3.0/ips/filters?cveId=${encodeURIComponent(cveId.toUpperCase())}`;

  try {
    const tv1Res = await fetch(url, {
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Accept": "application/json",
        "User-Agent": "CyberVeille-Pro/2.0"
      },
      signal: AbortSignal.timeout(12_000)
    });

    if (tv1Res.status === 429) {
      const ra = tv1Res.headers.get("Retry-After") || "60";
      res.setHeader("Retry-After", ra);
      return res.status(429).json({ error: "Rate limited", retryAfter: ra });
    }
    if (!tv1Res.ok) {
      return res.status(200).json({
        cveId: cveId.toUpperCase(), status: "unknown",
        reason: `tv1_http_${tv1Res.status}`, source: "trend_v1", cachedAt: Date.now()
      });
    }

    const json  = await tv1Res.json();
    const items = json?.items || [];
    const upper = cveId.toUpperCase();
    const hit   = items.find(f => (f.cveIds || []).some(c => c.toUpperCase() === upper));

    res.setHeader("Cache-Control", "s-maxage=86400, stale-while-revalidate=3600");

    if (!hit) {
      return res.status(200).json({
        cveId: upper, status: "not_available", source: "trend_v1", cachedAt: Date.now()
      });
    }
    return res.status(200).json({
      cveId: upper, status: "available",
      filterId: String(hit.id || ""), filterName: hit.name || "",
      publishedAt: hit.publishedAt || null, source: "trend_v1", cachedAt: Date.now()
    });

  } catch (err) {
    return res.status(200).json({
      cveId: cveId.toUpperCase(), status: "unknown",
      reason: err.name === "TimeoutError" ? "timeout" : "network_error",
      source: "trend_v1", cachedAt: Date.now()
    });
  }
}

// ── Normalize TV1 endpoint inventory → watchlist items ───────────────────────
//
// Extracts distinct vendor / product / technology signals from the raw TV1
// endpoint list. Conservative: only emits items with high watchlist relevance.
// Extend this function when TV1 exposes software inventory or asset-tag APIs.

function _normalizeEndpoints(endpoints) {
  const seen  = new Set();
  const items = [];

  function _add(type, label, value) {
    if (seen.has(value)) return;
    seen.add(value);
    items.push({ type, label, value });
  }

  for (const ep of endpoints) {
    const os = String(ep.os?.name || ep.osName || ep.operatingSystem || "").toLowerCase();

    // Windows family
    if (os.includes("windows")) {
      _add("vendor", "Microsoft", "microsoft");
      if (os.includes("server")) _add("product", "Windows Server", "windows server");
    }
    // Linux distributions
    if (os.includes("red hat") || os.includes("rhel"))
      _add("vendor", "Red Hat", "red hat");
    if (os.includes("ubuntu"))
      _add("vendor", "Ubuntu", "ubuntu");
    if (os.includes("centos"))
      _add("vendor", "CentOS", "centos");
    if (os.includes("debian"))
      _add("vendor", "Debian", "debian");
    if (os.includes("linux"))
      _add("technology", "Linux", "linux");
    // macOS
    if (os.includes("macos") || os.includes("mac os"))
      _add("vendor", "Apple", "apple");

    // Protection managers hint at additional stack vendors
    for (const pm of (ep.protectionManagers || ep.agentComponents || [])) {
      const name = String(pm.name || pm.productName || "").toLowerCase();
      if (name.includes("cisco"))    _add("vendor", "Cisco",    "cisco");
      if (name.includes("vmware"))   _add("vendor", "VMware",   "vmware");
      if (name.includes("fortinet")) _add("vendor", "Fortinet", "fortinet");
      if (name.includes("palo alto")) _add("vendor", "Palo Alto Networks", "palo alto");
      if (name.includes("crowdstrike")) _add("vendor", "CrowdStrike", "crowdstrike");
    }

    // endpointType hints
    const et = String(ep.endpointType || "").toLowerCase();
    if (et.includes("exchange") || (ep.displayName || "").toLowerCase().includes("exchange"))
      _add("product", "Exchange Server", "exchange");
    if (et.includes("domain controller") || (ep.displayName || "").toLowerCase().includes("dc-"))
      _add("product", "Active Directory", "active directory");
  }

  return items;
}
