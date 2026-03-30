// api/tv1-sync.js — Trend Vision One Watchlist Sync endpoint
//
// GET /api/tv1-sync?region=us|eu|au|in|sg|jp[&demo=1]
//
// Behaviour:
//   • demo=1 OR TV1_API_KEY not set → returns curated demo dataset (always works)
//   • TV1_API_KEY + TV1_REGION configured → calls TV1 V3.0 endpoint inventory API
//
// Returns: { items, source, count, fetchedAt, note? }
//   item: { type: 'vendor'|'product'|'technology', label: string, value: string }
//
// Real integration:
//   Requires env vars: TV1_API_KEY, TV1_REGION (optional, default: 'us')
//   TV1 API: GET https://api[.{region}].xdr.trendmicro.com/v3.0/endpointSecurity/endpoints
//   Authorization: Bearer {TV1_API_KEY}
//   The response items[] are normalized into watchlist-ready vendor/product/technology entries.
//
// Architecture note:
//   This function is intentionally thin. All normalization logic lives in _normalizeEndpoints().
//   When TV1 exposes additional API surfaces (software inventory, asset tags), extend
//   _normalizeEndpoints() without touching the response contract.

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
        "Content-Type":  "application/json",
        "TMV1-Filter":   "",   // no extra filter — we want all managed endpoints
      },
      signal: controller.signal
    });
    clearTimeout(timer);
  } catch (e) {
    if (e.name === "AbortError") {
      return res.status(504).json({ error: "TV1 API timeout" });
    }
    console.error("[tv1-sync] fetch error:", e.message);
    return res.status(502).json({ error: "TV1 API unreachable", detail: e.message });
  }

  if (!tv1Res.ok) {
    const body = await tv1Res.text().catch(() => "");
    console.error("[tv1-sync] TV1 HTTP error:", tv1Res.status, body.slice(0, 200));
    // Graceful fallback to demo on auth error (avoids breaking the UX)
    if (tv1Res.status === 401 || tv1Res.status === 403) {
      return res.status(200).json({
        items:     TV1_DEMO_ITEMS,
        source:    "tv1_demo",
        count:     TV1_DEMO_ITEMS.length,
        fetchedAt: new Date().toISOString(),
        note:      `TV1 authentication failed (HTTP ${tv1Res.status}) — verify TV1_API_KEY. Returning demo data.`
      });
    }
    return res.status(502).json({
      error:  "TV1 API error",
      detail: `HTTP ${tv1Res.status} — ${body.slice(0, 100)}`
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
