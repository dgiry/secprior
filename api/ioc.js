// api/ioc.js — IOC enrichment: article body fetch + OTX reputation + ThreatFox
//
// Merged (Vercel Hobby plan: 12 serverless function limit)
//
// Dispatch via ?action= parameter:
//
//   GET /api/ioc?action=body&url=<encoded_url>
//   → { text: "...", chars: N }
//   Fetches full article HTML server-side (CORS-safe), strips tags,
//   returns clean text for deep IOC extraction.
//
//   GET /api/ioc?action=reputation&type=ip|domain|hash|url&value=<value>
//   → { verdict, pulses, labels, source: "otx" }
//   Queries AlienVault OTX. Key: X-OTX-Key header || OTX_API_KEY env var.
//
//   GET /api/ioc?action=threatfox&value=<value>
//   → { matched, threat_type, malware, confidence, first_seen, tags, count, source: "threatfox" }
//   Queries ThreatFox (abuse.ch). Auth-Key: X-TF-Key header || THREATFOX_AUTH_KEY env var.
//   Same Auth-Key as URLhaus (both abuse.ch services). No IOC type param needed — ThreatFox
//   auto-detects type from the value (IP, domain, URL, hash).

"use strict";

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET")
    return res.status(405).json({ error: "Method not allowed" });

  const { action } = req.query;

  if (action === "body")       return _handleBody(req, res);
  if (action === "reputation") return _handleReputation(req, res);
  if (action === "threatfox")  return _handleThreatFox(req, res);

  return res.status(400).json({
    error: "Missing or unknown action. Use ?action=body, ?action=reputation or ?action=threatfox"
  });
};

// ── action=body : fetch full article text ────────────────────────────────────

async function _handleBody(req, res) {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing url param" });

  let decoded;
  try {
    decoded = decodeURIComponent(url);
    const parsed = new URL(decoded);
    if (!["http:", "https:"].includes(parsed.protocol))
      return res.status(400).json({ error: "Only http/https URLs are allowed" });
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }

  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 10_000);

    const resp = await fetch(decoded, {
      headers: {
        "User-Agent": "ThreatLens-IOC/1.0 (security research; +https://threatlens.vercel.app)",
        "Accept":     "text/html,application/xhtml+xml,text/xml;q=0.9,*/*;q=0.8"
      },
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!resp.ok)
      return res.status(resp.status).json({ error: `Source returned HTTP ${resp.status}` });

    const html = await resp.text();
    const text = _stripHTML(html);

    res.setHeader("Cache-Control", "s-maxage=1800, stale-while-revalidate=3600");
    return res.status(200).json({ text, chars: text.length });

  } catch (err) {
    const msg = err.name === "AbortError"
      ? "Timeout: source did not respond within 10 s"
      : err.message;
    return res.status(500).json({ error: msg });
  }
}

function _stripHTML(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi,     " ")
    .replace(/<style[\s\S]*?<\/style>/gi,       " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<nav[\s\S]*?<\/nav>/gi,           " ")
    .replace(/<footer[\s\S]*?<\/footer>/gi,     " ")
    .replace(/<header[\s\S]*?<\/header>/gi,     " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g,  "&").replace(/&lt;/g,   "<")
    .replace(/&gt;/g,   ">").replace(/&quot;/g, '"')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n))
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 50_000);
}

// ── action=reputation : OTX IOC reputation ───────────────────────────────────

const _OTX_TYPE = { ip: "IPv4", domain: "domain", hash: "file", url: "url" };

async function _handleReputation(req, res) {
  const { type, value } = req.query;
  if (!type || !value)
    return res.status(400).json({ error: "Missing required params: type, value" });

  const otxType = _OTX_TYPE[type];
  if (!otxType)
    return res.status(400).json({ error: `Unknown IOC type: ${type}. Use: ip, domain, hash, url` });

  // UI key (X-OTX-Key header from localStorage) takes priority over env var.
  // This lets open-source users self-configure without touching Vercel env vars.
  const otxKey = req.headers["x-otx-key"] || process.env.OTX_API_KEY;
  if (!otxKey) {
    // Fail gracefully — frontend shows "OTX unavailable" inline, no hard error
    return res.status(200).json({ otxUnavailable: true, reason: "OTX_API_KEY not configured" });
  }

  const indicator = encodeURIComponent(value);
  const otxUrl = `https://otx.alienvault.com/api/v1/indicators/${otxType}/${indicator}/general`;

  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 8_000);

    const resp = await fetch(otxUrl, {
      headers: { "X-OTX-API-KEY": otxKey },
      signal:  controller.signal
    });
    clearTimeout(timeout);

    if (resp.status === 404) {
      res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=7200");
      return res.status(200).json({ verdict: "clean", pulses: 0, labels: [], source: "otx" });
    }

    if (!resp.ok)
      return res.status(resp.status).json({ error: `OTX returned HTTP ${resp.status}` });

    const data   = await resp.json();
    const pulses = data.pulse_info?.count || 0;
    const labels = (data.pulse_info?.pulses || [])
      .slice(0, 5).map(p => p.name).filter(Boolean);

    const verdict = pulses === 0 ? "clean"
                  : pulses  <  3 ? "suspicious"
                  :                "malicious";

    res.setHeader("Cache-Control", "s-maxage=1800, stale-while-revalidate=3600");
    return res.status(200).json({ verdict, pulses, labels, source: "otx" });

  } catch (err) {
    const msg = err.name === "AbortError"
      ? "OTX did not respond within 8 s"
      : err.message;
    return res.status(500).json({ error: msg });
  }
}

// ── action=threatfox : ThreatFox (abuse.ch) IOC lookup ───────────────────────
//
// ThreatFox uses a POST JSON API — the backend proxies it server-side.
// The Auth-Key is the same abuse.ch key as URLhaus (unified auth).
// No IOC type param is required: ThreatFox auto-detects from the value.

async function _handleThreatFox(req, res) {
  const { value } = req.query;
  if (!value)
    return res.status(400).json({ error: "Missing required param: value" });

  // UI key (X-TF-Key header from localStorage) or env var fallback.
  // Same abuse.ch Auth-Key as URLhaus — users only need one key for both.
  const tfKey = req.headers["x-tf-key"] || process.env.THREATFOX_AUTH_KEY;
  if (!tfKey) {
    return res.status(200).json({ tfUnavailable: true, reason: "THREATFOX_AUTH_KEY not configured" });
  }

  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 8_000);

    const resp = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method:  "POST",
      headers: {
        "Auth-Key":     tfKey,
        "Content-Type": "application/json"
      },
      body:   JSON.stringify({ query: "search_ioc", search_term: value }),
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!resp.ok)
      return res.status(resp.status).json({ error: `ThreatFox returned HTTP ${resp.status}` });

    const json = await resp.json();

    // No result or empty dataset
    if (json.query_status === "no_result" || !Array.isArray(json.data) || !json.data.length) {
      res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=7200");
      return res.status(200).json({ matched: false, source: "threatfox" });
    }

    // Best result = highest confidence_level
    const best = [...json.data].sort((a, b) => (b.confidence_level || 0) - (a.confidence_level || 0))[0];

    res.setHeader("Cache-Control", "s-maxage=1800, stale-while-revalidate=3600");
    return res.status(200).json({
      matched:     true,
      threat_type: best.threat_type        || null,
      malware:     best.malware_printable  || null,
      confidence:  best.confidence_level   ?? null,
      first_seen:  best.first_seen         || null,
      tags:        (best.tags || []).slice(0, 4),
      count:       json.data.length,
      source:      "threatfox"
    });

  } catch (err) {
    const msg = err.name === "AbortError"
      ? "ThreatFox did not respond within 8 s"
      : err.message;
    return res.status(500).json({ error: msg });
  }
}

