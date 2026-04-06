// api/ioc.js — IOC enrichment: article body fetch + OTX reputation + VirusTotal
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
//   GET /api/ioc?action=vt&type=ip|domain|hash|url&value=<value>
//   → { malicious, suspicious, harmless, undetected, total, reputation, country, asOwner, source: "vt" }
//   Queries VirusTotal API v3. Key: X-VT-Key header || VT_API_KEY env var.
//   Free tier: 4 req/min, 500/day.
//   VT API v3 endpoints used:
//     ip_addresses/{ip}  · domains/{domain}  · files/{hash}
//     urls/{base64url(url)} — url is base64url-encoded (no padding)

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
  if (action === "vt")         return _handleVT(req, res);

  return res.status(400).json({
    error: "Missing or unknown action. Use ?action=body, ?action=reputation or ?action=vt"
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

// ── action=vt : VirusTotal API v3 IOC lookup ─────────────────────────────────

async function _handleVT(req, res) {
  const { type, value } = req.query;
  if (!type || !value)
    return res.status(400).json({ error: "Missing required params: type, value" });

  if (!["ip", "domain", "hash", "url"].includes(type))
    return res.status(400).json({ error: `Unknown IOC type: ${type}. Use: ip, domain, hash, url` });

  // UI key (X-VT-Key header from localStorage) takes priority over env var.
  const vtKey = req.headers["x-vt-key"] || process.env.VT_API_KEY;
  if (!vtKey) {
    // Fail gracefully — frontend shows "VT unavailable" inline, no hard error
    return res.status(200).json({ vtUnavailable: true, reason: "VT_API_KEY not configured" });
  }

  // Build VT API v3 endpoint
  let endpoint;
  if (type === "ip") {
    endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`;
  } else if (type === "domain") {
    endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
  } else if (type === "hash") {
    endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`;
  } else if (type === "url") {
    // VT requires base64url-encoded URL (no padding)
    const b64 = Buffer.from(value).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    endpoint = `https://www.virustotal.com/api/v3/urls/${b64}`;
  }

  try {
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 10_000);

    const resp = await fetch(endpoint, {
      headers: { "x-apikey": vtKey },
      signal:  controller.signal
    });
    clearTimeout(timeout);

    // 404 = unknown to VT (never submitted)
    if (resp.status === 404) {
      res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=7200");
      return res.status(200).json({
        malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0,
        reputation: 0, source: "vt"
      });
    }

    if (resp.status === 401 || resp.status === 403)
      return res.status(200).json({ vtUnavailable: true, reason: "Invalid or unauthorized VT API key" });

    if (!resp.ok)
      return res.status(resp.status).json({ error: `VirusTotal returned HTTP ${resp.status}` });

    const json  = await resp.json();
    const attrs = json?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};

    const malicious   = stats.malicious   || 0;
    const suspicious  = stats.suspicious  || 0;
    const harmless    = stats.harmless    || 0;
    const undetected  = stats.undetected  || 0;
    const total       = malicious + suspicious + harmless + undetected;
    const reputation  = attrs.reputation  ?? null;
    const country     = attrs.country     || null;
    const asOwner     = attrs.as_owner    || attrs.asn                || null;

    res.setHeader("Cache-Control", "s-maxage=1800, stale-while-revalidate=3600");
    return res.status(200).json({
      malicious, suspicious, harmless, undetected, total,
      reputation, country, asOwner, source: "vt"
    });

  } catch (err) {
    const msg = err.name === "AbortError"
      ? "VirusTotal did not respond within 10 s"
      : err.message;
    return res.status(500).json({ error: msg });
  }
}
