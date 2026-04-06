// api/ioc.js — IOC enrichment: article body fetch + reputation lookup
//
// Merged from api/article-body.js + api/ioc-reputation.js
// (Vercel Hobby plan: 12 serverless function limit)
//
// Dispatch via ?action= parameter:
//
//   GET /api/ioc?action=body&url=<encoded_url>
//   → { text: "...", chars: N }
//   Fetches full article HTML server-side (CORS-safe), strips tags,
//   returns clean text for deep IOC extraction (Option B).
//
//   GET /api/ioc?action=reputation&type=ip|domain|hash|url&value=<value>
//   → { verdict: "malicious"|"suspicious"|"clean", pulses: N, labels: [...], source: "otx" }
//   Queries AlienVault OTX for IOC reputation (Option C).
//   Requires OTX_API_KEY env var.

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

  return res.status(400).json({
    error: "Missing or unknown action. Use ?action=body or ?action=reputation"
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

  const otxKey = process.env.OTX_API_KEY;
  if (!otxKey) {
    return res.status(503).json({
      error: "OTX_API_KEY not configured — add it to Vercel Environment Variables"
    });
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
