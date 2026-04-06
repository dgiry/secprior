// api/article-body.js — Fetch full article body for deep IOC extraction
//
// Option B of the IOC recovery strategy:
//   Browser cannot fetch arbitrary URLs (CORS).
//   This serverless function fetches the HTML server-side and returns
//   clean stripped text for re-ingestion into IOCExtractor.
//
// GET /api/article-body?url=<encoded_article_url>
// → { text: "...", chars: 12345 }
//
// Security:
//   • Only http/https allowed (no file://, data://, etc.)
//   • 10s timeout
//   • Text capped at 50 000 chars (sufficient for any advisory page)
//   • 30 min CDN cache to avoid hammering source sites
//
// Usage (browser):
//   const res  = await fetch(`/api/article-body?url=${encodeURIComponent(article.link)}`);
//   const { text } = await res.json();
//   const enriched = IOCExtractor.enrichArticle(article, text);

"use strict";

module.exports = async (req, res) => {
  // CORS — same-origin requests from ThreatLens front-end
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET")
    return res.status(405).json({ error: "Method not allowed" });

  const { url } = req.query;
  if (!url)
    return res.status(400).json({ error: "Missing url param" });

  // ── Validate URL ────────────────────────────────────────────────────────────
  let decoded;
  try {
    decoded = decodeURIComponent(url);
    const parsed = new URL(decoded);
    if (!["http:", "https:"].includes(parsed.protocol))
      return res.status(400).json({ error: "Only http/https URLs are allowed" });
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }

  // ── Fetch ───────────────────────────────────────────────────────────────────
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

    // Cache 30 min — article bodies don't change frequently
    res.setHeader("Cache-Control", "s-maxage=1800, stale-while-revalidate=3600");
    return res.status(200).json({ text, chars: text.length });

  } catch (err) {
    const msg = err.name === "AbortError"
      ? "Timeout: source did not respond within 10 s"
      : err.message;
    return res.status(500).json({ error: msg });
  }
};

// ── HTML → plain text ────────────────────────────────────────────────────────
// Conservative strip: remove scripts/styles first, then all tags.
// HTML entities decoded for better IOC regex matching downstream.

function _stripHTML(html) {
  return html
    // Remove non-content blocks entirely
    .replace(/<script[\s\S]*?<\/script>/gi,   " ")
    .replace(/<style[\s\S]*?<\/style>/gi,     " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<nav[\s\S]*?<\/nav>/gi,         " ")
    .replace(/<footer[\s\S]*?<\/footer>/gi,   " ")
    .replace(/<header[\s\S]*?<\/header>/gi,   " ")
    // Strip remaining tags
    .replace(/<[^>]+>/g, " ")
    // Decode common HTML entities
    .replace(/&amp;/g,  "&")
    .replace(/&lt;/g,   "<")
    .replace(/&gt;/g,   ">")
    .replace(/&quot;/g, '"')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n))
    // Normalise whitespace
    .replace(/\s+/g, " ")
    .trim()
    // Cap at 50 000 chars — sufficient for any advisory / blog post
    .slice(0, 50_000);
}
