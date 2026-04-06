// api/fetch-feeds.js — Proxy RSS + URLhaus backend fetcher
//
// Merged from api/fetch-feeds.js + api/urlhaus.js
// (Vercel Hobby plan: 12 serverless function limit)
//
// Dispatch via query parameter:
//
//   GET /api/fetch-feeds?url=<rss-url>
//   → Raw XML for one RSS/Atom feed (cached 5 min CDN)
//
//   GET /api/fetch-feeds?urlhaus=1
//   → { articles: [...], total, skipped? } — URLhaus CSV bulk export
//     Requires env var: URLHAUS_AUTH_KEY
//     If missing → { articles: [], skipped: true, reason: "..." }
//     (cached 1 h CDN)

"use strict";

const zlib = require("node:zlib");
const { promisify } = require("node:util");
const inflateRaw = promisify(zlib.inflateRaw);
const ssrfGuard = require("./_lib/ssrf-guard");

module.exports = async (req, res) => {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const { url, urlhaus } = req.query;

  if (urlhaus) return _handleURLhaus(req, res);
  if (url)     return _handleRSSProxy(req, res, url);

  return res.status(400).json({ error: "Paramètre 'url' ou 'urlhaus' requis" });
};

// ── GET /api/fetch-feeds?url= — RSS proxy ─────────────────────────────────────

async function _handleRSSProxy(req, res, url) {
  // Sécurité : autoriser uniquement les URLs http/https
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({ error: "Protocole non autorisé" });
    }
  } catch {
    return res.status(400).json({ error: "URL invalide" });
  }

  // ── SSRF guard — block private/internal networks + cloud metadata ───────
  const ssrf = await ssrfGuard.checkURL(url);
  if (ssrf.blocked)
    return res.status(403).json({ error: "Blocked: " + ssrf.reason });

  try {
    const response = await fetch(url, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; CyberVeille-Pro/2.0; +https://github.com/cyberveille)",
        Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"
      },
      signal: AbortSignal.timeout(10_000)
    });

    if (!response.ok) {
      return res.status(502).json({
        error: `Flux RSS inaccessible (HTTP ${response.status})`,
        feedUrl: url
      });
    }

    const body = await response.text();

    // Cache CDN Vercel 5 minutes, stale-while-revalidate 1 heure
    res.setHeader("Cache-Control", "s-maxage=300, stale-while-revalidate=3600");
    res.setHeader("Content-Type", "application/xml; charset=utf-8");
    res.status(200).send(body);
  } catch (err) {
    const isTimeout = err.name === "TimeoutError" || err.message?.includes("timeout");
    console.error("[fetch-feeds/rss]", err.message);
    res.status(isTimeout ? 504 : 502).json({
      error: isTimeout
        ? "Feed timeout — source did not respond"
        : "Feed fetch failed"
    });
  }
}

// ── GET /api/fetch-feeds?urlhaus=1 — URLhaus CSV backend ─────────────────────
//
// URLhaus CSV bulk export — authenticated.
// Format auto-detected from magic bytes: ZIP, gzip, or plain CSV.
//   The URLhaus API (/v1/) is a lookup API only — no "list recent" endpoint.
//   The canonical bulk path is https://urlhaus.abuse.ch/downloads/csv_recent/
//   URLhaus may serve it as ZIP, gzip or plain CSV depending on the request.
//   Fields: id, dateadded, url, url_status, last_online, threat, tags,
//           urlhaus_link, reporter
//   Decompression uses node:zlib only (no npm deps).

const URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/";
const URLHAUS_MAX     = 500; // Entries in the IOC lookup map (domain + url → threat)

async function _handleURLhaus(req, res) {
  // UI key (from localStorage via X-URLhaus-Key header) takes priority over env var.
  // This lets open-source users self-configure without touching Vercel env vars.
  const authKey = req.headers["x-urlhaus-key"] || process.env.URLHAUS_AUTH_KEY || "";

  // Vary: tells the Vercel CDN to cache separately for each unique key value,
  // so a cached "skipped" response (no key) never shadows a keyed request.
  res.setHeader("Vary", "X-URLhaus-Key");

  // Fail gracefully when key is not configured
  if (!authKey) {
    res.setHeader("Cache-Control", "s-maxage=300, stale-while-revalidate=60");
    return res.status(200).json({
      articles: [],
      total:    0,
      skipped:  true,
      reason:   "URLHAUS_AUTH_KEY environment variable not set"
    });
  }

  try {
    // 1. Fetch CSV from URLhaus (format varies: ZIP, gzip, or plain text)
    const response = await fetch(URLHAUS_CSV_URL, {
      headers: {
        "Auth-Key":   authKey,
        "User-Agent": "CyberVeille-Pro/2.0 (+https://github.com/dgiry/cyberveille-pro)",
        "Accept":     "application/zip, application/gzip, text/csv, text/plain, */*"
      },
      signal: AbortSignal.timeout(20_000)
    });

    if (!response.ok) {
      return res.status(502).json({
        error:    `URLhaus download failed: HTTP ${response.status}`,
        articles: [],
        total:    0
      });
    }

    const contentType = (response.headers.get("content-type") || "").toLowerCase();
    const buf = Buffer.from(await response.arrayBuffer());

    // 2. Auto-detect format from magic bytes and content-type
    let csvText;

    if (buf.length >= 4 && buf.readUInt32LE(0) === 0x04034b50) {
      // Magic PK\x03\x04 → ZIP archive
      const csvBuf = await _unzipFirst(buf);
      csvText = csvBuf.toString("utf-8");

    } else if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
      // Magic \x1f\x8b → gzip
      const csvBuf = await promisify(zlib.gunzip)(buf);
      csvText = csvBuf.toString("utf-8");

    } else if (
      contentType.includes("text") ||
      contentType.includes("csv") ||
      buf.slice(0, 1).toString() === "#"   // URLhaus CSV starts with # comments
    ) {
      // Plain text / CSV — no compression
      csvText = buf.toString("utf-8");

    } else {
      // Unknown format — return debug hint instead of a cryptic error
      const preview = buf.slice(0, 120).toString("utf-8").replace(/[^\x20-\x7e]/g, ".");
      return res.status(502).json({
        error:    `URLhaus: unexpected response format (Content-Type: ${contentType || "unknown"}). ` +
                  `First bytes: ${preview}`,
        articles: [],
        total:    0
      });
    }

    // 3. Build structured IOC lookup map (domain → entry, url → entry)
    //    URLhaus is no longer injected as feed articles — it is used as a
    //    background IOC confirmation layer by js/urlhaus-ioc.js.
    const iocMap = _buildIOCMap(csvText, URLHAUS_MAX);
    const total  = Object.keys(iocMap.urls).length;

    res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=600");
    return res.status(200).json({ iocMap, total, articles: [] });

  } catch (err) {
    console.error("[fetch-feeds/urlhaus]", err.message);
    return res.status(502).json({
      error:    "URLhaus fetch failed",
      articles: [],
      total:    0
    });
  }
}

// ── ZIP extraction (single-entry ZIP, built-in only) ─────────────────────────

async function _unzipFirst(buf) {
  if (buf.length < 30 || buf.readUInt32LE(0) !== 0x04034b50) {
    throw new Error("Not a valid ZIP file (unexpected magic bytes)");
  }
  const method         = buf.readUInt16LE(8);
  let   compressedSize = buf.readUInt32LE(18);
  const filenameLen    = buf.readUInt16LE(26);
  const extraLen       = buf.readUInt16LE(28);
  const dataStart      = 30 + filenameLen + extraLen;

  // compressedSize=0 means data descriptor follows — read from Central Directory
  if (compressedSize === 0) {
    const eocdSig = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
    const eocdOff = _bufLastIndexOf(buf, eocdSig);
    if (eocdOff === -1) throw new Error("URLhaus ZIP: EOCD not found");
    const cdOffset = buf.readUInt32LE(eocdOff + 16);
    compressedSize = buf.readUInt32LE(cdOffset + 20);
  }

  const data = buf.subarray(dataStart, dataStart + compressedSize);
  if (method === 0) return data;              // Stored
  if (method === 8) return inflateRaw(data);  // DEFLATE
  throw new Error(`URLhaus ZIP: unsupported compression method ${method}`);
}

function _bufLastIndexOf(buf, pattern) {
  for (let i = buf.length - pattern.length; i >= 0; i--) {
    if (buf.subarray(i, i + pattern.length).equals(pattern)) return i;
  }
  return -1;
}

// ── CSV parsing ───────────────────────────────────────────────────────────────

/**
 * Build a structured IOC lookup map from URLhaus CSV.
 * Returns { domains: { hostname → entry }, urls: { url → entry } }
 * where entry = { threat, tags, status, link }
 *
 * Used by js/urlhaus-ioc.js to cross-reference IOCs extracted from
 * other feed articles — URLhaus is no longer injected as feed articles.
 */
function _buildIOCMap(csvText, maxItems) {
  const domains = {};
  const urls    = {};
  let   count   = 0;

  for (const line of csvText.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const cols = _parseCSVRow(trimmed);
    if (cols.length < 8) continue;

    const [, , url, url_status, , threat, tags, urlhaus_link] = cols;
    if (!url || !url.startsWith("http")) continue;

    const entry = {
      threat: (threat     || "malware_download").trim(),
      tags:   _parseTags(tags),
      status: (url_status || "unknown").trim(),
      link:   urlhaus_link || ""
    };

    urls[url] = entry;
    try {
      const { hostname } = new URL(url);
      if (!domains[hostname]) domains[hostname] = entry; // first occurrence wins
    } catch { /* skip malformed URLs */ }

    if (++count >= maxItems) break;
  }

  return { domains, urls };
}

function _parseCSVRow(line) {
  const result = [];
  let current  = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
      else inQuotes = !inQuotes;
    } else if (ch === "," && !inQuotes) {
      result.push(current); current = "";
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}

function _parseTags(raw) {
  if (!raw) return [];
  const clean = raw.replace(/^"|"$/g, "").trim();
  return clean ? clean.split(",").map(t => t.trim()).filter(Boolean) : [];
}

