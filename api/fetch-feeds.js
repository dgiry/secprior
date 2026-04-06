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
    res.status(isTimeout ? 504 : 502).json({
      error: isTimeout
        ? `Délai dépassé pour ${url}`
        : `Erreur proxy : ${err.message}`
    });
  }
}

// ── GET /api/fetch-feeds?urlhaus=1 — URLhaus CSV backend ─────────────────────
//
// URLhaus CSV bulk export — authenticated, ZIP-compressed.
// Format: CSV (not RSS, not JSON)
//   The URLhaus API (/v1/) is a lookup API only — no "list recent" endpoint.
//   The canonical bulk ingestion path is the ZIP-compressed CSV export:
//   https://urlhaus.abuse.ch/downloads/csv_recent/
//   Fields: id, dateadded, url, url_status, last_online, threat, tags,
//           urlhaus_link, reporter
//   ZIP extracted using node:zlib inflateRaw (no npm deps).

const URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/";
const URLHAUS_MAX     = 50; // Keep N most recent rows

async function _handleURLhaus(req, res) {
  const authKey = process.env.URLHAUS_AUTH_KEY || "";

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
    // 1. Fetch ZIP-compressed CSV
    const response = await fetch(URLHAUS_CSV_URL, {
      headers: {
        "Auth-Key":   authKey,
        "User-Agent": "CyberVeille-Pro/2.0 (+https://github.com/dgiry/cyberveille-pro)",
        "Accept":     "application/zip, application/octet-stream, */*"
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

    // 2. Extract CSV from ZIP (built-in zlib, no npm deps)
    const zipBuf  = Buffer.from(await response.arrayBuffer());
    const csvBuf  = await _unzipFirst(zipBuf);
    const csvText = csvBuf.toString("utf-8");

    // 3. Parse → ThreatLens articles
    const articles = _csvToArticles(csvText, URLHAUS_MAX);

    res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=600");
    return res.status(200).json({ articles, total: articles.length });

  } catch (err) {
    return res.status(502).json({
      error:    `URLhaus error: ${err.message}`,
      articles: [],
      total:    0
    });
  }
}

// ── ZIP extraction (single-entry ZIP, built-in only) ─────────────────────────

async function _unzipFirst(buf) {
  if (buf.length < 30 || buf.readUInt32LE(0) !== 0x04034b50) {
    throw new Error("URLhaus response is not a valid ZIP file");
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

function _csvToArticles(csvText, maxItems) {
  const articles = [];
  for (const line of csvText.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const cols = _parseCSVRow(trimmed);
    if (cols.length < 8) continue;

    const [id, dateadded, url, url_status, , threat, tags, urlhaus_link, reporter] = cols;
    if (!url || !url.startsWith("http")) continue;

    const tagList     = _parseTags(tags);
    const threatLabel = (threat    || "malware_download").trim();
    const reporter_   = (reporter  || "community").trim();
    const status_     = (url_status || "unknown").trim();
    const pubDate     = dateadded
      ? new Date(dateadded.replace(" ", "T") + "Z")
      : new Date();

    articles.push({
      id:          `urlhaus-${id}`,
      title:       `[URLhaus] ${threatLabel}: ${_truncate(url, 80)}`,
      link:        urlhaus_link || "https://urlhaus.abuse.ch/browse/",
      description: `Malicious URL (${status_}) reported by ${reporter_}. ` +
                   `Threat: ${threatLabel}. ` +
                   (tagList.length ? `Tags: ${tagList.join(", ")}. ` : "") +
                   `IOC URL: ${url}`,
      pubDate:     isNaN(pubDate.getTime()) ? new Date() : pubDate,
      source:      "urlhaus",
      sourceName:  "URLhaus (abuse.ch)",
      sourceIcon:  "☣️",
      lang:        "en"
    });

    if (articles.length >= maxItems) break;
  }
  return articles;
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

function _truncate(str, max) {
  return str.length <= max ? str : str.slice(0, max - 3) + "...";
}
