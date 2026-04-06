// api/urlhaus.js — URLhaus (abuse.ch) backend integration
//
// Replaces the obsolete RSS-style URLhaus feed with an authenticated
// backend handler using the URLhaus CSV bulk export.
//
// Requires env var: URLHAUS_AUTH_KEY (abuse.ch API key)
//   → If missing, responds with { articles: [], skipped: true }
//   → If present, fetches, unzips and parses the CSV export
//
// GET /api/urlhaus
// → { articles: [...], total: N }            when key is present
// → { articles: [], total: 0, skipped: true } when key is missing
//
// Format choice: CSV (not JSON)
//   URLhaus distributes bulk exports as ZIP-compressed CSV, which is the
//   canonical supported path. The URLhaus API (/v1/) is a lookup API only —
//   it has no "list recent" endpoint. The CSV export contains all active
//   malicious URLs with full metadata (id, date, url, status, threat, tags).
//   We extract the ZIP using only Node.js built-in zlib (no npm deps).
//
// Cache: 1 hour CDN (URLhaus CSV refreshes every 5 min server-side,
//        but daily recency is sufficient for ThreatLens IOC enrichment).

"use strict";

const zlib = require("node:zlib");
const { promisify } = require("node:util");
const inflateRaw = promisify(zlib.inflateRaw);

const URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/";
const MAX_ARTICLES    = 50; // Keep only the N most recent entries

// ── Entry point ───────────────────────────────────────────────────────────────

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();

  const authKey = process.env.URLHAUS_AUTH_KEY || "";

  // Fail gracefully when key is not configured — no broken behaviour
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
    // ── 1. Fetch ZIP-compressed CSV from URLhaus ─────────────────────────────
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

    // ── 2. Extract CSV from ZIP (built-in zlib only, no npm deps) ───────────
    const arrayBuffer = await response.arrayBuffer();
    const zipBuf      = Buffer.from(arrayBuffer);
    const csvBuf      = await _extractFirstZipEntry(zipBuf);
    const csvText     = csvBuf.toString("utf-8");

    // ── 3. Parse CSV rows into ThreatLens article objects ───────────────────
    const articles = _parseCSVToArticles(csvText, MAX_ARTICLES);

    res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=600");
    return res.status(200).json({ articles, total: articles.length });

  } catch (err) {
    return res.status(502).json({
      error:    `URLhaus integration error: ${err.message}`,
      articles: [],
      total:    0
    });
  }
};

// ── ZIP extraction (single-file ZIP, built-in only) ───────────────────────────

/**
 * Extract the first file entry from a ZIP buffer.
 * Handles DEFLATE (method 8) and Stored (method 0).
 * No external dependencies — uses node:zlib inflateRaw.
 */
async function _extractFirstZipEntry(buf) {
  // Local File Header signature: PK\x03\x04
  if (buf.length < 30 || buf.readUInt32LE(0) !== 0x04034b50) {
    throw new Error("URLhaus response is not a valid ZIP file");
  }

  const method         = buf.readUInt16LE(8);   // 0 = stored, 8 = DEFLATE
  let   compressedSize = buf.readUInt32LE(18);
  const filenameLen    = buf.readUInt16LE(26);
  const extraLen       = buf.readUInt16LE(28);
  const dataStart      = 30 + filenameLen + extraLen;

  // If compressedSize is 0 the archive uses a data descriptor; fall back to
  // reading it from the Central Directory (safer for edge cases).
  if (compressedSize === 0) {
    const eocdSig = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
    const eocdOff = _bufLastIndexOf(buf, eocdSig);
    if (eocdOff === -1) throw new Error("URLhaus ZIP: cannot locate End of Central Directory");
    const cdOffset   = buf.readUInt32LE(eocdOff + 16);
    compressedSize   = buf.readUInt32LE(cdOffset + 20);
  }

  const data = buf.subarray(dataStart, dataStart + compressedSize);
  if (method === 0) return data;              // Stored (no compression)
  if (method === 8) return inflateRaw(data);  // DEFLATE
  throw new Error(`URLhaus ZIP: unsupported compression method ${method}`);
}

/** Find last occurrence of pattern Buffer inside buf. */
function _bufLastIndexOf(buf, pattern) {
  for (let i = buf.length - pattern.length; i >= 0; i--) {
    if (buf.subarray(i, i + pattern.length).equals(pattern)) return i;
  }
  return -1;
}

// ── CSV parsing ───────────────────────────────────────────────────────────────

/**
 * Parse URLhaus CSV export into ThreatLens-compatible article objects.
 *
 * URLhaus CSV columns (lines starting with # are comments/header):
 *   id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
 */
function _parseCSVToArticles(csvText, maxItems) {
  const lines    = csvText.split("\n");
  const articles = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue; // skip comments & header

    const cols = _parseCSVRow(trimmed);
    if (cols.length < 8) continue;

    const [id, dateadded, url, url_status, , threat, tags, urlhaus_link, reporter] = cols;
    if (!url || !url.startsWith("http")) continue;

    const tagList     = _parseTags(tags);
    const threatLabel = (threat || "malware_download").trim();
    const reporter_   = (reporter || "community").trim();
    const status_     = (url_status || "unknown").trim();

    // Title: short, scannable — threat type + truncated URL
    const title = `[URLhaus] ${threatLabel}: ${_truncate(url, 80)}`;

    // Description: full context for IOC extractor to pick up the malicious URL
    const description =
      `Malicious URL confirmed by URLhaus community. ` +
      `Status: ${status_}. Threat: ${threatLabel}. ` +
      (tagList.length ? `Tags: ${tagList.join(", ")}. ` : "") +
      `Reported by: ${reporter_}. ` +
      `IOC URL: ${url}`;

    const pubDate = dateadded ? new Date(dateadded.replace(" ", "T") + "Z") : new Date();

    articles.push({
      id:         `urlhaus-${id}`,
      title,
      link:       urlhaus_link || "https://urlhaus.abuse.ch/browse/",
      description,
      pubDate:    isNaN(pubDate.getTime()) ? new Date() : pubDate,
      source:     "urlhaus",
      sourceName: "URLhaus (abuse.ch)",
      sourceIcon: "☣️",
      lang:       "en"
    });

    if (articles.length >= maxItems) break;
  }

  return articles;
}

/**
 * Parse one CSV row, correctly handling quoted fields that contain commas.
 */
function _parseCSVRow(line) {
  const result = [];
  let current  = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === "," && !inQuotes) {
      result.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}

/** Parse URLhaus tag field — may be quoted CSV like `"exe,trojan"`. */
function _parseTags(raw) {
  if (!raw) return [];
  const clean = raw.replace(/^"|"$/g, "").trim();
  if (!clean) return [];
  return clean.split(",").map(t => t.trim()).filter(Boolean);
}

function _truncate(str, max) {
  return str.length <= max ? str : str.slice(0, max - 3) + "...";
}
