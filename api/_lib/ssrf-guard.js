// _lib/ssrf-guard.js — Reject URLs targeting private/internal networks
//
// Used by ioc.js (action=body) and fetch-feeds.js (RSS proxy) to prevent
// SSRF attacks that probe internal networks or cloud metadata endpoints.
//
// Strategy:
//   1. Reject known dangerous hostnames (localhost, metadata, .local, .internal)
//   2. Reject IP-literal hostnames in private/reserved ranges
//   3. DNS-resolve the hostname and reject if it resolves to a private IP
//
// This blocks the most common SSRF vectors:
//   - http://169.254.169.254/latest/meta-data/ (AWS/GCP/Azure IMDS)
//   - http://localhost:3000/... (loopback)
//   - http://10.0.0.1/... (internal network)
//   - http://[::1]/... (IPv6 loopback)
//   - DNS rebinding (domain resolving to 127.0.0.1)

"use strict";

const dns = require("node:dns");
const net = require("node:net");
const { promisify } = require("node:util");
const dnsLookup = promisify(dns.lookup);

// Private / reserved IPv4 ranges (RFC 1918, link-local, loopback, CGN, etc.)
const PRIVATE_V4 = [
  /^0\./,                                        // current network
  /^10\./,                                       // Class A private
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,   // CGN (RFC 6598)
  /^127\./,                                      // loopback
  /^169\.254\./,                                  // link-local / cloud metadata
  /^172\.(1[6-9]|2\d|3[01])\./,                  // Class B private
  /^192\.168\./,                                  // Class C private
];

// Private / reserved IPv6 prefixes
const PRIVATE_V6 = [
  /^::1$/i,      // loopback
  /^fc/i,        // unique local (fc00::/7)
  /^fd/i,        // unique local (fd00::/8)
  /^fe80/i,      // link-local
];

// Known dangerous hostnames
const BLOCKED_HOSTS = new Set([
  "localhost",
  "metadata",
  "metadata.google.internal",
]);

function _isPrivateIP(ip) {
  if (net.isIPv4(ip)) return PRIVATE_V4.some(re => re.test(ip));
  if (net.isIPv6(ip)) return PRIVATE_V6.some(re => re.test(ip));
  return false;
}

function _isBlockedHostname(hostname) {
  const lower = hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(lower)) return true;
  if (lower.endsWith(".local"))    return true;
  if (lower.endsWith(".internal")) return true;
  if (lower.endsWith(".localhost")) return true;
  return false;
}

/**
 * Check if a URL targets a private/internal network.
 * @param {string} urlString — decoded URL to check
 * @returns {Promise<{blocked: boolean, reason?: string}>}
 */
async function checkURL(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return { blocked: true, reason: "Invalid URL" };
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets

  // 1. Known dangerous hostnames
  if (_isBlockedHostname(hostname)) {
    return { blocked: true, reason: "Blocked hostname" };
  }

  // 2. IP literal — check directly
  if (net.isIP(hostname)) {
    if (_isPrivateIP(hostname)) {
      return { blocked: true, reason: "Private/reserved IP address" };
    }
    return { blocked: false };
  }

  // 3. DNS resolution — check resolved address
  try {
    const { address } = await dnsLookup(hostname, { family: 0 });
    if (_isPrivateIP(address)) {
      return { blocked: true, reason: "Hostname resolves to private IP" };
    }
  } catch {
    // DNS resolution failed — block to be safe (non-routable hostname)
    return { blocked: true, reason: "DNS resolution failed" };
  }

  return { blocked: false };
}

module.exports = { checkURL };
