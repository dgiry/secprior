// api/ai-brief.js — AI Brief generation endpoint (Sprint IA v1)
//
// Calls Anthropic Claude API to generate three structured outputs
// from verified security signals already present in CyberVeille Pro.
//
// Requires: ANTHROPIC_API_KEY environment variable on Vercel.
//
// POST /api/ai-brief
// Body: structured context object (whitelisted fields only — see ALLOWED_FIELDS)
//
// Returns: { analystBrief, executiveBrief, nextStep, model, generatedAt, signalCount }
//
// Anti-hallucination design:
//   • Input is restricted to a whitelist of known signal fields
//   • System prompt explicitly prohibits inventing CVEs, vendors, IPs, attribution
//   • Description is sent as-is (already sanitized client-side, truncated to 800 chars)
//   • Output is parsed as JSON and validated for required fields
//   • Each field is post-processed: markdown artifacts stripped, length capped
//   • Model: claude-haiku (fast, cost-effective for structured extraction)

"use strict";

const ANTHROPIC_API   = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VER   = "2023-06-01";
const MODEL           = "claude-3-haiku-20240307";
const MAX_TOKENS      = 512;
const REQUEST_TIMEOUT = 15_000; // 15 s

// Whitelist — prevents arbitrary prompt injection via unknown fields
const ALLOWED_FIELDS = new Set([
  "type", "title", "source", "pubDate", "description",
  "priorityLevel", "priorityScore", "priorityReasons",
  "cves", "isKEV", "epssScore", "cvssScore",
  "vendors", "watchlistHits", "watchlistHit", "iocCount",
  "trending", "trendingCount", "attackTags",
  "articleCount", "sourceCount", "sources",
  "summary", "firstSeen", "lastSeen"
]);

module.exports = async (req, res) => {
  // ── CORS ─────────────────────────────────────────────────────────────────
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // ── API key check ─────────────────────────────────────────────────────────
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(503).json({
      error:  "AI service not configured",
      detail: "Add ANTHROPIC_API_KEY to Vercel environment variables to enable AI Brief."
    });
  }

  // ── Input sanitization — whitelist only ───────────────────────────────────
  const raw = req.body || {};
  const ctx = {};
  for (const key of ALLOWED_FIELDS) {
    if (raw[key] !== undefined) ctx[key] = raw[key];
  }

  if (!ctx.title) {
    return res.status(400).json({ error: "Missing required field: title" });
  }

  // ── Call Anthropic ────────────────────────────────────────────────────────
  let anthropicRes;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    anthropicRes = await fetch(ANTHROPIC_API, {
      method:  "POST",
      headers: {
        "Content-Type":      "application/json",
        "x-api-key":         apiKey,
        "anthropic-version": ANTHROPIC_VER
      },
      body: JSON.stringify({
        model:      MODEL,
        max_tokens: MAX_TOKENS,
        system:     _buildSystemPrompt(),
        messages:   [{ role: "user", content: _buildUserPrompt(ctx) }]
      }),
      signal: controller.signal
    });
    clearTimeout(timer);
  } catch (e) {
    if (e.name === "AbortError") {
      return res.status(504).json({ error: "AI service timeout" });
    }
    console.error("[ai-brief] Fetch error:", e.message);
    return res.status(502).json({ error: "AI service unreachable", detail: e.message });
  }

  if (!anthropicRes.ok) {
    const errBody = await anthropicRes.json().catch(() => ({}));
    console.error("[ai-brief] Anthropic HTTP error:", anthropicRes.status, errBody);
    return res.status(502).json({
      error:  "AI service error",
      detail: `HTTP ${anthropicRes.status}`
    });
  }

  // ── Parse response ────────────────────────────────────────────────────────
  const data     = await anthropicRes.json();
  const rawText  = data.content?.[0]?.text ?? "";

  let parsed;
  try {
    // Strip accidental markdown fences before parsing
    const cleaned = rawText
      .replace(/^```[a-z]*\s*/m, "")
      .replace(/```\s*$/m, "")
      .trim();
    parsed = JSON.parse(cleaned);
  } catch (e) {
    console.error("[ai-brief] JSON parse failed. Raw:", rawText.slice(0, 300));
    return res.status(502).json({ error: "Invalid AI response format" });
  }

  if (!parsed.analystBrief || !parsed.executiveBrief || !parsed.nextStep) {
    console.error("[ai-brief] Incomplete response fields:", Object.keys(parsed));
    return res.status(502).json({ error: "Incomplete AI response" });
  }

  // ── Post-process — strip markdown artifacts, cap length ───────────────────
  return res.status(200).json({
    analystBrief:   _postProcess(parsed.analystBrief,   800),
    executiveBrief: _postProcess(parsed.executiveBrief, 400),
    nextStep:       _postProcess(parsed.nextStep,       250),
    model:          "claude-haiku",
    generatedAt:    new Date().toISOString(),
    signalCount:    Object.keys(ctx).length
  });
};

// ── Prompt builders ──────────────────────────────────────────────────────────

function _buildSystemPrompt() {
  return `You are a cybersecurity threat intelligence assistant embedded in CyberVeille Pro, a SOC/SecOps platform used by security analysts.

Your task: Analyze the structured security event JSON provided and produce exactly three outputs.

OUTPUT FORMAT — Return ONLY a valid JSON object with exactly these three keys:
- "analystBrief": Technical brief for a SOC analyst (max 120 words). Cover: what the threat is, the key technical signals, and why it matters operationally.
- "executiveBrief": Business-risk summary for a CISO or manager (max 65 words). No technical jargon. Cover: what is at risk and what decision is needed.
- "nextStep": One concrete next action (max 40 words). Begin with a strong action verb. Match urgency to the priorityLevel field.

MANDATORY GUARDRAILS — never violate:
1. Use ONLY information present in the provided JSON. Never add context that is not in the data.
2. Only write "actively exploited" or "exploitation confirmed" if "isKEV" is true in the input.
3. Only reference CVE IDs that appear in the "cves" array. Never invent CVE identifiers.
4. Only reference vendor names from the "vendors" array. Never invent vendor names.
5. If "description" is absent or fewer than 40 characters, write "Limited context — assessment based on metadata signals only."
6. Match nextStep urgency to priorityLevel: critical_now→use "immediately" or "urgently", investigate→use "assess" or "validate", watch→use "monitor", low→use "note for review".
7. Never invent: IP addresses, domain names, file hashes, threat actor names, malware family names, or attribution.
8. Never recommend specific patch version numbers unless they appear in the provided description.
9. Return ONLY the JSON object. No markdown fences. No explanations before or after the JSON.`;
}

function _buildUserPrompt(ctx) {
  return `Analyze this security event and generate the three required outputs:\n\n${JSON.stringify(ctx, null, 2)}`;
}

// ── Post-processing ──────────────────────────────────────────────────────────

function _postProcess(text, maxLen) {
  if (typeof text !== "string") return "";
  // Strip common markdown artifacts the model might accidentally include
  let t = text
    .replace(/\*\*/g, "")
    .replace(/\*/g,   "")
    .replace(/#{1,4} /g, "")
    .replace(/`/g,    "")
    .trim();
  // Cap at maxLen — try to cut at sentence boundary
  if (t.length > maxLen) {
    t = t.slice(0, maxLen);
    const lastDot = t.lastIndexOf(". ");
    if (lastDot > maxLen * 0.55) t = t.slice(0, lastDot + 1);
    else t = t.trimEnd() + "…";
  }
  return t;
}
