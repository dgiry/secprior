// api/ai-brief.js — AI Brief generation endpoint (Sprint IA v2 — quality polish)
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
// Sprint IA v2 — Quality improvements over v1:
//   • System prompt fully rewritten: section-by-section tone rules, anti-repetition rules,
//     poor-context rules, explicit anti-drama vocabulary, per-priorityLevel guidance
//   • User prompt enriched with a human-readable signal summary before raw JSON
//     (helps Haiku understand signal hierarchy without having to interpret the raw object)
//   • MAX_TOKENS increased 512 → 700 (avoids self-truncation on rich context)
//   • Post-processing: bullet stripping, nextStep verb check, executive brief sentence cap,
//     quality warnings for dramatic language and unauthorized KEV-language
//   • signalCount counts only meaningful signal fields (not metadata like type/source/pubDate)

"use strict";

const ANTHROPIC_API   = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VER   = "2023-06-01";
const MODEL           = "claude-3-haiku-20240307";
const MAX_TOKENS      = 700;   // v2: increased from 512 to avoid self-truncation
const REQUEST_TIMEOUT = 15_000;

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

// Fields that represent actual security signals (used for signalCount — excludes metadata)
const SIGNAL_FIELDS = new Set([
  "priorityLevel", "priorityScore", "priorityReasons",
  "cves", "isKEV", "epssScore", "cvssScore",
  "vendors", "watchlistHits", "watchlistHit", "iocCount",
  "trending", "trendingCount", "attackTags"
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
  const data    = await anthropicRes.json();
  const rawText = data.content?.[0]?.text ?? "";

  let parsed;
  try {
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

  // ── Post-process ──────────────────────────────────────────────────────────
  const result = {
    analystBrief:   _postProcess(parsed.analystBrief,   900, { trimSentences: 5 }),
    executiveBrief: _postProcess(parsed.executiveBrief, 450, { trimSentences: 3 }),
    nextStep:       _postProcess(parsed.nextStep,       260, { trimSentences: 1, checkVerb: true }),
    model:          "claude-haiku",
    generatedAt:    new Date().toISOString(),
    signalCount:    _countSignals(ctx)
  };

  _qualityCheck(result, ctx);

  return res.status(200).json(result);
};

// ── System prompt ─────────────────────────────────────────────────────────────
//
// v2 design principles:
//   • Three sections are explicitly differentiated by READER and PURPOSE
//   • Anti-repetition rule: exec brief must not re-enumerate analyst signals
//   • Tone vocabulary: prescribes "should", "may", "warrants" — bans "definitely", "certainly"
//   • Poor-context rules: cover all poverty indicators, not just description length
//   • Per-priorityLevel nextStep vocabulary mapped explicitly
//   • Anti-drama: named forbidden phrases

function _buildSystemPrompt() {
  return `You write professional threat intelligence briefs for CyberVeille Pro, a SOC/SecOps platform. Your readers are security analysts and non-technical managers. Your tone is sober, factual, and operationally useful.

═══ TONE RULES (apply to all three outputs) ═══
- Factual and measured. No marketing language, no drama, no hype.
- Prefer modal verbs: "should be", "may warrant", "warrants review", "based on available signals".
- Forbidden phrases: "severe threat", "imminent danger", "devastating impact", "definitely affecting", "certainly exploited", "highly likely", "requires immediate emergency action", "poses a major risk to your organization".
- Never say an environment is compromised or exposed — you cannot verify that.
- If confidence is low, say so plainly: "Limited context — assessment based on metadata signals only."

═══ MANDATORY ANTI-HALLUCINATION RULES ═══
1. Use ONLY facts present in the provided JSON. Never add context not in the data.
2. Only write "actively exploited" or "exploitation confirmed" if isKEV is true.
3. Only reference CVE IDs from the "cves" array. Never invent identifiers.
4. Only reference vendor names from the "vendors" array. Never invent vendor names.
5. Never invent: IP addresses, domains, file hashes, threat actors, malware family names, attribution.
6. Never recommend specific patch versions unless they appear in the description field.
7. Never say "your environment" is affected — the platform does not know internal inventory.

═══ THREE OUTPUTS — different readers, different purposes ═══

── analystBrief ── FOR: SOC analyst performing triage
Purpose: help the analyst understand which signals to act on and what to investigate first.
Rules:
- 3 to 5 sentences. Tight, no padding, no filler.
- Lead with the strongest available signal: KEV > EPSS high (≥50%) > CVSS high (≥7) > watchlist match > trending > CVE alone.
- Cite concrete values from the data when available: EPSS percentage, CVSS score, CVE IDs, vendor names.
- Focus on: what type of threat this is → what the key indicators are → what triage action is warranted.
- Do NOT open by restating the article title as a sentence. Do NOT use bullet points or lists.
- Tone: analyst-to-analyst, precise, operational.

── executiveBrief ── FOR: CISO / security manager making a decision
Purpose: help a non-technical decision-maker understand the risk level and whether to escalate.
Rules:
- 2 to 3 sentences MAXIMUM.
- Do NOT enumerate raw technical signals (no "EPSS 87%, CVSS 9.8, CVE-2024-xxxx"). Translate them to business terms.
- Translate signals as: high EPSS → "elevated exploitation probability", KEV → "actively exploited in the wild", watchlist match → "a monitored vendor or technology in your scope", high CVSS → "a high-severity vulnerability".
- Focus on: what technology or system category is at risk → the risk level → what the team recommends.
- IMPORTANT: Do NOT repeat the technical details already in analystBrief. This brief has a different purpose and a different reader.
- Tone: calm, clear, decision-oriented. Readable in under 10 seconds.

── nextStep ── FOR: analyst or responder taking the first action
Purpose: one concrete, prudent, actionable step that fits the available context and priority level.
Rules:
- Exactly 1 sentence. Starts with a strong action verb (Assess, Validate, Monitor, Escalate, Patch, Review, Investigate, Check, Prioritize, Track).
- Match urgency strictly to priorityLevel:
    critical_now  → "Immediately [action]" or "Urgently [action]" — only if KEV or EPSS ≥ 50% supports it
    investigate   → "Assess [scope/exposure]…" or "Validate whether [condition]…"
    watch         → "Monitor [source/feed]…" or "Flag for review if new signals emerge."
    low           → "Note for scheduled review" or "Track in the threat intelligence backlog."
- Do NOT list multiple steps. Do NOT repeat what was already said in analystBrief or executiveBrief.
- Do NOT mention specific tools, patch versions, or prescribe multi-step remediation.
- If iocCount is 0 or absent: do not mention "IOC blocking" or "IOC hunting".

═══ POOR CONTEXT RULES ═══
- If description is absent or under 40 characters AND no CVE AND no KEV: begin ALL three outputs with "Limited context available — " and base analysis solely on metadata signals.
- If priorityLevel is "low" or "watch" and no strong signals (no KEV, no high EPSS): tone is calm, no urgency implied. Use "may", "could", "worth monitoring".
- If no vendor present: do not mention "vendor exposure" or "affected vendor".
- If no IOC present: do not mention IOC blocking or IOC-based detection in nextStep.
- If no CVE present: do not use CVE-specific remediation language.

═══ OUTPUT FORMAT ═══
Return ONLY a valid JSON object. No markdown fences. No text before or after.
{"analystBrief": "...", "executiveBrief": "...", "nextStep": "..."}`;
}

// ── User prompt — enriched with signal summary ────────────────────────────────
//
// v2: prepends a human-readable signal priority summary before the raw JSON.
// This helps Haiku understand signal hierarchy without having to parse field names.

function _buildUserPrompt(ctx) {
  const lines = [];

  // Priority level — most important framing signal
  const levelMap = {
    critical_now: "CRITICAL — immediate action required",
    investigate:  "HIGH — investigate and validate",
    watch:        "MEDIUM — monitor",
    low:          "LOW — routine review"
  };
  if (ctx.priorityLevel) {
    lines.push(`Priority level: ${levelMap[ctx.priorityLevel] || ctx.priorityLevel.toUpperCase()}`);
  }

  // Security signals in descending severity order
  if (ctx.isKEV)                   lines.push("Active exploitation: CONFIRMED (CISA KEV)");
  if (ctx.epssScore != null)       lines.push(`EPSS exploitation probability: ${ctx.epssScore}% over 30 days`);
  if (ctx.cvssScore != null)       lines.push(`CVSS score: ${ctx.cvssScore}/10`);
  if (ctx.cves?.length)            lines.push(`CVEs referenced: ${ctx.cves.join(", ")}`);
  if (ctx.vendors?.length)         lines.push(`Vendors in scope: ${ctx.vendors.join(", ")}`);

  const wlHits = ctx.watchlistHits?.length ? ctx.watchlistHits.join(", ") : null;
  if (wlHits)                      lines.push(`Watchlist matches: ${wlHits}`);
  else if (ctx.watchlistHit)       lines.push("Watchlist: match detected");

  if (ctx.iocCount)                lines.push(`IOCs extracted: ${ctx.iocCount}`);
  if (ctx.trending)                lines.push(`Trending: covered by ${ctx.trendingCount || "multiple"} sources simultaneously`);

  if (ctx.attackTags?.length) {
    const tactics = ctx.attackTags
      .map(t => (typeof t === "object" ? (t.tactic || t.label || "") : String(t)))
      .filter(Boolean).join(", ");
    if (tactics) lines.push(`ATT&CK tactics: ${tactics}`);
  }

  if (ctx.priorityReasons?.length) {
    lines.push(`Why flagged: ${ctx.priorityReasons.slice(0, 3).join(" | ")}`);
  }

  // Incident-specific
  if (ctx.type === "incident") {
    if (ctx.articleCount) lines.push(`Grouped articles: ${ctx.articleCount}`);
    if (ctx.sourceCount)  lines.push(`Distinct sources: ${ctx.sourceCount}`);
    if (ctx.firstSeen)    lines.push(`First seen: ${String(ctx.firstSeen).slice(0, 10)}`);
    if (ctx.lastSeen)     lines.push(`Last activity: ${String(ctx.lastSeen).slice(0, 10)}`);
  }

  // Context quality indicator
  const descLen = String(ctx.description || "").length;
  if (descLen < 40 && !ctx.cves?.length && !ctx.isKEV) {
    lines.push("Context quality: POOR — use metadata signals only, acknowledge limited context");
  } else if (descLen < 40) {
    lines.push("Context quality: PARTIAL — description minimal, rely on signal fields");
  }

  const signalSummary = lines.length > 0
    ? `KEY SIGNALS:\n${lines.map(l => `  • ${l}`).join("\n")}\n\n`
    : "";

  return `Generate the three required briefs for this security event.\n\n${signalSummary}FULL DATA:\n${JSON.stringify(ctx, null, 2)}`;
}

// ── Post-processing ───────────────────────────────────────────────────────────

// Main post-processor: strip artifacts, enforce sentence cap, check nextStep verb
function _postProcess(text, maxLen, opts = {}) {
  if (typeof text !== "string") return "";

  let t = text
    // Strip markdown artifacts
    .replace(/\*\*/g, "")
    .replace(/\*/g,   "")
    .replace(/#{1,4} /g, "")
    .replace(/`/g,    "")
    // Strip bullet points / list markers (shouldn't be present, but belt+suspenders)
    .replace(/^[\-\•\–]\s+/gm, "")
    // Normalize whitespace
    .replace(/\n+/g, " ")
    .replace(/  +/g, " ")
    .trim();

  // Sentence-count cap (applied before length cap)
  if (opts.trimSentences) {
    t = _trimToSentences(t, opts.trimSentences);
  }

  // Character length cap with sentence-boundary preservation
  if (t.length > maxLen) {
    t = t.slice(0, maxLen);
    const lastPeriod = Math.max(t.lastIndexOf(". "), t.lastIndexOf(".\n"));
    if (lastPeriod > maxLen * 0.55) t = t.slice(0, lastPeriod + 1);
    else t = t.trimEnd() + "…";
  }

  // nextStep verb check: if it doesn't start with a capitalized word that looks like a verb,
  // log a warning (we don't auto-fix to avoid introducing errors)
  if (opts.checkVerb) {
    const nonVerbStart = /^(The |A |An |It |This |That |There |You |We |I )/i;
    if (nonVerbStart.test(t)) {
      console.warn("[ai-brief] nextStep may not start with action verb:", t.slice(0, 60));
    }
  }

  return t;
}

// Trim text to at most N sentences (period/exclamation/question mark boundaries)
function _trimToSentences(text, maxSentences) {
  if (!text) return text;
  // Match sentence-ending patterns, keeping the terminator
  const sentences = text.match(/[^.!?]*[.!?](?:\s|$)/g);
  if (!sentences || sentences.length <= maxSentences) return text;
  return sentences.slice(0, maxSentences).join("").trim();
}

// Count only meaningful signal fields (exclude metadata like type/source/pubDate)
function _countSignals(ctx) {
  return [...SIGNAL_FIELDS].filter(k => {
    const v = ctx[k];
    if (v === undefined || v === null || v === false) return false;
    if (Array.isArray(v)) return v.length > 0;
    return true;
  }).length;
}

// Quality guard: log warnings for known tone/safety issues (non-blocking)
function _qualityCheck(result, ctx) {
  const warnings = [];

  // Unauthorized "actively exploited" language
  const exploitLang = /(actively exploit|exploitation confirmed|confirmed exploit)/i;
  if (!ctx.isKEV && exploitLang.test(result.analystBrief + result.executiveBrief)) {
    warnings.push("'actively exploited' language without isKEV=true");
  }

  // Dramatic / forbidden phrases
  const dramatic = /\b(imminent(ly)?|catastrophic|devastat|severe.{0,12}(threat|risk|danger)|definitely (affect|impact|compromise|exploit)|certainly (exploit|attack|affect)|requires? immediate emergency|immediate (emergency|crisis))\b/i;
  if (dramatic.test(result.analystBrief) || dramatic.test(result.executiveBrief) || dramatic.test(result.nextStep)) {
    warnings.push("Dramatic language detected in output");
  }

  // nextStep starts with non-verb indicator
  const nonVerbStart = /^(The |A |An |It |This |That |There |You |We |I )/i;
  if (nonVerbStart.test(result.nextStep)) {
    warnings.push("nextStep may not start with action verb: " + result.nextStep.slice(0, 50));
  }

  if (warnings.length > 0) {
    console.warn("[ai-brief] Quality warnings:", warnings.join(" | "), "— title:", String(ctx.title || "").slice(0, 70));
  }
}
