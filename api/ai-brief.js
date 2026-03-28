// api/ai-brief.js — AI Brief generation endpoint (Sprint IA v3 — action-ready)
//
// Calls Anthropic Claude API to generate SIX structured outputs
// from verified security signals already present in CyberVeille Pro.
//
// Requires: ANTHROPIC_API_KEY environment variable on Vercel.
//
// POST /api/ai-brief
// Body: structured context object (whitelisted fields only — see ALLOWED_FIELDS)
//
// Returns: {
//   analystBrief, executiveBrief, nextStep,   ← Sprint IA v1/v2
//   ticketDraft, escalationNote, shareRewrite  ← Sprint IA v3 (new)
//   model, generatedAt, signalCount
// }
//
// Sprint IA v3 additions:
//   ticketDraft    — structured text (TITLE/PRIORITY/SUMMARY/WHY/ACTION/SIGNALS)
//                    for Jira / ServiceNow / ops handoff
//   escalationNote — 3-4 plain-text lines for team lead / incident manager
//   shareRewrite   — 3-5 line natural-language message for Slack / Teams / internal mail
//
// All v2 guardrails preserved:
//   • Whitelist input, signal-summary user prompt, anti-drama tone rules
//   • isKEV required for "actively exploited" language
//   • Per-priorityLevel urgency vocabulary
//   • POST-PROCESSING: sentence trim, bullet strip, quality check
//
// MAX_TOKENS: 700 → 1000 (6 outputs require more room)
// CLIENT TIMEOUT: 28s (slightly more than v2 due to extra output tokens)

"use strict";

const ANTHROPIC_API   = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VER   = "2023-06-01";
const MODEL           = "claude-haiku-4-5-20251001";
const MAX_TOKENS      = 1000;  // v3: increased from 700 to accommodate 6 outputs
const REQUEST_TIMEOUT = 18_000; // 18 s

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

  // Core brief fields are required; new action fields are optional (graceful fallback)
  if (!parsed.analystBrief || !parsed.executiveBrief || !parsed.nextStep) {
    console.error("[ai-brief] Incomplete core response fields:", Object.keys(parsed));
    return res.status(502).json({ error: "Incomplete AI response" });
  }

  // ── Post-process all six outputs ──────────────────────────────────────────
  const result = {
    // Core brief (v1/v2 — unchanged limits)
    analystBrief:   _postProcess(parsed.analystBrief,    900, { trimSentences: 5 }),
    executiveBrief: _postProcess(parsed.executiveBrief,  320, { trimSentences: 2 }),
    nextStep:       _postProcess(parsed.nextStep,        260, { trimSentences: 1, checkVerb: true }),
    // Action outputs (v3 — new)
    ticketDraft:    _postProcess(parsed.ticketDraft    || "", 1200, { isStructured: true }),
    escalationNote: _postProcess(parsed.escalationNote || "", 600,  { trimSentences: 4 }),
    shareRewrite:   _postProcess(parsed.shareRewrite   || "", 400,  { trimSentences: 5 }),
    // Metadata
    model:         "claude-haiku",
    generatedAt:   new Date().toISOString(),
    signalCount:   _countSignals(ctx)
  };

  _qualityCheck(result, ctx);

  return res.status(200).json(result);
};

// ── System prompt ─────────────────────────────────────────────────────────────
//
// v3: adds ticketDraft, escalationNote, shareRewrite to the existing 3 outputs.
// All v2 tone rules, guardrails, and per-section differentiation rules are preserved.

function _buildSystemPrompt() {
  return `You write professional security outputs for ThreatLens, a SOC/SecOps platform. Your readers are security analysts, team leads, managers, and ops teams. Your tone is sober, factual, and operationally useful.

═══ TONE RULES (apply to all six outputs) ═══
- Factual and measured. No marketing language, no drama, no hype.
- Prefer: "should be", "may warrant", "warrants review", "based on available signals".
- Forbidden: "severe threat", "imminent danger", "devastating", "definitely affecting", "certainly exploited", "highly likely", "requires immediate emergency action", "poses a major risk to your organization".
- Never say an environment is compromised or exposed — you cannot verify internal inventory.
- If confidence is low, say so: "Limited context — assessment based on metadata signals only."

═══ ANTI-HALLUCINATION RULES (mandatory) ═══
1. Only use facts from the provided JSON. Never add context not in the data.
2. Only write "actively exploited" if isKEV is true.
3. Only reference CVEs from the "cves" array. Never invent identifiers.
4. Only reference vendor names from the "vendors" array. Never invent names.
5. Never invent: IP addresses, domains, file hashes, threat actors, malware names, attribution.
6. Never recommend specific patch versions unless in the description field.
7. Never say "your environment" is affected — the platform does not know internal inventory.

═══ SIX OUTPUTS — distinct purpose, distinct reader ═══

── analystBrief ── FOR: SOC analyst (triage)
- 3 to 5 sentences. Lead with the strongest signal (KEV > EPSS ≥50% > CVSS ≥7 > watchlist > CVE).
- Cite concrete values: EPSS %, CVSS score, CVE IDs, vendor names (from data only).
- Focus: what type of threat, key indicators, what triage action is warranted.
- Do NOT open by restating the article title. Do NOT use bullet points.

── executiveBrief ── FOR: CISO / security director / manager (10-second decision read)
- EXACTLY 2 sentences. Hard limit — never write a third sentence, no matter how rich the context.
- Sentence 1: why this item warrants attention right now — plain business stakes, no technical signal dump. Write for someone who will not read the full details.
- Sentence 2: what the security team or manager should validate, prepare, or confirm internally.
- FORBIDDEN in this section — never use, not even once:
  · Raw EPSS percentages ("EPSS 87%", "87.3%", "score of 0.87")
  · Raw CVSS scores ("CVSS 9.8", "severity score of 9.8", "9.8/10")
  · CVE identifiers ("CVE-2024-XXXX", "CVE number", "the CVE")
  · Technical jargon: "remote code execution capability", "threat actor TTPs", "MITRE ATT&CK", "attack vector", "lateral movement", "privilege escalation vector"
  · Long signal enumerations ("vendor A, vendor B, IOC count 14, EPSS 87%, watchlist match…")
  · Repetition of what was already said in analystBrief
- REQUIRED plain-language translations (use these instead of raw values):
  · EPSS ≥ 50%    → "elevated probability of exploitation in the near term"
  · EPSS ≥ 80%    → "high probability of exploitation in the near term"
  · isKEV = true  → "confirmed active exploitation in the wild"
  · watchlist hit → "a technology or vendor in your monitored scope"
  · CVSS ≥ 9      → "critical severity"
  · CVSS 7–8.9    → "high severity"
  · trending      → "confirmed across multiple independent sources"
  · iocCount > 0  → "associated indicators have been extracted" (only if directly relevant)
- If context is poor or signals are weak: use "Limited information is available at this stage — monitor for updates." as sentence 2 if nothing concrete can be said.
- Tone: sober, measured, decision-ready. Not alarming, not dismissive.
- ZERO-DAY / NO-PATCH RULE — applies when signals indicate active exploitation with no patch available:
  · Sentence 1: state that a critical vulnerability in the affected product or vendor is actively exploited and no patch is currently available. Plain language, no mechanics.
  · Sentence 2: state that immediate internal validation of exposure is warranted and that readiness to apply temporary mitigations should be assessed if affected systems are present.
  · NEVER include in Executive Brief for zero-day cases: isolation steps, containment instructions, vendor coordination steps, compensating control details, incident response engagement, or any multi-step operational guidance.
  · All operational actions belong in: Recommended Next Step, Ticket Draft, or Analyst Brief — not here.
  · Preferred phrasing model: "A zero-day affecting [product/vendor] is being actively exploited with no patch currently available. Immediate validation of internal exposure is warranted, along with readiness to apply temporary mitigations if affected systems are identified."
  · Forbidden in zero-day Executive Brief: "isolate affected systems", "coordinate with vendor support", "engage incident response immediately", "deploy compensating controls across the environment", "activate your incident response plan".

── nextStep ── FOR: analyst / responder (first action)
- Exactly 1 sentence. Starts with action verb. Matches priorityLevel urgency:
  critical_now → "Immediately…" / "Urgently…" (only if KEV or EPSS ≥50%)
  investigate  → "Assess…" / "Validate whether…"
  watch        → "Monitor…" / "Flag for review…"
  low          → "Note for scheduled review" / "Track in threat intelligence backlog."
- Do NOT mention IOC blocking/hunting if iocCount is 0 or absent.
- Do NOT repeat what was said in analystBrief or executiveBrief.

── ticketDraft ── FOR: Jira / ServiceNow / ops handoff
- Use this EXACT format, one field per line, separated by \\n:
  TITLE: [concise title, max 75 chars]
  PRIORITY: [e.g. "P1 — Critical / Immediate" matching priorityLevel]
  SUMMARY: [2 sentences: what the threat is, which vendor/technology is concerned]
  WHY IT MATTERS: [1-2 sentences: operational risk based on available signals, no invented exposure]
  RECOMMENDED ACTION: [1-2 sentences: what the team should do first, match priorityLevel urgency]
  KEY SIGNALS: [comma-separated list: e.g. "KEV confirmed, EPSS 87%, CVSS 9.8, CVE-2024-1234, Vendor: Cisco"]
- Tone: technical, direct, handoff-ready. No drama.
- Do NOT invent internal fields (owner, sprint, component, ticket number, SLA).
- If context is poor: all sections should be brief and acknowledge limited information.

── escalationNote ── FOR: team lead / incident manager (escalation decision)
- Exactly 3 to 4 short plain-text lines, separated by \\n.
- Line 1: What — one sentence: what type of event, what scope (use "an item in your monitored scope" if watchlist match, avoid inventing specific systems).
- Line 2: Why now — the key signal driving urgency (one concrete signal: KEV, EPSS value, watchlist match, or trending across sources).
- Line 3: Scope — what systems/vendors are in scope or "Scope not confirmed — internal validation needed."
- Line 4: Recommendation — choose one: "Escalation is recommended." / "Review recommended before escalation." / "No immediate escalation required — monitor for new signals." (match priorityLevel).
- Max one technical term per line. No jargon dump. Tone: concise, professional.

── shareRewrite ── FOR: Slack / Teams / internal mail (quick circulation)
- 3 to 4 plain-text lines, separated by \\n. Max 55 words total.
- Line 1: Direct opening — what was identified and why it is relevant (natural, not alarming).
- Line 2: Key signals in plain terms — no raw acronym dump (e.g. "Actively exploited · CVSS 9.8 · Affects Cisco" not "isKEV=true EPSS=87.3").
- Line 3: One-line action for the recipient ("Analyst team is reviewing — flag if you have exposed assets." or similar).
- No bullet points. No markdown. No emoji. No invented details.
- Tone: collegial, informational, calm.

═══ POOR CONTEXT RULES ═══
- Use "Limited context — " prefix ONLY when the user prompt explicitly says "Context quality: POOR". Do NOT use it otherwise.
- When "Context quality: PARTIAL" is indicated: description is minimal but strong signals are present. Write normally using the available signal data. Do NOT use "Limited context" prefix.
- Strong signals that make "Limited context" inappropriate: KEV confirmed, CVEs present, watchlist hit, ATT&CK tags, trending across ≥2 sources, incident with ≥2 sources, incident with a meaningful summary. If any of these are present, write a normal confident brief based on the signals.
- priorityLevel "low" or "watch" with no strong signals: calm tone, no urgency.
- No vendor present: do not mention "vendor exposure" in any output.
- No IOC present: do not mention IOC blocking or IOC-based detection.

═══ QUALITY RULES (cross-output) ═══
- Preserve source names exactly as provided in the data. Never guess, translate, paraphrase, or normalize a source name incorrectly.
- Analyst Brief is for a security analyst or triage lead: concise, operational, signal-driven, grounded in the strongest available indicators.
- If KEV is present, treat confirmed exploitation as the primary signal. If EPSS is low but KEV is true, state clearly that confirmed exploitation takes precedence over statistical likelihood.
- Executive Brief is for a security manager or incident lead: maximum 2 sentences, plain language, decision-oriented, and clearly different from the Analyst Brief.
- Executive Brief must avoid raw signal dumping unless strictly necessary: avoid exact EPSS percentages, CVSS numbers, ATT&CK IDs, exploit mechanics, or long enumerations of indicators.
- Recommended Next Step must be exactly 1 sentence, start with an action verb, stay prudent, and avoid over-prescriptive language when context is incomplete.
- Do not repeat the same fact across sections. Analyst Brief explains the signal, Executive Brief explains why leadership attention is warranted, Next Step states the immediate validation or action step.
- Use a sober enterprise SecOps tone: precise, non-dramatic, non-marketing.
- Avoid phrases like: "severe threat", "highly dangerous", "critical cyber emergency", "immediate emergency action", "definitely affecting your environment".
- Prefer phrases like: "based on available signals", "warrants review", "should be validated internally", "may justify escalation".
- If context is weak, say so briefly and stay conservative. Do not fill gaps with generic filler language.
- Prefer fewer, sharper sentences over longer summaries.

═══ OUTPUT FORMAT ═══
Return ONLY a valid JSON object with exactly these six keys. Use \\n for line breaks within values. No markdown fences. No text before or after.
{"analystBrief":"...","executiveBrief":"...","nextStep":"...","ticketDraft":"TITLE: ...\\nPRIORITY: ...\\nSUMMARY: ...\\nWHY IT MATTERS: ...\\nRECOMMENDED ACTION: ...\\nKEY SIGNALS: ...","escalationNote":"Line 1.\\nLine 2.\\nLine 3.\\nLine 4.","shareRewrite":"Line 1.\\nLine 2.\\nLine 3."}`;
}

// ── User prompt — enriched with signal summary ────────────────────────────────

function _buildUserPrompt(ctx) {
  const lines = [];

  const levelMap = {
    critical_now: "CRITICAL — immediate action required",
    investigate:  "HIGH — investigate and validate",
    watch:        "MEDIUM — monitor",
    low:          "LOW — routine review"
  };
  if (ctx.priorityLevel) {
    lines.push(`Priority level: ${levelMap[ctx.priorityLevel] || ctx.priorityLevel.toUpperCase()}`);
  }

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

  if (ctx.type === "incident") {
    if (ctx.articleCount) lines.push(`Grouped articles: ${ctx.articleCount}`);
    if (ctx.sourceCount)  lines.push(`Distinct sources: ${ctx.sourceCount}`);
    if (ctx.firstSeen)    lines.push(`First seen: ${String(ctx.firstSeen).slice(0, 10)}`);
    if (ctx.lastSeen)     lines.push(`Last activity: ${String(ctx.lastSeen).slice(0, 10)}`);
  }

  const descLen = String(ctx.description || "").length;
  // A signal is "strong" if any of these are present — even a sparse description
  // is sufficient context to write normally when these indicators exist.
  const hasStrongSignal =
    ctx.isKEV ||
    (ctx.cves?.length > 0) ||
    (ctx.watchlistHit === true) ||
    (ctx.watchlistHits?.length > 0) ||
    (ctx.trendingCount || 0) >= 2 ||
    (ctx.attackTags?.length > 0) ||
    (ctx.type === "incident" && (ctx.sourceCount || 0) >= 2) ||
    (ctx.type === "incident" && String(ctx.summary || "").length > 40);

  if (descLen < 40 && !hasStrongSignal) {
    lines.push("Context quality: POOR — use metadata signals only, acknowledge limited context in all outputs");
  } else if (descLen < 40) {
    lines.push("Context quality: PARTIAL — description minimal but strong signals are present; write normally from signal data, do NOT use 'Limited context' prefix");
  }

  const signalSummary = lines.length > 0
    ? `KEY SIGNALS:\n${lines.map(l => `  • ${l}`).join("\n")}\n\n`
    : "";

  return `Generate all six required outputs for this security event.\n\n${signalSummary}FULL DATA:\n${JSON.stringify(ctx, null, 2)}`;
}

// ── Post-processing ───────────────────────────────────────────────────────────

function _postProcess(text, maxLen, opts = {}) {
  if (typeof text !== "string") return "";

  let t = text
    .replace(/\*\*/g, "")
    .replace(/\*/g,   "")
    .replace(/#{1,4} /g, "")
    .replace(/`/g,    "");

  if (opts.isStructured) {
    // For ticketDraft: preserve \n as-is, only strip other artifacts
    t = t.replace(/  +/g, " ").trim();
  } else {
    // For prose outputs: strip bullets, collapse whitespace
    t = t
      .replace(/^[\-\•\–]\s+/gm, "")
      .replace(/\n+/g, " ")
      .replace(/  +/g, " ")
      .trim();

    if (opts.trimSentences) {
      t = _trimToSentences(t, opts.trimSentences);
    }
  }

  // Character cap
  if (t.length > maxLen) {
    if (opts.isStructured) {
      // For structured text, just truncate cleanly at a line boundary
      const lastNl = t.lastIndexOf("\n", maxLen);
      t = lastNl > maxLen * 0.7 ? t.slice(0, lastNl) : t.slice(0, maxLen).trimEnd() + "…";
    } else {
      t = t.slice(0, maxLen);
      const lastPeriod = Math.max(t.lastIndexOf(". "), t.lastIndexOf(".\n"));
      if (lastPeriod > maxLen * 0.55) t = t.slice(0, lastPeriod + 1);
      else t = t.trimEnd() + "…";
    }
  }

  if (opts.checkVerb) {
    const nonVerbStart = /^(The |A |An |It |This |That |There |You |We |I )/i;
    if (nonVerbStart.test(t)) {
      console.warn("[ai-brief] nextStep may not start with action verb:", t.slice(0, 60));
    }
  }

  return t;
}

function _trimToSentences(text, maxSentences) {
  if (!text) return text;
  const sentences = text.match(/[^.!?]*[.!?](?:\s|$)/g);
  if (!sentences || sentences.length <= maxSentences) return text;
  return sentences.slice(0, maxSentences).join("").trim();
}

function _countSignals(ctx) {
  return [...SIGNAL_FIELDS].filter(k => {
    const v = ctx[k];
    if (v === undefined || v === null || v === false) return false;
    if (Array.isArray(v)) return v.length > 0;
    return true;
  }).length;
}

function _qualityCheck(result, ctx) {
  const warnings = [];

  const exploitLang = /(actively exploit|exploitation confirmed|confirmed exploit)/i;
  if (!ctx.isKEV && exploitLang.test(result.analystBrief + result.executiveBrief + result.escalationNote + result.shareRewrite)) {
    warnings.push("'actively exploited' language without isKEV=true");
  }

  const dramatic = /\b(imminent(ly)?|catastrophic|devastat|severe.{0,12}(threat|risk|danger)|definitely (affect|impact|compromise|exploit)|certainly (exploit|attack|affect)|requires? immediate emergency)\b/i;
  const allText = [result.analystBrief, result.executiveBrief, result.nextStep, result.ticketDraft, result.escalationNote, result.shareRewrite].join(" ");
  if (dramatic.test(allText)) {
    warnings.push("Dramatic language detected in output");
  }

  const nonVerbStart = /^(The |A |An |It |This |That |There |You |We |I )/i;
  if (nonVerbStart.test(result.nextStep)) {
    warnings.push("nextStep may not start with action verb: " + result.nextStep.slice(0, 50));
  }

  // Executive brief: raw technical signal dump check
  const execRawSignals = /\bEPSS\s*[\d.]|CVSS\s*[\d.]|\bCVE-\d{4}-\d+\b|remote code execution capability|\bTTPs\b|ATT&CK|attack vector|lateral movement|privilege escalation vector/i;
  if (execRawSignals.test(result.executiveBrief)) {
    warnings.push("executiveBrief contains raw technical signals or jargon — expected plain management language: " + result.executiveBrief.slice(0, 100));
  }

  // Executive brief: sentence count (hard limit is 2 — post-processed, but log overruns)
  const execSentences = (result.executiveBrief.match(/[^.!?]*[.!?](?:\s|$)/g) || []).filter(s => s.trim().length > 4);
  if (execSentences.length > 2) {
    warnings.push(`executiveBrief has ${execSentences.length} sentences (max 2)`);
  }

  // Executive brief: operational action language (zero-day / no-patch drift)
  const execOperational = /\b(isolat(e|ion|ing)|coordinat(e|ing) with vendor|engage incident response|deploy(ing)? compensating control|contain(ment|ing)|activate.{0,20}incident response|vendor support)\b/i;
  if (execOperational.test(result.executiveBrief)) {
    warnings.push("executiveBrief contains operational action language (isolation/containment/IR/vendor coordination) — belongs in nextStep or ticketDraft: " + result.executiveBrief.slice(0, 120));
  }

  if (warnings.length > 0) {
    console.warn("[ai-brief] Quality warnings:", warnings.join(" | "), "— title:", String(ctx.title || "").slice(0, 70));
  }
}
