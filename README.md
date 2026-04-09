# 🛡️ SecPrior

**Open-source threat prioritization for SecOps teams.**

> SecPrior correlates cyber news, CVEs, incidents, and exposure context to help security teams focus on what matters first.

[![CI](https://github.com/dgiry/secprior/actions/workflows/ci.yml/badge.svg)](https://github.com/dgiry/secprior/actions/workflows/ci.yml)
[![CodeQL](https://github.com/dgiry/secprior/actions/workflows/codeql.yml/badge.svg)](https://github.com/dgiry/secprior/actions/workflows/codeql.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/dgiry/secprior)
[![Live Demo](https://img.shields.io/badge/demo-live-blue.svg)](https://secprior.vercel.app)

---

## Why SecPrior?

SecOps teams today face a familiar problem:

- **Too much noise** — dozens of RSS feeds, vendor advisories, CVE alerts, all mixed together
- **No prioritization** — a blog post and an actively-exploited KEV look the same in a feed reader
- **No context** — you know something is critical, but not *why*, and not *for your environment*
- **Manual triage** — analysts spend hours sorting signals instead of acting on them

SecPrior solves this by running every article through a 7-step intelligence pipeline that scores, deduplicates, correlates and contextualizes threats — then surfaces only what matters, with the evidence to act.

---

## What it does

### 🔢 Composite scoring
Every article is scored 0–100 using weighted signals:

| Signal | Weight | Source |
|--------|--------|--------|
| CVSS severity | 30% | NVD API |
| EPSS exploitation probability | 25% | FIRST API |
| CISA KEV (known exploited) | 25% | CISA catalog |
| Source coverage (multi-feed) | 10% | Feed dedup |
| IOC indicators | 5% | In-text extraction |
| Keywords / attack patterns | 5% | Heuristics |

### 🔗 Incident correlation
Articles sharing CVEs, vendors or attack patterns are grouped into consolidated incidents using a Union-Find algorithm — so you see a campaign, not 12 separate articles.

### 👁 Watchlist matching
Configure vendors, products, technologies and keywords. Relevant articles receive the **Matches you** badge and surface to the top of your priorities.

### 📋 Analyst-ready outputs
- **Daily briefing** — structured digest with top threats, KEV count, EPSS leaders
- **Exec View** — CISO-ready posture summary, KPIs, top incidents and vendors
- **PDF Report** — printable weekly threat summary
- **CSV / JSON export** — feed into your SIEM, ticket system or reporting tools

### 🔬 IOC extraction
Automatic extraction of IPs, domains, hashes and URLs from article content. Deep scan mode fetches full article text for richer extraction. Export to CSV/JSON/TXT.

### 🗺 MITRE ATT&CK mapping
Automatic tactic detection (Phishing, Ransomware, Lateral Movement, RCE, 0-Day...) from article text. Displayed as chips on every card.

### ⏱ SLA tracking
Configurable remediation deadlines per priority level (Critical = 1 day, Investigate = 7 days, Watch = 30 days). SLA badges turn red when overdue. KPI bar shows overdue count at a glance.

---

## Who it's for

| Persona | Use case |
|---------|----------|
| **SOC analysts** | Morning triage — what exploded overnight, what needs a ticket |
| **CTI analysts** | Threat correlation, watchlist monitoring, IOC extraction |
| **SecOps leads** | KPI overview, SLA tracking, briefing their team |
| **CISOs / managers** | Exec View — clean posture summary, no raw feeds |
| **MSSPs** | Multi-client profiles, persona presets, PDF/CSV exports |
| **Blue team / homelabs** | Self-hosted, no telemetry, full control |

---

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Vanilla JS, HTML, CSS — zero framework, zero dependencies |
| Backend (optional) | Vercel Serverless Functions (Node.js ≥ 20) |
| Intelligence pipeline | 7-stage client-side: fetch → enrich → dedup → IOC → score → contextualize → prioritize |
| Data enrichment | NVD API, FIRST EPSS API, CISA KEV catalog |
| Alerting | Email (Resend / SendGrid / EmailJS), Slack, Discord, Webhooks, Zapier, Make, n8n |
| Integrations | Jira, Trend Vision One (watchlist sync) |
| Storage | LocalStorage (client-side) + Vercel KV (server-side dedup, optional) |
| Deployment | Vercel (recommended) or any static host + Node.js server |

---

## Quick Start

### Option A — One-click deploy (recommended)

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/dgiry/secprior)

No configuration required for the demo mode. Add environment variables for live feeds and alerts.

### Option B — Local development

```bash
git clone https://github.com/dgiry/secprior.git
cd secprior
npm install        # dev dependencies only (Jest for tests)
npm run dev        # serves at http://localhost:3001
```

Open `http://localhost:3001` — runs in demo mode with sample data.

For live RSS feeds, deploy to Vercel (the feed proxy requires server-side execution to bypass CORS).

### Option C — Self-hosted server

Any Node.js ≥ 20 host works. The `api/` directory contains Vercel Serverless Functions that can be adapted to Express or any Node.js framework.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CRON_SECRET` | For alerting | Secures the scheduled digest endpoint |
| `RESEND_API_KEY` | For email | Resend email provider |
| `SENDGRID_API_KEY` | For email | SendGrid alternative |
| `EMAILJS_*` | For email | EmailJS client-side alternative |
| `SLACK_WEBHOOK_URL` | For Slack | Slack incoming webhook |
| `KV_REST_API_URL` | Recommended | Vercel KV — enables deduplication and run history |
| `KV_REST_API_TOKEN` | Recommended | Vercel KV token |
| `NVD_API_KEY` | Optional | Higher NVD rate limits (500 req/30s vs 5) |

---

## Intelligence Pipeline

```
RSS Feeds (20+ sources)
    ↓
1. Fetch        — parse RSS/Atom, normalize articles
2. Enrich       — CVSS from NVD, EPSS from FIRST, KEV from CISA, vendor NER
3. Deduplicate  — Union-Find on CVE IDs + Jaccard title similarity
4. IOC Extract  — IPs, domains, hashes, URLs from article text
5. Score        — composite 0-100 (CVSS 30% + EPSS 25% + KEV 25% + sources 10% + IOC 5% + keywords 5%)
6. Contextualize — watchlist matching, MITRE ATT&CK detection, trending signals
7. Prioritize   — explainable priority level (Critical Now / Investigate / Watch / Low)
    ↓
Dashboard — cards, KPIs, incidents, CVEs, vendors, briefings
```

---

## Privacy & Security

- **No telemetry** — SecPrior sends no data anywhere except the APIs you configure
- **Self-hosted** — your watchlist, profiles and notes never leave your instance
- **Client-side first** — the intelligence pipeline runs in the browser; the server only proxies public APIs to bypass CORS
- **No tracking** — no analytics, no cookies beyond LocalStorage for your own settings
- **SSRF guard** — server-side API routes include an SSRF guard (`api/_lib/ssrf-guard.js`) blocking requests to private IP ranges

---

## Roadmap

- [ ] Multi-tenant support (per-user profiles, shared watchlists)
- [ ] Additional feed sources (MISP, OpenCTI, STIX/TAXII)
- [ ] AI-generated briefing summaries (opt-in)
- [ ] Mobile-responsive layout improvements
- [ ] i18n / localization framework
- [ ] Webhook inbound (receive alerts from external systems)
- [ ] Docker image for simplified self-hosting

---

## Contributing

Contributions are welcome. Areas where help is most valuable:

- **New feed sources** — add RSS feeds to `js/feeds-config.js`
- **Enrichment integrations** — new API sources (VirusTotal, Shodan, etc.)
- **UI improvements** — the frontend is vanilla JS, easy to modify
- **Tests** — `npm test` runs Jest; coverage is currently focused on the pipeline
- **Documentation** — deploy guides, use-case walkthroughs, video demos

Please open an issue before submitting a large PR.

---

## License

MIT — free to use, modify and self-host. See [LICENSE](LICENSE).

---

*Built for the security community. If SecPrior is useful to your team, a ⭐ on GitHub helps others find it.*
