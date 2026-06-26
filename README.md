# Bastion

[![CI](https://github.com/AR-base/bastion/actions/workflows/ci.yml/badge.svg)](https://github.com/AR-base/bastion/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Cloudflare Workers](https://img.shields.io/badge/runtime-Cloudflare%20Workers-f38020.svg)
![Claude](https://img.shields.io/badge/model-Claude%20Haiku%204.5-orange.svg)

A fast, **passive** website security scanner for small businesses and startups, built on Cloudflare Workers. It checks the security signals an attacker looks at first — transport security, response headers, cookie flags, CORS, and information disclosure — scores them A–F, and uses Claude Haiku to explain the risks in plain language for a non-technical owner.

It does **not** attack, probe, fuzz, or log into the target. It only inspects what the server already returns to any visitor. Only scan sites you own or are authorized to test.

**Security policy:** [SECURITY.md](SECURITY.md) · **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)

## Architecture

```
bastion/
├── src/worker.js        Worker entry: routing + SSRF-guarded fetch + orchestration
├── lib/
│   ├── ssrf-guard.js    URL validation, obfuscated-IP normalization, private-range
│   │                    blocking (v4/v6), DNS-over-HTTPS resolution + re-check
│   ├── analyzers.js     Pure passive checks → findings
│   ├── scoring.js       Findings → 0–100 score + A–F grade
│   └── ai-summary.js    Builds the Claude Haiku request → plain-English briefing
├── public/index.html    Frontend (served via the static-assets binding)
├── test/                Unit tests (node --test), incl. SSRF bypass attempts
├── wrangler.toml        Worker + assets config (no secrets stored here)
└── package.json
```

The analysis, scoring, SSRF IP logic, and AI request builder are all pure functions, which is why they're unit-tested without any network calls. The live fetch is integration-tested on deploy.

## Security decisions (why it's built this way)

- **SSRF is the headline risk.** A server that fetches user-supplied URLs can be tricked into hitting internal services or the cloud metadata endpoint (`169.254.169.254`). Defenses: scheme allowlist; rejection of URL credentials; canonicalization of decimal/octal/hex IP literals so `http://2130706433` (= 127.0.0.1) can't sneak through; blocking of all private/loopback/link-local/reserved ranges for IPv4, IPv6, and IPv4-mapped IPv6; DNS-over-HTTPS resolution with a re-check of every returned IP; and re-validation of **every redirect hop** so an allowed origin can't 302 us inward. DNS resolution **fails closed**.
- **No secrets in source.** The Anthropic API key is a Wrangler secret read from `env`, never committed.
- **Graceful degradation.** With no key set, the scanner returns full technical findings; the key only adds the AI briefing.
- **Output encoding.** The frontend HTML-escapes all scan data before rendering, so a hostile `Server` header can't inject script into the report.
- **Known limitation:** TOCTOU DNS rebinding (a record that changes between the resolve check and the fetch) is not fully eliminated. For higher assurance, add a Cloudflare WAF rate-limit rule and consider pinning the resolved IP. Documented honestly rather than hidden.

## Run the tests

```powershell
cd bastion
node --test
```

## Deploy to Cloudflare (Windows PowerShell)

```powershell
# 1. Install the Cloudflare CLI (one time)
npm install -g wrangler

# 2. Log in (opens your browser)
wrangler login

# 3. From the project folder, set your Anthropic key as an encrypted secret.
#    Paste the key when prompted — it is never written to disk in the repo.
cd bastion
wrangler secret put ANTHROPIC_API_KEY

# 4. Deploy
wrangler deploy
```

Wrangler prints your live URL (e.g. `https://bastion.<your-subdomain>.workers.dev`). Open it and scan a site.

To run it locally before deploying:

```powershell
cd bastion
wrangler dev
```

## Choosing the AI model

The briefing model is set by the `AI_MODEL` var in `wrangler.toml` (currently `claude-opus-4-8`). Change that one line and redeploy, or override it in the Cloudflare dashboard with no redeploy:

- `claude-haiku-4-5-20251001` — cheapest and fastest, ~$0.002/scan. Recommended default, since the heavy analysis is done in code and the model only writes the summary.
- `claude-sonnet-4-6` — middle ground, ~3x Haiku cost.
- `claude-opus-4-8` — flagship, richest prose, ~5x Haiku cost (~$0.01/scan).

If `AI_MODEL` is unset the code falls back to Haiku.

## Next steps worth adding

- A Cloudflare WAF **rate-limit rule** on `/api/scan` (free tier) to prevent abuse.
- Optional `.well-known` / DNS email checks (SPF, DMARC) via DoH TXT lookups.
- A shareable result link backed by Workers KV.
