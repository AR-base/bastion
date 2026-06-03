# Contributing to Bastion

Thanks for your interest in improving Bastion.

## Development setup

```bash
git clone https://github.com/AR-base/bastion.git
cd bastion
npm install        # installs wrangler (dev dependency)
```

## Running tests

All core logic — analyzers, scoring, the SSRF guard, and the AI request builder — is covered by unit tests with no network dependency.

```bash
node --test
```

CI runs the same suite on every push and pull request, and also fails the build if an API key pattern is found in source.

## Local development

```bash
npx wrangler dev
```

This serves the frontend and the `/api/scan` Worker locally. To exercise the AI briefing locally, set the key first:

```bash
npx wrangler secret put ANTHROPIC_API_KEY
```

## Guidelines

- **Keep checks passive.** Bastion must never gain active-scanning, exploitation, or authentication behavior. Pull requests that add intrusive probing will be declined.
- **Preserve SSRF protections.** Any change to fetching or redirect handling must keep every hop validated against the SSRF guard, and must add tests for new bypass vectors.
- **Add tests with new checks.** New analyzers belong in `lib/analyzers.js` as pure functions, with cases in `test/`.
- **No secrets in commits.** Configuration goes in `wrangler.toml`; credentials go through Worker secrets.

## Project layout

```
src/worker.js     Worker entry: routing + SSRF-guarded fetch + orchestration
lib/              Pure logic: ssrf-guard, analyzers, scoring, ai-summary
public/           Frontend served via the static-assets binding
test/             Unit tests (node --test)
```
