// Bastion — Cloudflare Worker entry point.
//
// Serves the static frontend (via the [assets] binding) and exposes one API
// route: POST /api/scan { url }. The Worker performs an SSRF-guarded fetch of
// the target, runs the passive analyzers, scores the result, and (if an API
// key is configured) attaches a plain-English AI briefing.

import {
  parseAndValidateUrl,
  resolveAndCheck,
  isForbiddenHost,
  UrlRejected,
} from '../lib/ssrf-guard.js';
import { runAllChecks } from '../lib/analyzers.js';
import { computeScore } from '../lib/scoring.js';
import { generateBriefing } from '../lib/ai-summary.js';

const FETCH_TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 5;
const USER_AGENT = 'BastionScanner/1.0 (+passive security posture check)';

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...extraHeaders,
    },
  });
}

function headersToObject(headers) {
  const obj = {};
  for (const [k, v] of headers) obj[k.toLowerCase()] = v;
  return obj;
}

function getSetCookies(headers) {
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

// Fetch following redirects manually so every hop can be re-validated against
// the SSRF guard — an allowed origin must not be able to redirect us inward.
async function safeFetch(startUrl, fetchImpl, method = 'GET') {
  let current = startUrl;
  let redirects = 0;

  while (true) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let resp;
    try {
      resp = await fetchImpl(current.toString(), {
        method,
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'user-agent': USER_AGENT, accept: '*/*' },
      });
    } finally {
      clearTimeout(timer);
    }

    const status = resp.status;
    if (status >= 300 && status < 400) {
      const location = resp.headers.get('location');
      if (!location) return { resp, finalUrl: current };
      if (++redirects > MAX_REDIRECTS) {
        throw new UrlRejected('Too many redirects', 'redirect_loop');
      }
      const next = parseAndValidateUrl(new URL(location, current).toString());
      if (isForbiddenHost(next.hostname)) {
        throw new UrlRejected('Redirect points to a private address', 'redirect_private');
      }
      await resolveAndCheck(next.hostname, fetchImpl);
      // Don't consume the redirect body.
      if (resp.body && typeof resp.body.cancel === 'function') resp.body.cancel().catch(() => {});
      current = next;
      continue;
    }
    return { resp, finalUrl: current };
  }
}

async function handleScan(request, env) {
  // /api/scan makes outbound network requests and (optionally) calls the
  // Anthropic API, so unauthenticated bursts are expensive. The
  // SCAN_RATE_LIMITER binding (see wrangler.toml) is keyed on caller IP; if
  // the binding is absent (e.g. local dev) we proceed without limiting.
  if (env && env.SCAN_RATE_LIMITER) {
    const ip = request.headers.get('cf-connecting-ip') ||
      request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      'unknown';
    const { success } = await env.SCAN_RATE_LIMITER.limit({ key: ip });
    if (!success) {
      return json({ error: 'Too many scans from this IP. Try again in a minute.' }, 429, {
        'retry-after': '60',
      });
    }
  }

  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: 'Request body must be valid JSON.' }, 400);
  }

  const rawUrl = payload && payload.url;
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    return json({ error: 'Provide a "url" field with the website to scan.' }, 400);
  }

  let target;
  try {
    target = parseAndValidateUrl(rawUrl);
  } catch (err) {
    if (err instanceof UrlRejected) return json({ error: err.message, code: err.code }, 400);
    return json({ error: 'Could not process that URL.' }, 400);
  }

  // Resolve + screen every IP the hostname maps to.
  try {
    await resolveAndCheck(target.hostname, fetch);
  } catch (err) {
    if (err instanceof UrlRejected) return json({ error: err.message, code: err.code }, 403);
    return json({ error: 'Could not resolve that host.' }, 502);
  }

  // Primary fetch (force HTTPS view when available).
  let primary;
  try {
    primary = await safeFetch(target, fetch);
  } catch (err) {
    if (err instanceof UrlRejected) return json({ error: err.message, code: err.code }, 403);
    return json({ error: 'The site did not respond in time.' }, 504);
  }

  const finalUrl = primary.finalUrl;
  const isHttps = finalUrl.protocol === 'https:';
  const headerObj = headersToObject(primary.resp.headers);
  const setCookies = getSetCookies(primary.resp.headers);
  if (primary.resp.body && typeof primary.resp.body.cancel === 'function') {
    primary.resp.body.cancel().catch(() => {});
  }

  // Secondary probe: does plain HTTP redirect to HTTPS?
  let httpRedirectsToHttps = null;
  if (isHttps) {
    try {
      const httpUrl = new URL(finalUrl.toString());
      httpUrl.protocol = 'http:';
      const httpProbe = await safeFetch(parseAndValidateUrl(httpUrl.toString()), fetch);
      httpRedirectsToHttps = httpProbe.finalUrl.protocol === 'https:';
      if (httpProbe.resp.body && typeof httpProbe.resp.body.cancel === 'function') {
        httpProbe.resp.body.cancel().catch(() => {});
      }
    } catch {
      httpRedirectsToHttps = null; // inconclusive; analyzer treats null as "unknown"
    }
  }

  const findings = runAllChecks({
    headers: headerObj,
    setCookies,
    isHttps,
    httpRedirectsToHttps,
  });
  const { score, grade, counts } = computeScore(findings);

  const scanResult = {
    url: finalUrl.toString(),
    scannedAt: new Date().toISOString(),
    httpStatus: primary.resp.status,
    grade,
    score,
    counts,
    findings,
  };

  scanResult.briefing = await generateBriefing(
    scanResult,
    env && env.ANTHROPIC_API_KEY,
    fetch,
    (env && env.AI_MODEL) || undefined,
  );
  return json(scanResult);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/scan') {
      if (request.method !== 'POST') return json({ error: 'Use POST.' }, 405);
      return handleScan(request, env);
    }

    // Everything else is served by the static assets binding.
    if (env && env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Not found', { status: 404 });
  },
};

export { handleScan, safeFetch };
