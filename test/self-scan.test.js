// Bastion must pass every check it runs on other sites. These tests send
// requests through the real Worker entry point and grade the responses with
// Bastion's own analyzers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import worker from '../src/worker.js';
import { runAllChecks } from '../lib/analyzers.js';
import { computeScore } from '../lib/scoring.js';
import { CSP, SECURITY_HEADERS, httpsRedirect, withSecurityHeaders } from '../lib/security-headers.js';

// Stand-in for the static-assets binding: returns a page with no headers of its
// own, plus a header that leaks a version, to prove the Worker strips it.
const env = {
  ASSETS: {
    fetch: async () => new Response('<!doctype html><title>Bastion</title>', {
      headers: { 'content-type': 'text/html; charset=utf-8', 'x-powered-by': 'Express 4.18' },
    }),
  },
};

function headersOf(response) {
  const obj = {};
  for (const [k, v] of response.headers) obj[k.toLowerCase()] = v;
  return obj;
}

async function selfScan(path) {
  const httpsResp = await worker.fetch(new Request(`https://bastion.example${path}`), env);
  const httpResp = await worker.fetch(new Request(`http://bastion.example${path}`), env);
  const redirectsToHttps = httpResp.status === 301 &&
    new URL(httpResp.headers.get('location')).protocol === 'https:';
  const findings = runAllChecks({
    headers: headersOf(httpsResp),
    setCookies: [],
    isHttps: true,
    httpRedirectsToHttps: redirectsToHttps,
  });
  return { findings, ...computeScore(findings) };
}

test('Bastion grades its own home page A with a perfect score', async () => {
  const { findings, score, grade } = await selfScan('/');
  const problems = findings.filter((f) => f.status !== 'pass').map((f) => f.title);
  assert.deepEqual(problems, [], `self-scan found: ${problems.join(', ')}`);
  assert.equal(score, 100);
  assert.equal(grade, 'A');
});

test('the API and error responses carry the same protection', async () => {
  const resp = await worker.fetch(new Request('https://bastion.example/api/scan'), env);
  assert.equal(resp.status, 405);
  assert.equal(resp.headers.get('content-security-policy'), CSP);
  assert.equal(resp.headers.get('strict-transport-security'), SECURITY_HEADERS['strict-transport-security']);
  const score = computeScore(runAllChecks({ headers: headersOf(resp), isHttps: true, httpRedirectsToHttps: true }));
  assert.equal(score.score, 100);
});

test('plain HTTP is redirected to HTTPS with path and query kept', async () => {
  const resp = await worker.fetch(new Request('http://bastion.example/docs?q=1'), env);
  assert.equal(resp.status, 301);
  assert.equal(resp.headers.get('location'), 'https://bastion.example/docs?q=1');
});

test('local development over http is not redirected', () => {
  assert.equal(httpsRedirect(new Request('http://localhost:8787/')), null);
  assert.equal(httpsRedirect(new Request('http://127.0.0.1:8787/')), null);
});

test('version-revealing headers are removed', async () => {
  const resp = await worker.fetch(new Request('https://bastion.example/'), env);
  assert.equal(resp.headers.get('x-powered-by'), null);
});

test('the policy forbids inline script, inline style and eval', () => {
  assert.doesNotMatch(CSP, /unsafe-inline|unsafe-eval/);
  assert.match(CSP, /default-src 'none'/);
  assert.match(CSP, /frame-ancestors 'none'/);
});

test('weaker upstream headers are overridden', async () => {
  const weak = new Response('x', { headers: { 'content-security-policy': "default-src *; script-src 'unsafe-inline'" } });
  assert.equal(withSecurityHeaders(weak).headers.get('content-security-policy'), CSP);
});

test('public/_headers matches the headers the Worker sets', () => {
  const file = readFileSync(new URL('../public/_headers', import.meta.url), 'utf8');
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    assert.ok(file.includes(`${name}: ${value}`), `public/_headers is missing or out of date for ${name}`);
  }
});

test('the page has no inline script, inline style or event-handler attributes', () => {
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /<style[\s>]/i, 'inline <style> block');
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, 'inline <script> block');
  assert.doesNotMatch(html, /\sstyle\s*=/i, 'style= attribute');
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i, 'inline event handler');
  const js = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.doesNotMatch(js, /\sstyle\s*=\s*["']/i, 'app.js builds markup with a style= attribute');
});
