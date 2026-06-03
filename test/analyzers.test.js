import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeHeaders,
  analyzeCookies,
  analyzeCors,
  analyzeTransport,
  runAllChecks,
} from '../lib/analyzers.js';
import { computeScore, gradeFor } from '../lib/scoring.js';

function byId(findings, id) {
  return findings.find((f) => f.id === id);
}

test('a hardened site passes the core header checks', () => {
  const headers = {
    'strict-transport-security': 'max-age=63072000; includeSubDomains',
    'content-security-policy': "default-src 'self'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'geolocation=()',
  };
  const findings = analyzeHeaders(headers, { isHttps: true });
  assert.equal(byId(findings, 'hsts').status, 'pass');
  assert.equal(byId(findings, 'csp').status, 'pass');
  assert.equal(byId(findings, 'clickjacking').status, 'pass');
  assert.equal(byId(findings, 'nosniff').status, 'pass');
});

test('a bare site fails the expected header checks', () => {
  const findings = analyzeHeaders({}, { isHttps: true });
  assert.equal(byId(findings, 'hsts').status, 'fail');
  assert.equal(byId(findings, 'csp').status, 'fail');
  assert.equal(byId(findings, 'clickjacking').status, 'fail');
  assert.equal(byId(findings, 'nosniff').status, 'fail');
  assert.equal(byId(findings, 'referrer').status, 'warn');
});

test('permissive CSP is flagged as a warning, not a pass', () => {
  const findings = analyzeHeaders(
    { 'content-security-policy': "default-src 'self' 'unsafe-inline'" },
    { isHttps: true },
  );
  assert.equal(byId(findings, 'csp').status, 'warn');
  assert.equal(byId(findings, 'csp').severity, 'medium');
});

test('cookie flag analysis detects missing Secure/HttpOnly/SameSite', () => {
  const findings = analyzeCookies(['session=abc123; Path=/']);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].status, 'fail');
  assert.match(findings[0].title, /Secure/);
  assert.match(findings[0].title, /HttpOnly/);
  assert.match(findings[0].title, /SameSite/);
});

test('a fully-flagged cookie passes', () => {
  const findings = analyzeCookies(['session=abc; Secure; HttpOnly; SameSite=Strict']);
  assert.equal(findings[0].status, 'pass');
});

test('CORS wildcard with credentials is a high-severity failure', () => {
  const findings = analyzeCors({
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
  });
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].status, 'fail');
});

test('transport analysis flags plain HTTP as high severity', () => {
  const findings = analyzeTransport({ isHttps: false });
  assert.equal(findings[0].id, 'https');
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].status, 'fail');
});

test('transport analysis flags missing HTTP->HTTPS redirect', () => {
  const findings = analyzeTransport({ isHttps: true, httpRedirectsToHttps: false });
  assert.equal(byId(findings, 'https-redirect').status, 'fail');
});

test('scoring: hardened site grades A, bare site grades poorly', () => {
  const hardened = runAllChecks({
    isHttps: true,
    httpRedirectsToHttps: true,
    headers: {
      'strict-transport-security': 'max-age=63072000',
      'content-security-policy': "default-src 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'geolocation=()',
    },
    setCookies: ['s=1; Secure; HttpOnly; SameSite=Lax'],
  });
  const hardenedScore = computeScore(hardened);
  assert.equal(hardenedScore.grade, 'A');

  const bare = runAllChecks({ isHttps: false, headers: {}, setCookies: [] });
  const bareScore = computeScore(bare);
  assert.ok(bareScore.score < 60, `bare site should score low, got ${bareScore.score}`);
});

test('gradeFor boundaries', () => {
  assert.equal(gradeFor(90), 'A');
  assert.equal(gradeFor(89), 'B');
  assert.equal(gradeFor(70), 'C');
  assert.equal(gradeFor(0), 'F');
});

test('findings are sorted with failures before passes', () => {
  const findings = runAllChecks({
    isHttps: true,
    httpRedirectsToHttps: true,
    headers: { 'content-security-policy': "default-src 'self'" },
    setCookies: [],
  });
  const firstPassIndex = findings.findIndex((f) => f.status === 'pass');
  const lastFailIndex = findings.map((f) => f.status).lastIndexOf('fail');
  if (firstPassIndex !== -1 && lastFailIndex !== -1) {
    assert.ok(lastFailIndex < firstPassIndex, 'all failures should come before passes');
  }
});
