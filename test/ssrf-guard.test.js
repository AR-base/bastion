import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseIpv4ToInt,
  intToDottedIpv4,
  isForbiddenIpv4Int,
  isForbiddenIp,
  isForbiddenHost,
  isForbiddenIpv6,
  parseAndValidateUrl,
  resolveAndCheck,
  UrlRejected,
} from '../lib/ssrf-guard.js';

test('parseIpv4ToInt handles dotted, decimal, octal and hex forms', () => {
  assert.equal(intToDottedIpv4(parseIpv4ToInt('127.0.0.1')), '127.0.0.1');
  assert.equal(intToDottedIpv4(parseIpv4ToInt('2130706433')), '127.0.0.1'); // decimal
  assert.equal(intToDottedIpv4(parseIpv4ToInt('0x7f000001')), '127.0.0.1'); // hex
  assert.equal(intToDottedIpv4(parseIpv4ToInt('0177.0.0.1')), '127.0.0.1'); // octal first octet
  assert.equal(parseIpv4ToInt('example.com'), null);
  assert.equal(parseIpv4ToInt('999.1.1.1'), null);
});

test('private and reserved IPv4 ranges are forbidden', () => {
  for (const ip of [
    '127.0.0.1', '10.0.0.5', '10.255.255.255', '172.16.0.1', '172.31.255.255',
    '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '224.0.0.1',
    '198.18.0.1', '192.0.2.5',
  ]) {
    assert.equal(isForbiddenIp(ip), true, `${ip} should be forbidden`);
  }
});

test('public IPv4 addresses are allowed', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1']) {
    assert.equal(isForbiddenIp(ip), false, `${ip} should be allowed`);
  }
});

test('obfuscated IP literals do not bypass the host check', () => {
  // All of these are 127.0.0.1 in disguise — classic SSRF bypass attempts.
  for (const host of ['2130706433', '0x7f000001', '0177.0.0.1', '0x7f.1', '127.1']) {
    assert.equal(isForbiddenHost(host), true, `${host} should be blocked`);
  }
});

test('localhost-style and reserved hostnames are blocked', () => {
  for (const host of ['localhost', 'foo.localhost', 'service.internal', 'db.local']) {
    assert.equal(isForbiddenHost(host), true, `${host} should be blocked`);
  }
  assert.equal(isForbiddenHost('example.com'), false);
});

test('IPv6 loopback, link-local, ULA and mapped addresses are forbidden', () => {
  assert.equal(isForbiddenIpv6('::1'), true);
  assert.equal(isForbiddenIpv6('::'), true);
  assert.equal(isForbiddenIpv6('fe80::1'), true);
  assert.equal(isForbiddenIpv6('fc00::1'), true);
  assert.equal(isForbiddenIpv6('fd12:3456::1'), true);
  assert.equal(isForbiddenIpv6('::ffff:127.0.0.1'), true);  // IPv4-mapped loopback
  assert.equal(isForbiddenIpv6('::ffff:169.254.169.254'), true); // mapped metadata IP
  assert.equal(isForbiddenIpv6('2606:4700:4700::1111'), false); // public (1.1.1.1)
});

test('bracketed IPv6 hosts are screened', () => {
  assert.equal(isForbiddenHost('[::1]'), true);
  assert.equal(isForbiddenHost('[fe80::1]'), true);
  assert.equal(isForbiddenHost('[2606:4700:4700::1111]'), false);
});

test('parseAndValidateUrl rejects bad schemes, userinfo and private hosts', () => {
  assert.throws(() => parseAndValidateUrl('ftp://example.com'), UrlRejected);
  assert.throws(() => parseAndValidateUrl('file:///etc/passwd'), UrlRejected);
  assert.throws(() => parseAndValidateUrl('http://user:pass@example.com'), UrlRejected);
  assert.throws(() => parseAndValidateUrl('http://169.254.169.254/latest/meta-data/'), UrlRejected);
  assert.throws(() => parseAndValidateUrl('not a url'), UrlRejected);
  assert.throws(() => parseAndValidateUrl('http://' + 'a'.repeat(3000)), UrlRejected);
});

test('parseAndValidateUrl accepts well-formed public URLs', () => {
  const u = parseAndValidateUrl('https://example.com/path?q=1');
  assert.equal(u.hostname, 'example.com');
  assert.equal(u.protocol, 'https:');
});

test('resolveAndCheck rejects a domain that resolves to a private IP', async () => {
  // Mock DoH: pretend evil.test resolves to 127.0.0.1.
  const fakeFetch = async () => ({
    ok: true,
    json: async () => ({ Answer: [{ type: 1, data: '127.0.0.1' }] }),
  });
  await assert.rejects(() => resolveAndCheck('evil.test', fakeFetch), UrlRejected);
});

test('resolveAndCheck allows a domain that resolves to a public IP', async () => {
  const fakeFetch = async () => ({
    ok: true,
    json: async () => ({ Answer: [{ type: 1, data: '93.184.216.34' }] }),
  });
  const result = await resolveAndCheck('example.com', fakeFetch);
  assert.equal(result.resolved, true);
  assert.ok(result.ips.includes('93.184.216.34'));
});

test('resolveAndCheck fails closed when DNS errors', async () => {
  const fakeFetch = async () => { throw new Error('network down'); };
  await assert.rejects(() => resolveAndCheck('example.com', fakeFetch), UrlRejected);
});
