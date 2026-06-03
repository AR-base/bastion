// SSRF guard — the security-critical core of the scanner.
//
// A tool that fetches arbitrary user-supplied URLs server-side is a textbook
// SSRF target: without these checks an attacker could point it at internal
// services, container networks, or the cloud metadata endpoint
// (169.254.169.254) to exfiltrate credentials. Every URL — including each
// redirect hop — must pass through here before any fetch is issued.
//
// Strategy (defense in depth):
//   1. Strict URL parsing + scheme/userinfo allowlist.
//   2. Canonicalize obfuscated IP literals (decimal / octal / hex) so they
//      can't slip past a naive dotted-quad check.
//   3. Block private / loopback / link-local / reserved IP ranges (v4 + v6,
//      including IPv4-mapped IPv6).
//   4. Resolve hostnames via DNS-over-HTTPS and re-check every returned IP,
//      so a domain that resolves to 127.0.0.1 is rejected too.
//
// All pure functions are exported so they can be unit-tested in isolation.

const MAX_URL_LENGTH = 2048;
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
]);

class UrlRejected extends Error {
  constructor(reason, code = 'rejected') {
    super(reason);
    this.name = 'UrlRejected';
    this.code = code;
  }
}

// --- IPv4 ----------------------------------------------------------------

// inet_aton-style parser. Accepts dotted forms with 1–4 parts where each part
// may be decimal, octal (leading 0) or hex (0x). Returns a 32-bit unsigned
// integer, or null if the host is not an IPv4 literal in any of these forms.
// This is exactly the parsing attackers abuse, e.g. http://2130706433 == 127.0.0.1.
function parseIpv4ToInt(host) {
  if (typeof host !== 'string' || host.length === 0) return null;
  if (!/^[0-9a-fA-FxX.]+$/.test(host)) return null;

  const parts = host.split('.');
  if (parts.length === 0 || parts.length > 4) return null;

  const nums = [];
  for (const part of parts) {
    if (part === '') return null;
    let value;
    if (/^0[xX][0-9a-fA-F]+$/.test(part)) {
      value = parseInt(part, 16);
    } else if (/^0[0-7]+$/.test(part)) {
      value = parseInt(part, 8);
    } else if (/^0$/.test(part)) {
      value = 0;
    } else if (/^[1-9][0-9]*$/.test(part)) {
      value = parseInt(part, 10);
    } else {
      return null; // not a recognizable numeric part
    }
    if (!Number.isFinite(value) || value < 0) return null;
    nums.push(value);
  }

  // inet_aton: the final part absorbs all remaining low-order bytes.
  const n = nums.length;
  for (let i = 0; i < n - 1; i++) {
    if (nums[i] > 0xff) return null;
  }
  const last = nums[n - 1];
  const maxLast = Math.pow(256, 4 - (n - 1));
  if (last >= maxLast) return null;

  let result = last;
  for (let i = 0; i < n - 1; i++) {
    result += nums[i] * Math.pow(256, 4 - 1 - i);
  }
  return result >>> 0;
}

function intToDottedIpv4(int) {
  return [
    (int >>> 24) & 0xff,
    (int >>> 16) & 0xff,
    (int >>> 8) & 0xff,
    int & 0xff,
  ].join('.');
}

// CIDR ranges that must never be reachable. [networkInt, prefixBits]
const FORBIDDEN_V4 = [
  [0x00000000, 8],   // 0.0.0.0/8        "this network"
  [0x0a000000, 8],   // 10.0.0.0/8       private
  [0x64400000, 10],  // 100.64.0.0/10    carrier-grade NAT
  [0x7f000000, 8],   // 127.0.0.0/8      loopback
  [0xa9fe0000, 16],  // 169.254.0.0/16   link-local (incl. cloud metadata)
  [0xac100000, 12],  // 172.16.0.0/12    private
  [0xc0000000, 24],  // 192.0.0.0/24     IETF protocol assignments
  [0xc0000200, 24],  // 192.0.2.0/24     TEST-NET-1
  [0xc0a80000, 16],  // 192.168.0.0/16   private
  [0xc6120000, 15],  // 198.18.0.0/15    benchmarking
  [0xc6336400, 24],  // 198.51.100.0/24  TEST-NET-2
  [0xcb007100, 24],  // 203.0.113.0/24   TEST-NET-3
  [0xe0000000, 4],   // 224.0.0.0/4      multicast
  [0xf0000000, 4],   // 240.0.0.0/4      reserved
];

function isForbiddenIpv4Int(int) {
  for (const [network, prefix] of FORBIDDEN_V4) {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    if ((int & mask) === (network & mask)) return true;
  }
  return false;
}

// --- IPv6 ----------------------------------------------------------------

// Expand an IPv6 address to its eight 16-bit groups. Handles "::" compression
// and IPv4-mapped tails (::ffff:1.2.3.4). Returns an array of 8 integers or null.
function expandIpv6(addr) {
  if (typeof addr !== 'string') return null;
  let s = addr.trim().toLowerCase();
  if (s.includes('%')) s = s.split('%')[0]; // strip zone id

  // Pull out an embedded IPv4 tail, if present.
  let embeddedV4 = null;
  const lastColon = s.lastIndexOf(':');
  const tail = lastColon >= 0 ? s.slice(lastColon + 1) : s;
  if (tail.includes('.')) {
    const v4int = parseIpv4ToInt(tail);
    if (v4int === null) return null;
    embeddedV4 = v4int;
    s = s.slice(0, lastColon + 1) +
      ((v4int >>> 16) & 0xffff).toString(16) + ':' + (v4int & 0xffff).toString(16);
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;

  const head = halves[0] ? halves[0].split(':') : [];
  const back = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : null;

  let groups;
  if (back === null) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const fill = 8 - head.length - back.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill('0'), ...back];
  }
  if (groups.length !== 8) return null;

  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return { groups: out, embeddedV4 };
}

function isForbiddenIpv6(addr) {
  const parsed = expandIpv6(addr);
  if (!parsed) return false;
  const { groups, embeddedV4 } = parsed;

  // IPv4-mapped (::ffff:0:0/96) or IPv4-compatible — judge by the embedded v4.
  const isMapped = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 &&
    groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff;
  const isCompat = groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0;
  if ((isMapped || isCompat) && embeddedV4 !== null) {
    return isForbiddenIpv4Int(embeddedV4);
  }

  const allZero = groups.every((g) => g === 0);
  if (allZero) return true;                          // ::         unspecified
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return true; // ::1 loopback
  if ((groups[0] & 0xfe00) === 0xfc00) return true;  // fc00::/7   unique local
  if ((groups[0] & 0xffc0) === 0xfe80) return true;  // fe80::/10  link-local
  if ((groups[0] & 0xffc0) === 0xfec0) return true;  // fec0::/10  site-local (deprecated)
  if ((groups[0] & 0xff00) === 0xff00) return true;  // ff00::/8   multicast
  return false;
}

// --- Host classification --------------------------------------------------

// True if the host string is an IP literal in a forbidden range. Domain names
// (which must still be DoH-resolved and re-checked) return false here.
function isForbiddenHost(host) {
  if (typeof host !== 'string' || host === '') return true;
  let h = host.trim().toLowerCase();

  if (BLOCKED_HOSTNAMES.has(h)) return true;
  if (h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;

  // Bracketed IPv6, e.g. [::1]
  if (h.startsWith('[') && h.endsWith(']')) {
    return isForbiddenIpv6(h.slice(1, -1));
  }
  // Bare IPv6 (contains multiple colons)
  if ((h.match(/:/g) || []).length >= 2) {
    return isForbiddenIpv6(h);
  }
  // IPv4 in any obfuscation
  const v4 = parseIpv4ToInt(h);
  if (v4 !== null) return isForbiddenIpv4Int(v4);

  return false; // treat as a domain name; resolve before trusting
}

function isForbiddenIp(ip) {
  if (typeof ip !== 'string') return true;
  const v4 = parseIpv4ToInt(ip);
  if (v4 !== null) return isForbiddenIpv4Int(v4);
  return isForbiddenIpv6(ip);
}

// --- URL validation -------------------------------------------------------

function parseAndValidateUrl(raw) {
  if (typeof raw !== 'string') throw new UrlRejected('URL must be a string', 'type');
  const trimmed = raw.trim();
  if (trimmed.length === 0) throw new UrlRejected('URL is empty', 'empty');
  if (trimmed.length > MAX_URL_LENGTH) throw new UrlRejected('URL is too long', 'too_long');

  let url;
  try {
    url = new URL(trimmed);
  } catch {
    throw new UrlRejected('URL is malformed', 'malformed');
  }

  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    throw new UrlRejected(`Unsupported scheme "${url.protocol}"`, 'scheme');
  }
  if (url.username || url.password) {
    throw new UrlRejected('Credentials in URL are not allowed', 'userinfo');
  }
  if (isForbiddenHost(url.hostname)) {
    throw new UrlRejected('Target resolves to a private or reserved address', 'private_host');
  }
  return url;
}

// --- DNS-over-HTTPS resolution --------------------------------------------

// Resolve A + AAAA records via Cloudflare DoH and confirm none of the answers
// fall in a forbidden range. Fails closed: any resolution error rejects the
// target rather than allowing an unchecked fetch. `fetchImpl` is injectable
// for testing.
async function resolveAndCheck(hostname, fetchImpl = fetch) {
  // An IP literal needs no resolution; it was already screened by isForbiddenHost.
  if (parseIpv4ToInt(hostname) !== null || (hostname.match(/:/g) || []).length >= 2) {
    return { ips: [hostname], resolved: false };
  }

  const types = ['A', 'AAAA'];
  const ips = [];
  for (const type of types) {
    const endpoint = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`;
    let resp;
    try {
      resp = await fetchImpl(endpoint, { headers: { accept: 'application/dns-json' } });
    } catch {
      throw new UrlRejected('DNS resolution failed', 'dns_error');
    }
    if (!resp.ok) throw new UrlRejected('DNS resolution failed', 'dns_error');
    const data = await resp.json();
    for (const answer of data.Answer || []) {
      // type 1 = A, 28 = AAAA; ignore CNAMEs (5) etc.
      if (answer.type === 1 || answer.type === 28) ips.push(answer.data);
    }
  }

  if (ips.length === 0) throw new UrlRejected('Host did not resolve', 'no_records');
  for (const ip of ips) {
    if (isForbiddenIp(ip)) {
      throw new UrlRejected('Target resolves to a private or reserved address', 'private_resolved');
    }
  }
  return { ips, resolved: true };
}

export {
  UrlRejected,
  MAX_URL_LENGTH,
  parseIpv4ToInt,
  intToDottedIpv4,
  isForbiddenIpv4Int,
  expandIpv6,
  isForbiddenIpv6,
  isForbiddenIp,
  isForbiddenHost,
  parseAndValidateUrl,
  resolveAndCheck,
};
