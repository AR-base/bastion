// Security headers and HTTPS enforcement for every response Bastion serves.
//
// Bastion grades other sites on these exact headers, so its own responses
// must pass every check it runs (see test/self-scan.test.js). The Worker runs
// before the static assets (run_worker_first in wrangler.toml), so these
// headers apply to the page, its assets, the API and error responses alike.

// No 'unsafe-inline' or 'unsafe-eval': all script and style live in
// /app.js and /styles.css. Google Fonts is the only third-party origin.
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  'upgrade-insecure-requests',
].join('; ');

const SECURITY_HEADERS = Object.freeze({
  'content-security-policy': CSP,
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'x-permitted-cross-domain-policies': 'none',
});

// Headers that advertise software or versions are removed.
const STRIP = ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

// Returns a 301 to the HTTPS URL for plain-HTTP requests, or null.
// Local development (wrangler dev on http://localhost) is left alone.
function httpsRedirect(request) {
  const url = new URL(request.url);
  if (url.protocol !== 'http:' || LOCAL_HOSTS.has(url.hostname)) return null;
  url.protocol = 'https:';
  return new Response(null, {
    status: 301,
    headers: { location: url.toString(), ...SECURITY_HEADERS },
  });
}

// Copies the response with the security headers set (overriding any weaker
// value) and version-revealing headers removed.
function withSecurityHeaders(response) {
  const out = new Response(response.body, response);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) out.headers.set(name, value);
  for (const name of STRIP) out.headers.delete(name);
  return out;
}

export { CSP, SECURITY_HEADERS, httpsRedirect, withSecurityHeaders };
