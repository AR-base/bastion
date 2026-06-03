// Analysis engine — pure functions that turn an HTTP response's observable
// surface (headers, cookies, redirect behavior) into a list of findings.
//
// Every check is passive: it only inspects what the server voluntarily returns
// to any visitor. Nothing here probes, fuzzes, or attacks the target.
//
// A finding is:
//   { id, title, severity: 'high'|'medium'|'low'|'info',
//     status: 'pass'|'fail'|'warn', detail, fix }

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

function header(headers, name) {
  return headers[name.toLowerCase()];
}

// --- Security response headers -------------------------------------------

function analyzeHeaders(headers, { isHttps } = {}) {
  const findings = [];

  // HSTS — only meaningful over HTTPS.
  const hsts = header(headers, 'strict-transport-security');
  if (isHttps) {
    if (!hsts) {
      findings.push({
        id: 'hsts',
        title: 'No HSTS header',
        severity: 'high',
        status: 'fail',
        detail: 'Strict-Transport-Security is missing, so browsers may still attempt insecure HTTP connections that can be intercepted.',
        fix: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
      });
    } else {
      const maxAgeMatch = /max-age=(\d+)/i.exec(hsts);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 15552000) {
        findings.push({
          id: 'hsts',
          title: 'HSTS max-age is short',
          severity: 'low',
          status: 'warn',
          detail: `max-age is ${maxAge}s; under six months weakens the protection.`,
          fix: 'Raise max-age to at least 31536000 (one year).',
        });
      } else {
        findings.push({ id: 'hsts', title: 'HSTS enabled', severity: 'high', status: 'pass', detail: 'Browsers are forced onto HTTPS.', fix: '' });
      }
    }
  }

  // Content-Security-Policy
  const csp = header(headers, 'content-security-policy');
  if (!csp) {
    findings.push({
      id: 'csp',
      title: 'No Content-Security-Policy',
      severity: 'high',
      status: 'fail',
      detail: 'Without a CSP the browser will execute any injected script, making cross-site scripting (XSS) far more damaging.',
      fix: "Define a policy, starting strict: Content-Security-Policy: default-src 'self'",
    });
  } else {
    const weak = /unsafe-inline|unsafe-eval/i.test(csp);
    findings.push({
      id: 'csp',
      title: weak ? 'CSP present but permissive' : 'Content-Security-Policy set',
      severity: weak ? 'medium' : 'high',
      status: weak ? 'warn' : 'pass',
      detail: weak ? "Policy allows 'unsafe-inline' or 'unsafe-eval', which undercuts XSS protection." : 'A content security policy is in place.',
      fix: weak ? "Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes for scripts." : '',
    });
  }

  // Clickjacking — X-Frame-Options or CSP frame-ancestors
  const xfo = header(headers, 'x-frame-options');
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !frameAncestors) {
    findings.push({
      id: 'clickjacking',
      title: 'No clickjacking protection',
      severity: 'medium',
      status: 'fail',
      detail: 'The page can be embedded in a hostile iframe and used for clickjacking.',
      fix: "Add: X-Frame-Options: DENY  (or CSP frame-ancestors 'none')",
    });
  } else {
    findings.push({ id: 'clickjacking', title: 'Framing controlled', severity: 'medium', status: 'pass', detail: 'Embedding in foreign frames is restricted.', fix: '' });
  }

  // MIME sniffing
  const xcto = header(headers, 'x-content-type-options');
  if (!xcto || !/nosniff/i.test(xcto)) {
    findings.push({
      id: 'nosniff',
      title: 'MIME sniffing not disabled',
      severity: 'medium',
      status: 'fail',
      detail: 'Browsers may reinterpret file types, which can turn an uploaded file into executable script.',
      fix: 'Add: X-Content-Type-Options: nosniff',
    });
  } else {
    findings.push({ id: 'nosniff', title: 'MIME sniffing disabled', severity: 'medium', status: 'pass', detail: '', fix: '' });
  }

  // Referrer-Policy
  if (!header(headers, 'referrer-policy')) {
    findings.push({
      id: 'referrer',
      title: 'No Referrer-Policy',
      severity: 'low',
      status: 'warn',
      detail: 'Full URLs may leak to third-party sites via the Referer header.',
      fix: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
    });
  } else {
    findings.push({ id: 'referrer', title: 'Referrer-Policy set', severity: 'low', status: 'pass', detail: '', fix: '' });
  }

  // Permissions-Policy
  if (!header(headers, 'permissions-policy')) {
    findings.push({
      id: 'permissions',
      title: 'No Permissions-Policy',
      severity: 'low',
      status: 'warn',
      detail: 'Powerful browser features (camera, geolocation, microphone) are not explicitly restricted.',
      fix: 'Add a Permissions-Policy disabling features you do not use, e.g. geolocation=(), camera=()',
    });
  } else {
    findings.push({ id: 'permissions', title: 'Permissions-Policy set', severity: 'low', status: 'pass', detail: '', fix: '' });
  }

  return findings;
}

// --- Information disclosure ----------------------------------------------

function analyzeDisclosure(headers) {
  const findings = [];
  const versioned = [];
  for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    const value = header(headers, name);
    if (value && /\d/.test(value)) versioned.push(`${name}: ${value}`);
  }
  if (versioned.length) {
    findings.push({
      id: 'version-disclosure',
      title: 'Software versions exposed',
      severity: 'low',
      status: 'warn',
      detail: `Response advertises specific software versions (${versioned.join('; ')}), helping attackers match known exploits.`,
      fix: 'Strip or genericize Server / X-Powered-By headers at your web server or CDN.',
    });
  } else {
    findings.push({ id: 'version-disclosure', title: 'No obvious version disclosure', severity: 'low', status: 'pass', detail: '', fix: '' });
  }
  return findings;
}

// --- Cookies --------------------------------------------------------------

function analyzeCookies(setCookieList = []) {
  const findings = [];
  if (!Array.isArray(setCookieList) || setCookieList.length === 0) {
    return findings; // no cookies set on this response — nothing to flag
  }
  for (const raw of setCookieList) {
    const name = (raw.split('=')[0] || 'cookie').trim();
    const lower = raw.toLowerCase();
    const issues = [];
    if (!/;\s*secure/.test(lower) && !lower.includes('secure')) issues.push('Secure');
    if (!lower.includes('httponly')) issues.push('HttpOnly');
    if (!lower.includes('samesite')) issues.push('SameSite');
    if (issues.length) {
      findings.push({
        id: `cookie-${name}`,
        title: `Cookie "${name}" missing ${issues.join(', ')}`,
        severity: issues.includes('HttpOnly') ? 'medium' : 'low',
        status: 'fail',
        detail: `Missing flags weaken cookie protection: ${issues.join(', ')}.`,
        fix: `Set the cookie with: ${issues.join('; ')} (and a SameSite value such as Lax or Strict).`,
      });
    } else {
      findings.push({ id: `cookie-${name}`, title: `Cookie "${name}" hardened`, severity: 'low', status: 'pass', detail: '', fix: '' });
    }
  }
  return findings;
}

// --- CORS -----------------------------------------------------------------

function analyzeCors(headers) {
  const findings = [];
  const acao = header(headers, 'access-control-allow-origin');
  const acac = header(headers, 'access-control-allow-credentials');
  if (acao === '*' && acac && /true/i.test(acac)) {
    findings.push({
      id: 'cors',
      title: 'Unsafe CORS configuration',
      severity: 'high',
      status: 'fail',
      detail: 'Wildcard origin combined with credentials lets any site read authenticated responses.',
      fix: 'Reflect a specific allowlisted origin instead of "*" when credentials are allowed.',
    });
  } else if (acao === '*') {
    findings.push({
      id: 'cors',
      title: 'Wildcard CORS origin',
      severity: 'low',
      status: 'warn',
      detail: 'Any origin can read non-credentialed responses. Acceptable for public APIs, risky otherwise.',
      fix: 'Restrict Access-Control-Allow-Origin to known origins if responses are not meant to be public.',
    });
  }
  return findings;
}

// --- TLS / transport ------------------------------------------------------

function analyzeTransport({ isHttps, httpRedirectsToHttps }) {
  const findings = [];
  if (!isHttps) {
    findings.push({
      id: 'https',
      title: 'Site not served over HTTPS',
      severity: 'high',
      status: 'fail',
      detail: 'Traffic is unencrypted and can be read or modified in transit.',
      fix: 'Obtain a TLS certificate (free via Cloudflare or Let’s Encrypt) and serve the site over HTTPS.',
    });
    return findings;
  }
  findings.push({ id: 'https', title: 'HTTPS available', severity: 'high', status: 'pass', detail: 'The site responds over an encrypted connection.', fix: '' });

  if (httpRedirectsToHttps === false) {
    findings.push({
      id: 'https-redirect',
      title: 'HTTP not redirected to HTTPS',
      severity: 'medium',
      status: 'fail',
      detail: 'Visitors using http:// are not automatically upgraded, exposing them to interception.',
      fix: 'Configure a 301 redirect from all HTTP traffic to the HTTPS equivalent.',
    });
  } else if (httpRedirectsToHttps === true) {
    findings.push({ id: 'https-redirect', title: 'HTTP redirects to HTTPS', severity: 'medium', status: 'pass', detail: '', fix: '' });
  }
  return findings;
}

// --- Orchestration --------------------------------------------------------

function runAllChecks(input) {
  const { headers = {}, setCookies = [], isHttps, httpRedirectsToHttps } = input;
  const findings = [
    ...analyzeTransport({ isHttps, httpRedirectsToHttps }),
    ...analyzeHeaders(headers, { isHttps }),
    ...analyzeDisclosure(headers),
    ...analyzeCors(headers),
    ...analyzeCookies(setCookies),
  ];
  findings.sort((a, b) => {
    const statusRank = (f) => (f.status === 'pass' ? 1 : 0);
    if (statusRank(a) !== statusRank(b)) return statusRank(a) - statusRank(b);
    return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
  });
  return findings;
}

export {
  SEVERITY_ORDER,
  analyzeHeaders,
  analyzeDisclosure,
  analyzeCookies,
  analyzeCors,
  analyzeTransport,
  runAllChecks,
};
