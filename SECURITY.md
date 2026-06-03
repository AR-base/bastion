# Security Policy

Bastion is a security tool, so we hold its own code to the same standard it measures others by.

## Reporting a vulnerability

If you discover a security issue in Bastion, please report it privately rather than opening a public issue.

- Open a [private security advisory](https://github.com/AR-base/bastion/security/advisories/new) on GitHub, or
- Contact the maintainer directly.

Please include steps to reproduce, the impact, and any suggested remediation. We aim to acknowledge reports within a few days.

## Scope and intended use

Bastion performs **passive** analysis only. It inspects the HTTP responses, headers, cookies, and transport configuration that a target server returns to any visitor. It does **not** attack, fuzz, brute-force, exploit, or attempt to authenticate to a target.

Only scan websites you own or are explicitly authorized to test. Unauthorized active scanning of third-party systems may be illegal in your jurisdiction; passive inspection of public responses is lower risk but you remain responsible for how you use this tool.

## Built-in protections

- **SSRF defense.** All target URLs — including every redirect hop — are validated against private, loopback, link-local, and reserved IP ranges (IPv4, IPv6, and IPv4-mapped IPv6), including obfuscated decimal/octal/hex literals. Hostnames are resolved via DNS-over-HTTPS and re-checked; resolution failures fail closed.
- **No secrets in source.** API keys are provided at runtime via Cloudflare Worker secrets, never committed. CI fails the build if a key pattern is found in the repository.
- **Output encoding.** All scan output is HTML-escaped before rendering, so a hostile response header cannot inject script into the report.

## Known limitations

TOCTOU DNS rebinding (a record that changes between the resolution check and the fetch) is not fully eliminated. For higher assurance in production, add a Cloudflare WAF rate-limit rule and consider pinning resolved IPs.
