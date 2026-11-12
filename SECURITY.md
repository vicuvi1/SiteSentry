# Security Policy

SiteSentry is a cybersecurity tool, so its own security matters. Thank you for helping keep it safe.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.3.x   | ✅ |
| < 1.3   | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub instead:
**[Report a vulnerability](https://github.com/vicuvi1/SiteSentry/security/advisories/new)** (Security tab → "Report a vulnerability").

Please include:
- a description of the issue and its impact,
- steps to reproduce, or a proof of concept,
- the SiteSentry version (`sitesentry --version`) and your OS / Python version.

What to expect:
- an acknowledgement within **7 days**,
- a fix or mitigation plan once the issue is confirmed,
- credit in the release notes if you want it.

## Scope

In scope:
- injection into generated HTML reports or the web UI (for example XSS via data from a scanned site),
- the local web server (`--serve`) exposing more than intended,
- parsing bugs in the HTTP or DNS clients that a malicious server could trigger,
- incorrect results that report an insecure configuration as secure.

Out of scope:
- vulnerabilities in websites you scan with SiteSentry. Report those to the site owner (check their `/.well-known/security.txt`).

## Using SiteSentry responsibly

SiteSentry is **passive**: it only sends the kind of requests a normal browser visit makes. The optional port check (`--ports`) opens TCP connections, so **only use it on systems you own or are authorised to test.**

---

Maintained by Victor Barbuta.
