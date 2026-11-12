# Changelog

## [1.3.0] - 2026-11-12

### Added
- **Redesigned web interface:** ambient "security console" look, glass cards, light/dark themes, toggle switches, a `/` shortcut, and reduced-motion support.
- **Live scan console:** real progress streamed from the server over Server-Sent Events (`/api/scan/stream`), with an automatic fallback to the JSON API.
- **Security profile:** per-category scores (radar chart and bars in the UI, bars in the terminal, `categories` in JSON).
- **Compare mode:** two sites side by side in the UI, `--compare A B` on the CLI, and standalone comparison reports (`--html`).
- **Bulk scanning:** `--list sites.txt` with parallel workers and `--csv` output.
- **Regression checks:** `--baseline old.json` shows fixed/regressed checks; `--fail-on-regression` for CI.
- "Copy link" button and `?a=&b=` deep links for comparisons.
- 31 new tests (103 total), covering the SSE stream, bulk, diff and compare (including an XSS regression test for comparison reports).

### Security
- **CSRF protection** for the local web server: cross-site requests (foreign `Origin` or `Sec-Fetch-Site: cross-site`) are refused, so another website can't make a visitor's machine run scans.
- SSRF guard now also blocks NAT64 (`64:ff9b::/96`), IPv4-compatible (`::/96`) and deprecated site-local IPv6 forms that embed internal addresses.
- The `Server` header is exactly `SiteSentry` (no Python version, no trailing space).

### Fixed
- A failing redirect *after* the first hop (dead target, another host's certificate) was reported as "HTTPS unavailable" and forced an F. Now the chain stops at the last good response and the problem is noted.
- Redirects to non-ASCII URLs or URLs with spaces crashed the scan; paths are now percent-encoded.
- With an explicit port (`https://host:8443`), the plain-HTTP check probed the TLS port and vice versa.
- Subdomains (`docs.github.com`) failed SPF, DMARC and CAA although their organisation passes. Records are now taken from the organisational domain, with RFC 7489 DMARC fallback and CAA inheritance.
- DNS `SERVFAIL`/`REFUSED` answers were treated as "record missing" instead of a lookup error.
- `security.txt` redirects (allowed by RFC 9116) are now followed.
- `--baseline` with the wrong JSON shape crashed (exit 1 = "regression"); it now exits 2 with a clear message.
- `--list` exited 0 when sites couldn't be scanned, so a CI gate passed silently; it now exits 2.
- UI: starting a second scan while one was running interleaved both scans; one scan at a time now.
- UI: `$` characters in scan data corrupted the downloaded HTML report.
- UI: IPv6 hosts broke headings, filenames and generated config.
- UI: results touched the screen edges on phones; comparison tables are now compact on small screens.
- Closing the browser mid-scan printed a traceback on Windows (`ConnectionAbortedError`).
- CSV output had blank rows on Windows (doubled CR characters in line endings).
- Saved HTML reports no longer play entrance animations (print and PDF friendly).

## [1.2.0] - 2026-11-12

### Security
- **SSRF hardening for the web server.** Private, loopback, link-local and reserved targets are refused (including IPv4-mapped and 6to4 IPv6), connections are pinned to the vetted IP (defeats DNS rebinding), and every redirect hop is re-checked. Opt out with `--allow-private`.
- Host-header allow-list on loopback servers (DNS rebinding against the UI), per-client rate limiting, a concurrent-scan cap, port check disabled in shared mode, and no Python version in the `Server` header.
- CodeQL (security-extended), ruff with bandit security rules, and mypy run on every push; Dependabot added.

### Fixed
- **False "invalid certificate" (grade F) on Windows** for sites whose root CA isn't cached locally (found while scanning 100 sites, e.g. cnn.com and walmart.com). Mozilla's CA bundle is now used when available, and an unverifiable chain is reported as an "incomplete chain" warning instead of a critical failure.
- TLS client contexts set an explicit TLS 1.2 minimum.

### Added
- **Research:** 100 popular websites scanned, published at `docs/research.html` with reproducible scripts in `research/`.
- Optional `certs` extra (`pip install ".[certs]"`); the Docker image includes it.
- 18 new tests (72 total), including attack-driven SSRF, DNS-rebinding and rate-limit tests.

## [1.1.1] - 2026-11-12

### Added
- Introduction section (what SiteSentry is, who it's for, a "How it works" diagram) in the README and on the project page.
- "Made by Victor Barbuta" credit in the README, project page, web app, HTML reports, CLI and package metadata.
- Author section on the project page and in the README.

## [1.1.0] - 2026-11-12

### Added
- **Email & DNS checks:** SPF (missing, `+all`, `?all`, duplicate records), DMARC policy strength, and CAA records inherited from parent domains.
- **DNS client written from scratch** (`sitesentry/dns.py`): hand-built query packets, UDP with TCP fallback, and compression-pointer parsing. Still zero dependencies.
- **"Fix it" config generator** in the UI and reports: copy-paste configuration for nginx, Apache, Caddy and Express.
- Light/dark theme toggle, recent-scan history, and shareable `?url=` links.
- `--no-dns` and `--host` CLI options.
- Dockerfile (runs as a non-root user).
- Project landing page on GitHub Pages, with live sample reports and screenshots.
- 12 new tests (54 total), covering DNS packet parsing and a fake resolver.

### Changed
- Static HTML reports draw the score ring right away (better for printing and screenshots).
- CI tests Python 3.11–3.13 on Ubuntu and Windows, and runs all jobs even if one fails.

## [1.0.0] - 2026-11-12

### Added
- First release: HTTPS/TLS, security header, cookie, CORS, information disclosure, mixed content, security.txt and opt-in port checks.
- A+ to F scoring, web UI, terminal output, and standalone HTML and JSON reports.
- `--fail-under` for CI pipelines.
