# Changelog

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
