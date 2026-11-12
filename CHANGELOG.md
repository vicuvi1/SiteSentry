# Changelog

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
