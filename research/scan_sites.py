"""Scan a list of popular websites with SiteSentry and save the raw results.

Usage:  python research/scan_sites.py [--workers 8] [--out research/results.json]

Only passive checks are used (no port scan): the same requests a browser visit
makes, plus TLS handshakes and public DNS lookups.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sitesentry import __version__  # noqa: E402
from sitesentry.scanner import ScanError, scan  # noqa: E402

# 100 widely used websites across search, social, shopping, news, tech, finance,
# government and education (a hand-picked popular-sites list, not a strict ranking).
SITES = [
    "google.com", "youtube.com", "facebook.com", "instagram.com", "x.com", "wikipedia.org", "amazon.com",
    "reddit.com", "linkedin.com", "netflix.com", "microsoft.com", "apple.com", "yahoo.com", "bing.com",
    "whatsapp.com", "tiktok.com", "openai.com", "github.com", "stackoverflow.com", "zoom.us", "office.com",
    "twitch.tv", "pinterest.com", "ebay.com", "paypal.com", "adobe.com", "dropbox.com", "spotify.com",
    "cloudflare.com", "wordpress.com", "tumblr.com", "quora.com", "medium.com", "imdb.com", "cnn.com",
    "bbc.com", "nytimes.com", "theguardian.com", "washingtonpost.com", "forbes.com", "bloomberg.com",
    "reuters.com", "espn.com", "weather.com", "booking.com", "airbnb.com", "tripadvisor.com", "expedia.com",
    "uber.com", "walmart.com", "target.com", "bestbuy.com", "etsy.com", "aliexpress.com", "alibaba.com",
    "baidu.com", "yandex.ru", "vk.com", "naver.com", "samsung.com", "sony.com", "nvidia.com", "intel.com",
    "oracle.com", "ibm.com", "salesforce.com", "shopify.com", "slack.com", "notion.so", "atlassian.com",
    "gitlab.com", "docker.com", "mozilla.org", "python.org", "npmjs.com", "duckduckgo.com", "proton.me",
    "telegram.org", "discord.com", "signal.org", "steampowered.com", "epicgames.com", "roblox.com",
    "nike.com", "adidas.com", "mcdonalds.com", "coca-cola.com", "nasa.gov", "whitehouse.gov", "europa.eu",
    "un.org", "who.int", "harvard.edu", "mit.edu", "stanford.edu", "ox.ac.uk", "coursera.org",
    "khanacademy.org", "duolingo.com", "canva.com",
]
KEEP_EVIDENCE = {"tls.version", "dns.dmarc", "dns.spf", "disclosure.server"}


def scan_one(site: str, timeout: float) -> dict:
    try:
        r = scan(site, timeout=timeout, check_ports=False)
    except (ScanError, ValueError) as exc:
        return {"site": site, "error": str(exc)}
    return {
        "site": site,
        "final_url": r.final_url,
        "grade": r.grade,
        "score": r.score,
        "checks": {
            f.check_id: {"status": f.status.value, **({"evidence": f.evidence[:160]} if f.check_id in KEEP_EVIDENCE else {})}
            for f in r.findings
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--out", default=str(Path(__file__).with_name("results.json")))
    args = ap.parse_args()

    started = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_one, s, args.timeout): s for s in SITES}
        for i, fut in enumerate(as_completed(futures), 1):
            res = fut.result()
            results.append(res)
            print(f"[{i:3}/{len(SITES)}] {res['site']:<20} {res.get('grade', 'ERR'):>3}  {res.get('score', res.get('error', ''))}",
                  flush=True)

    results.sort(key=lambda r: SITES.index(r["site"]))
    payload = {
        "tool": f"SiteSentry {__version__}",
        "scanned_at": datetime.now(UTC).strftime("%Y-%m-%d"),
        "duration_seconds": round(time.time() - started, 1),
        "sites": results,
    }
    Path(args.out).write_text(json.dumps(payload, indent=1), encoding="utf-8")
    ok = sum(1 for r in results if "grade" in r)
    print(f"\n{ok}/{len(results)} scanned successfully in {payload['duration_seconds']}s -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
