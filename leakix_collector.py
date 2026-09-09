"""
LeakIX collector — ComfyUI only, via its dedicated `ComfyUIPlugin` fingerprint
module (`+plugin:ComfyUIPlugin`), not generic text matching. Verified this
plugin exists and returns exclusively ComfyUIPlugin-sourced results before
building this. NOT used for Ollama/Open WebUI/vLLM — those only match via
LeakIX's generic HttpPlugin there, no better than what Shodan already gives
us, so adding them would just be redundant text-matching.

NOTE on `service.credentials.noauth`: initially assumed this was a real
per-host confirmed-auth check (ComfyUIPlugin actually probes the service,
unlike a generic text match). Verified this is WRONG — pulled 160 real
hosts and every single one showed `noauth: False` with zero variation.
That uniformity across diverse hosts/orgs means the field isn't actually
being tested by this plugin; it's a generic schema field that defaults to
False unless a different plugin type (e.g. a database misconfig scanner)
explicitly sets it. Trusting it would have deflated the risk score for
every LeakIX-sourced ComfyUI host. Falls back to the same documented-
default assumption Shodan's ComfyUI entry uses (ships with no auth by
default) instead — see products.py for that reasoning.

Free tier: 3000 requests/month, 25 pages max per query, 20 results/page.
Very generous compared to Shodan (100 query credits) or Censys (100
credits/week) — a full 10-page pull here costs 10 of 3000, negligible.
"""

import argparse
import os
import time

import requests
from dotenv import load_dotenv

from classify import classify_org
from db import connect, init_db, record_run, replace_product_snapshot, upsert_host
from risk_score import score_and_tier

load_dotenv()

SEARCH_URL = "https://leakix.net/search"
QUERY = "+plugin:ComfyUIPlugin"
PRODUCT = "ComfyUI"
SOURCE = "leakix"


def get_client_key() -> str:
    key = os.environ.get("LEAKIX_API_KEY")
    if not key:
        raise SystemExit("LEAKIX_API_KEY not set (check your .env file)")
    return key


def fetch_page(key: str, page: int) -> list[dict]:
    resp = requests.get(
        SEARCH_URL,
        headers={"api-key": key, "accept": "application/json"},
        params={"q": QUERY, "scope": "service", "page": page},
        timeout=20,
    )
    if resp.status_code == 429:
        wait = int(resp.headers.get("x-limited-for", 5))
        print(f"  rate limited, waiting {wait}s")
        time.sleep(wait)
        return fetch_page(key, page)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else []


def run(max_pages: int, dry_run: bool = False):
    key = get_client_key()

    print(f"[{PRODUCT} via LeakIX] query: {QUERY}")
    all_events = []
    for page in range(max_pages):
        events = fetch_page(key, page)
        if not events:
            break
        all_events.extend(events)
        print(f"  page {page}: {len(events)} results")
        time.sleep(1.1)  # stay under the ~1 req/sec limit

    # Dedupe by (ip, port) in case of pagination overlap
    seen = set()
    deduped = []
    for e in all_events:
        key_pair = (e.get("ip"), e.get("port"))
        if key_pair not in seen:
            seen.add(key_pair)
            deduped.append(e)

    print(f"  total fetched: {len(deduped)} ({len(all_events)} before dedup, "
          f"{max_pages if len(all_events) == max_pages * 20 else page + 1} pages used)")

    if dry_run:
        return

    init_db()
    with connect() as conn:
        replace_product_snapshot(conn, PRODUCT, source=SOURCE)

        for e in deduped:
            ip = e.get("ip")
            try:
                port = int(e.get("port"))
            except (TypeError, ValueError):
                continue

            network = e.get("network") or {}
            geoip = e.get("geoip") or {}
            location = geoip.get("location") or {}
            service = e.get("service") or {}
            software = service.get("software") or {}

            org = network.get("organization_name")
            asn = str(network.get("asn")) if network.get("asn") is not None else None
            country = geoip.get("country_name")
            city = geoip.get("city_name")
            latitude = location.get("lat")
            longitude = location.get("lon")
            version = software.get("version")

            # `noauth` field verified NOT meaningful for this plugin (see
            # module docstring — 100% False across 160 real samples).
            # Fall back to the documented product default, same as Shodan.
            looks_unauth = True

            hosting_category = classify_org(org)
            # No CVE tracking for ComfyUI (same as the Shodan path) — no
            # reliable version-to-CVE mapping built for this product.
            risk_score, risk_tier = score_and_tier(hosting_category, looks_unauth, [])

            upsert_host(
                conn, ip, port, PRODUCT, version, org, asn, country, city,
                latitude, longitude, looks_unauth, hosting_category,
                None, False, 0.0, risk_score, risk_tier, source=SOURCE,
            )

        record_run(conn, product=f"{PRODUCT} (LeakIX)", total_reported=len(deduped),
                   fetched=len(deduped), query_credits_used=page + 1)

    print(f"  stored {len(deduped)} hosts (source=leakix)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pages", type=int, default=10,
                         help="Max pages to fetch (20 results/page, free tier caps at 25)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    run(max_pages=args.pages, dry_run=args.dry_run)
