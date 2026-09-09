"""
Weekly Shodan collector for exposed-ai-radar.

Passive only: reads Shodan's pre-collected banner data for each tracked
product and stores/updates a local snapshot. Never connects to a
discovered host directly.

Usage:
    uv run collector.py [--dry-run]
"""

import argparse
import os
import sys
import time

import shodan
from dotenv import load_dotenv

from classify import classify_org
from cve_check import flag_cves, format_cve_flags
from db import connect, get_abuse_cache, init_db, record_run, replace_product_snapshot, restore_abuse_contact, upsert_host
from products import PRODUCTS
from risk_score import score_and_tier

# NOTE: per-host new/gone diff tracking was tried and abandoned — verified
# empirically that Shodan's page=1 search results have ZERO IP overlap
# between calls made 35 seconds apart, for both a huge-total product
# (Ollama, ~19.5k total) and a small-total one (vLLM, ~447 total). This
# means search result ordering isn't stable across calls on this API tier,
# so "host X disappeared since last run" can't be distinguished from
# "host X just wasn't in this call's arbitrary 100-result sample". The
# reliable trend signal is `total_reported` in snapshot_runs (Shodan's
# actual index count for the query), which doesn't depend on pagination.
# Don't rebuild per-host diffing without first confirming Shodan offers a
# stable sort/cursor for search (facets/count-with-facets are NOT available
# on the dev plan tier — tested and confirmed empty).

load_dotenv()


def get_client() -> shodan.Shodan:
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        sys.exit("SHODAN_API_KEY not set (check your .env file)")
    return shodan.Shodan(key)


def check_credits(api: shodan.Shodan, needed: int) -> None:
    info = api.info()
    remaining = info.get("query_credits", 0)
    print(f"Shodan query credits remaining: {remaining}")
    if remaining < needed:
        sys.exit(
            f"Not enough query credits: need {needed}, have {remaining}. "
            "Reduce the product list or wait for credits to refresh."
        )


def run(dry_run: bool = False) -> None:
    api = get_client()
    total_pages_needed = sum(p.get("pages", 1) for p in PRODUCTS)
    check_credits(api, needed=total_pages_needed)

    if not dry_run:
        init_db()

    with connect() as conn:
        for product in PRODUCTS:
            name = product["name"]
            query = product["query"]
            default_no_auth = product["default_no_auth"]
            pages = product.get("pages", 1)

            print(f"\n[{name}] query: {query}" + (f" ({pages} pages)" if pages > 1 else ""))
            matches = []
            total = 0
            credits_used = 0
            for page in range(1, pages + 1):
                try:
                    results = api.search(query, page=page)
                except shodan.APIError as e:
                    print(f"  ERROR (page {page}): {e}")
                    break
                credits_used += 1
                total = results.get("total", 0)
                page_matches = results.get("matches", [])
                if not page_matches:
                    break
                matches.extend(page_matches)
                if pages > 1:
                    time.sleep(1)

            # Multi-page fetches can occasionally re-return a host — dedupe.
            seen = set()
            deduped = []
            for m in matches:
                key = (m.get("ip_str"), m.get("port"))
                if key not in seen:
                    seen.add(key)
                    deduped.append(m)
            matches = deduped

            print(f"  total reported by Shodan: {total} | fetched: {len(matches)} "
                  f"({credits_used} credit{'s' if credits_used != 1 else ''})")

            if dry_run:
                continue

            abuse_cache = get_abuse_cache(conn, name)
            replace_product_snapshot(conn, name)

            cve_hits = 0
            kev_hits = 0
            for m in matches:
                ip = m.get("ip_str")
                port = m.get("port")
                org = m.get("org")
                asn = m.get("asn")
                location = m.get("location", {}) or {}
                country = location.get("country_name")
                city = location.get("city")
                latitude = location.get("latitude")
                longitude = location.get("longitude")
                version = m.get("version")

                looks_unauth = default_no_auth if default_no_auth is not None else False
                hosting_category = classify_org(org)
                cves = flag_cves(version) if name == "Ollama" else []
                if cves:
                    cve_hits += 1
                    if any(c.get("is_kev") for c in cves):
                        kev_hits += 1
                risk_score, risk_tier = score_and_tier(hosting_category, default_no_auth, cves)
                cve_flags_str = format_cve_flags(cves)
                cve_kev = any(c.get("is_kev") for c in cves)
                cve_epss_max = max((c.get("epss", 0.0) for c in cves), default=0.0)

                upsert_host(
                    conn, ip, port, name, version, org, asn, country, city,
                    latitude, longitude, looks_unauth, hosting_category,
                    cve_flags_str, cve_kev, cve_epss_max, risk_score, risk_tier,
                )
                if (ip, port) in abuse_cache:
                    contact, checked_at = abuse_cache[(ip, port)]
                    restore_abuse_contact(conn, ip, port, name, contact, checked_at)

            if cve_hits:
                print(f"  {cve_hits}/{len(matches)} hosts flagged with known CVEs (version-based), "
                      f"{kev_hits} confirmed in CISA KEV (actively exploited)")

            record_run(
                conn,
                product=name,
                total_reported=total,
                fetched=len(matches),
                query_credits_used=credits_used,
            )
            time.sleep(1)  # be polite to the API


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                         help="Query Shodan and print counts, but don't touch the DB")
    args = parser.parse_args()
    run(dry_run=args.dry_run)
