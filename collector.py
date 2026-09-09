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


def fetch_pages(api: shodan.Shodan, query: str, page_range: range) -> tuple[list[dict], int, int]:
    """Fetch a range of Shodan search-result pages for a query. Returns
    (deduped matches, Shodan's reported total, credits actually spent)."""
    matches = []
    total = 0
    credits_used = 0
    for page in page_range:
        try:
            results = api.search(query, page=page)
        except shodan.APIError as e:
            print(f"  ERROR (page {page}): {e}")
            break
        credits_used += 1
        total = results.get("total", 0)
        page_matches = results.get("matches", [])
        if not page_matches:
            print(f"  page {page}: no more results")
            break
        matches.extend(page_matches)
        time.sleep(1)

    # Multi-page fetches can occasionally re-return a host — dedupe.
    seen = set()
    deduped = []
    for m in matches:
        key = (m.get("ip_str"), m.get("port"))
        if key not in seen:
            seen.add(key)
            deduped.append(m)
    return deduped, total, credits_used


def process_and_upsert(conn, matches: list[dict], name: str, default_no_auth,
                        abuse_cache: dict) -> tuple[int, int]:
    """Score, classify, and upsert a batch of Shodan matches for one product.
    Upsert is idempotent on (ip, port, product, source), so calling this
    against an already-populated product is safe — it adds/refreshes rows,
    it never wipes the existing snapshot (that's replace_product_snapshot's
    job, called separately by the caller when a full replace is wanted).
    `abuse_cache` must be captured by the caller *before* any
    replace_product_snapshot call, since that deletes the rows it reads from."""
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

    return cve_hits, kev_hits


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
            matches, total, credits_used = fetch_pages(api, query, range(1, pages + 1))

            print(f"  total reported by Shodan: {total} | fetched: {len(matches)} "
                  f"({credits_used} credit{'s' if credits_used != 1 else ''})")

            if dry_run:
                continue

            abuse_cache = get_abuse_cache(conn, name)
            replace_product_snapshot(conn, name)
            cve_hits, kev_hits = process_and_upsert(conn, matches, name, default_no_auth, abuse_cache)

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


def run_supplement(product_names: list[str] | None, extra_pages: int) -> None:
    """Fetch pages beyond each product's normal baseline and merge them into
    the existing snapshot via upsert — never replace_product_snapshot, so the
    baseline `run()` already stored is preserved and just gets added to.

    This exists because Shodan's per-page query-credit cost makes full
    population coverage prohibitively expensive for the big-total products
    (see README) — e.g. ComfyUI's ~191k total would need ~1,916 credits for
    one complete pull, versus the dev tier's 100/month. Rather than let
    unused monthly credits go to waste, run this by hand whenever you have
    spare credits (check with `uv run python -c "...api.info()..."` or just
    watch for the 'Not enough query credits' exit) to push coverage further
    without touching the recurring weekly job's fixed page counts — bumping
    those directly risks the automated run failing outright mid-cycle if the
    account is short, since check_credits() hard-exits rather than partially
    running.

    IMPORTANT: Shodan's search pagination is cursor-based server-side and
    must be walked sequentially from page 1 — requesting e.g. page 3 cold
    fails with "Search cursor timed out. Restart the search query from page
    1." (confirmed empirically). So a supplemental fetch to depth N still
    costs N credits total (re-walking pages already covered by the
    baseline), not just the "extra" pages beyond it — re-fetching page 1 is
    wasted work but unavoidable. Re-upserting already-known page-1 hosts is
    harmless (idempotent on ip/port/product/source).

    Safe to re-run any time: upsert is idempotent on (ip, port, product,
    source), so a host fetched again just refreshes in place.
    """
    api = get_client()
    targets = [p for p in PRODUCTS if not product_names or p["name"] in product_names]
    if not targets:
        sys.exit(f"No matching product(s) in {product_names!r} — check spelling against products.py")

    total_pages = [product.get("pages", 1) + extra_pages for product in targets]
    check_credits(api, needed=sum(total_pages))
    init_db()

    with connect() as conn:
        for product, end_page in zip(targets, total_pages):
            name = product["name"]
            query = product["query"]
            default_no_auth = product["default_no_auth"]
            base_pages = product.get("pages", 1)

            print(f"\n[{name}] supplemental fetch: walking pages 1-{end_page} "
                  f"({extra_pages} beyond the existing {base_pages}-page baseline; "
                  f"Shodan's cursor requires starting from page 1)")
            matches, total, credits_used = fetch_pages(api, query, range(1, end_page + 1))

            abuse_cache = get_abuse_cache(conn, name)
            cve_hits, kev_hits = process_and_upsert(conn, matches, name, default_no_auth, abuse_cache)
            current_count = conn.execute(
                "SELECT COUNT(*) FROM hosts WHERE product = ? AND source = 'shodan'", (name,)
            ).fetchone()[0]

            print(f"  total reported by Shodan: {total} | new hosts this fetch: {len(matches)} "
                  f"({credits_used} credit{'s' if credits_used != 1 else ''}) | "
                  f"snapshot now holds: {current_count}")
            if cve_hits:
                print(f"  {cve_hits}/{len(matches)} hosts flagged with known CVEs (version-based), "
                      f"{kev_hits} confirmed in CISA KEV (actively exploited)")

            record_run(
                conn,
                product=name,
                total_reported=total,
                fetched=current_count,
                query_credits_used=credits_used,
            )
            time.sleep(1)  # be polite to the API


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                         help="Query Shodan and print counts, but don't touch the DB")
    parser.add_argument("--supplement", action="store_true",
                         help="Fetch extra pages beyond each product's baseline and merge them "
                              "into the existing snapshot, instead of the normal replace-and-refetch")
    parser.add_argument("--extra-pages", type=int, default=5,
                         help="Extra pages to fetch per product in --supplement mode (default: 5)")
    parser.add_argument("--only", type=str, default=None,
                         help="Comma-separated product name(s) to target in --supplement mode "
                              "(e.g. 'Ollama,Open WebUI'). Default: all products.")
    args = parser.parse_args()

    if args.supplement:
        only = [p.strip() for p in args.only.split(",")] if args.only else None
        run_supplement(only, args.extra_pages)
    else:
        run(dry_run=args.dry_run)
