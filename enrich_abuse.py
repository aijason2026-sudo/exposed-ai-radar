"""
Standalone abuse-contact enrichment for High/Critical risk-tier hosts.

Separate from collector.py deliberately: RDAP lookups are per-host and
slow (one HTTP request each, rate-limited by politeness delay), whereas
the Shodan collection is per-product. Scoped to High/Critical tiers only —
that's where responsible disclosure actually matters, and it keeps this
fast enough to run standalone.

Usage:
    uv run enrich_abuse.py                  # High + Critical, skip recently-checked
    uv run enrich_abuse.py --tiers Critical  # Critical only
    uv run enrich_abuse.py --force           # re-check even if recently checked
"""

import argparse

import time

from abuse_lookup import LookupFailed, lookup_abuse_contact
from db import connect, hosts_needing_abuse_check, init_db, update_abuse_contact


def run(tiers: list[str], force: bool, delay: float) -> None:
    init_db()
    with connect() as conn:
        max_age = 0 if force else 30
        targets = hosts_needing_abuse_check(conn, tiers, max_age_days=max_age)
        print(f"{len(targets)} host(s) to check (tiers={tiers}, force={force})")

        failed = []
        for i, (ip, port, product) in enumerate(targets, 1):
            try:
                contact = lookup_abuse_contact(ip)
            except LookupFailed as e:
                # Don't cache a lookup failure as "no contact found" — that
                # would be a false negative. Leave abuse_checked_at untouched
                # so it's retried next run.
                failed.append((ip, e))
                print(f"  [{i}/{len(targets)}] {ip}:{port} ({product}) -> LOOKUP FAILED, will retry next run")
                time.sleep(delay)
                continue

            update_abuse_contact(conn, ip, port, product, contact)
            status = contact if contact else "no abuse contact found"
            print(f"  [{i}/{len(targets)}] {ip}:{port} ({product}) -> {status}")
            if i < len(targets):
                time.sleep(delay)

        if failed:
            print(f"\n{len(failed)} lookup(s) failed (network/rate-limit) and will be retried next run:")
            for ip, e in failed:
                print(f"  {ip}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tiers", nargs="+", default=["High", "Critical"],
                         help="Risk tiers to check (default: High Critical)")
    parser.add_argument("--force", action="store_true",
                         help="Re-check even hosts checked within the last 30 days")
    parser.add_argument("--delay", type=float, default=0.5,
                         help="Seconds between RDAP requests (politeness)")
    args = parser.parse_args()
    run(tiers=args.tiers, force=args.force, delay=args.delay)
