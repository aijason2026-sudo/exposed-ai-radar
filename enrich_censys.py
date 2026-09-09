"""
Standalone Censys host enrichment — full open-service inventory + OS
fingerprint for high-priority hosts. Separate from collector.py: Censys's
free tier only supports single-IP lookups (1 credit each, ~94-100/week),
never search, so this only ever enriches hosts Shodan already found.

Scoped to Critical tier first, then High as budget allows — deliberately
conservative given how small the weekly credit reset is compared to how
many High/Critical hosts we typically have.

Usage:
    uv run enrich_censys.py                    # Critical only, up to 20
    uv run enrich_censys.py --tiers Critical High --limit 50
    uv run enrich_censys.py --force             # re-check even if recent
"""

import argparse
import os
import time

from dotenv import load_dotenv

from censys_lookup import LookupFailed, get_credit_balance, lookup_host
from db import connect, init_db

load_dotenv()


def hosts_needing_censys_check(conn, tiers, max_age_days=30):
    placeholders = ",".join("?" * len(tiers))
    from datetime import datetime, timezone
    cutoff = datetime.now(timezone.utc).timestamp() - max_age_days * 86400
    rows = conn.execute(
        f"""
        SELECT DISTINCT ip, risk_tier FROM hosts
        WHERE risk_tier IN ({placeholders}) AND censys_checked_at IS NULL
        """,
        tiers,
    ).fetchall()
    stale_rows = conn.execute(
        f"""
        SELECT DISTINCT ip, risk_tier, censys_checked_at FROM hosts
        WHERE risk_tier IN ({placeholders}) AND censys_checked_at IS NOT NULL
        """,
        tiers,
    ).fetchall()
    for ip, tier, checked_at in stale_rows:
        if datetime.fromisoformat(checked_at).timestamp() < cutoff:
            rows.append((ip, tier))

    tier_priority = {t: i for i, t in enumerate(tiers)}
    rows.sort(key=lambda r: tier_priority.get(r[1], 99))
    return [ip for ip, _tier in rows]


def update_censys_enrichment(conn, ip, open_port_count, services_summary, os_name):
    from datetime import datetime, timezone
    conn.execute(
        """
        UPDATE hosts SET censys_open_ports = ?, censys_services_summary = ?,
                          censys_os = ?, censys_checked_at = ?
        WHERE ip = ?
        """,
        (open_port_count, services_summary, os_name,
         datetime.now(timezone.utc).isoformat(), ip),
    )


def run(tiers, limit, force, delay):
    token = os.environ.get("CENSYS_API_TOKEN")
    if not token:
        raise SystemExit("CENSYS_API_TOKEN not set (check your .env file)")

    balance = get_credit_balance(token)
    print(f"Censys credit balance: {balance}")
    if balance is not None and balance < 5:
        print("Balance too low to proceed safely — stopping.")
        return

    init_db()
    with connect() as conn:
        max_age = 0 if force else 30
        targets = hosts_needing_censys_check(conn, tiers, max_age_days=max_age)
        safe_limit = min(limit, balance - 2) if balance is not None else limit
        targets = targets[:safe_limit]
        print(f"{len(targets)} host(s) to check (tiers={tiers}, limit={limit}, "
              f"budget-capped to {safe_limit})")

        failed = []
        for i, ip in enumerate(targets, 1):
            try:
                result = lookup_host(ip, token)
            except LookupFailed as e:
                failed.append((ip, e))
                print(f"  [{i}/{len(targets)}] {ip} -> LOOKUP FAILED, will retry next run")
                time.sleep(delay)
                continue

            if result is None:
                update_censys_enrichment(conn, ip, None, None, None)
                print(f"  [{i}/{len(targets)}] {ip} -> no Censys data")
            else:
                update_censys_enrichment(
                    conn, ip, result["open_port_count"],
                    result["services_summary"], result["os"],
                )
                print(f"  [{i}/{len(targets)}] {ip} -> {result['open_port_count']} open "
                      f"service(s){' | OS: ' + result['os'] if result['os'] else ''}")
            time.sleep(delay)

        if failed:
            print(f"\n{len(failed)} lookup(s) failed and will be retried next run:")
            for ip, e in failed:
                print(f"  {ip}: {e}")

        remaining = get_credit_balance(token)
        print(f"\nCensys credit balance after run: {remaining}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tiers", nargs="+", default=["Critical", "High"],
                         help="Risk tiers to check, in priority order (default: Critical High)")
    parser.add_argument("--limit", type=int, default=20,
                         help="Max hosts to check this run (credits are precious — default 20)")
    parser.add_argument("--force", action="store_true",
                         help="Re-check even hosts checked within the last 30 days")
    parser.add_argument("--delay", type=float, default=0.5,
                         help="Seconds between requests (politeness)")
    args = parser.parse_args()
    run(tiers=args.tiers, limit=args.limit, force=args.force, delay=args.delay)
