"""
Standalone GreyNoise enrichment — flags whether a High/Critical-risk
host's own IP has independently been observed mass-scanning the internet,
or is known-benign common infrastructure. Separate from collector.py, same
reason as enrich_censys.py: this only ever enriches hosts Shodan/LeakIX
already found, and the Community API's budget is tiny (50 lookups/week,
*shared with the GreyNoise Visualizer web UI* if you ever browse there
manually — no quota-remaining check is possible in advance, so the default
--limit here is deliberately conservative to leave headroom).

Usage:
    uv run enrich_greynoise.py                    # Critical only, up to 15
    uv run enrich_greynoise.py --tiers Critical High --limit 15
    uv run enrich_greynoise.py --force              # re-check even if recent
"""

import argparse
import os
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

from db import connect, init_db
from greynoise_lookup import LookupFailed, RateLimited, lookup_host

load_dotenv()


def hosts_needing_greynoise_check(conn, tiers, max_age_days=30):
    placeholders = ",".join("?" * len(tiers))
    cutoff = datetime.now(timezone.utc).timestamp() - max_age_days * 86400
    rows = conn.execute(
        f"""
        SELECT DISTINCT ip, risk_tier FROM hosts
        WHERE risk_tier IN ({placeholders}) AND greynoise_checked_at IS NULL
        """,
        tiers,
    ).fetchall()
    stale_rows = conn.execute(
        f"""
        SELECT DISTINCT ip, risk_tier, greynoise_checked_at FROM hosts
        WHERE risk_tier IN ({placeholders}) AND greynoise_checked_at IS NOT NULL
        """,
        tiers,
    ).fetchall()
    for ip, tier, checked_at in stale_rows:
        if datetime.fromisoformat(checked_at).timestamp() < cutoff:
            rows.append((ip, tier))

    tier_priority = {t: i for i, t in enumerate(tiers)}
    rows.sort(key=lambda r: tier_priority.get(r[1], 99))
    return [ip for ip, _tier in rows]


def update_greynoise_enrichment(conn, ip, noise, riot, classification, name):
    conn.execute(
        """
        UPDATE hosts SET greynoise_noise = ?, greynoise_riot = ?,
                          greynoise_classification = ?, greynoise_name = ?,
                          greynoise_checked_at = ?
        WHERE ip = ?
        """,
        (int(noise) if noise is not None else None,
         int(riot) if riot is not None else None,
         classification, name, datetime.now(timezone.utc).isoformat(), ip),
    )


def run(tiers, limit, force, delay):
    api_key = os.environ.get("GREYNOISE_API_KEY")
    if not api_key:
        raise SystemExit("GREYNOISE_API_KEY not set (check your .env file)")

    init_db()
    with connect() as conn:
        max_age = 0 if force else 30
        targets = hosts_needing_greynoise_check(conn, tiers, max_age_days=max_age)
        targets = targets[:limit]
        print(f"{len(targets)} host(s) to check (tiers={tiers}, limit={limit} — "
              f"Community API budget is only 50/week, shared with the "
              f"Visualizer web UI)")

        malicious_hits = 0
        noise_hits = 0
        failed = []
        for i, ip in enumerate(targets, 1):
            try:
                result = lookup_host(ip, api_key)
            except RateLimited as e:
                print(f"  [{i}/{len(targets)}] {ip} -> RATE LIMITED, stopping run early: {e}")
                break
            except LookupFailed as e:
                failed.append((ip, e))
                print(f"  [{i}/{len(targets)}] {ip} -> LOOKUP FAILED, will retry next run")
                time.sleep(delay)
                continue

            if result is None:
                update_greynoise_enrichment(conn, ip, False, False, None, None)
                print(f"  [{i}/{len(targets)}] {ip} -> not observed scanning")
            else:
                update_greynoise_enrichment(
                    conn, ip, result["noise"], result["riot"],
                    result["classification"], result["name"],
                )
                if result["classification"] == "malicious":
                    malicious_hits += 1
                if result["noise"]:
                    noise_hits += 1
                print(f"  [{i}/{len(targets)}] {ip} -> noise={result['noise']} "
                      f"riot={result['riot']} classification={result['classification']} "
                      f"({result['name']})")
            time.sleep(delay)

        if malicious_hits:
            print(f"\n{malicious_hits} host(s) GreyNoise-classified 'malicious' — "
                  f"their IP is independently known-bad, not just exposed")
        if noise_hits:
            print(f"{noise_hits} host(s) observed mass-scanning the internet themselves")
        if failed:
            print(f"\n{len(failed)} lookup(s) failed and will be retried next run:")
            for ip, e in failed:
                print(f"  {ip}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tiers", nargs="+", default=["Critical"],
                         help="Risk tiers to check, in priority order (default: Critical)")
    parser.add_argument("--limit", type=int, default=15,
                         help="Max hosts to check this run (50/week total budget — default 15)")
    parser.add_argument("--force", action="store_true",
                         help="Re-check even hosts checked within the last 30 days")
    parser.add_argument("--delay", type=float, default=1.0,
                         help="Seconds between requests (politeness)")
    args = parser.parse_args()
    run(tiers=args.tiers, limit=args.limit, force=args.force, delay=args.delay)
