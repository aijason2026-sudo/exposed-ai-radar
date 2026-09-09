"""SQLite storage for exposed-ai-radar snapshots."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = "radar.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    product TEXT NOT NULL,
    version TEXT,
    org TEXT,
    asn TEXT,
    country TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    looks_unauthenticated INTEGER,
    hosting_category TEXT,
    cve_flags TEXT,
    cve_kev INTEGER,
    cve_epss_max REAL,
    risk_score INTEGER,
    risk_tier TEXT,
    abuse_contact TEXT,
    abuse_checked_at TEXT,
    source TEXT NOT NULL DEFAULT 'shodan',
    censys_open_ports INTEGER,
    censys_services_summary TEXT,
    censys_os TEXT,
    censys_checked_at TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (ip, port, product, source)
);

CREATE TABLE IF NOT EXISTS snapshot_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at TEXT NOT NULL,
    product TEXT NOT NULL,
    total_reported INTEGER NOT NULL,
    fetched INTEGER NOT NULL,
    query_credits_used INTEGER NOT NULL
);
"""


def migrate(conn):
    """Add columns that might be missing from a DB created before this feature existed."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(hosts)")}
    for col, ddl in [
        ("hosting_category", "ALTER TABLE hosts ADD COLUMN hosting_category TEXT"),
        ("cve_flags", "ALTER TABLE hosts ADD COLUMN cve_flags TEXT"),
        ("cve_kev", "ALTER TABLE hosts ADD COLUMN cve_kev INTEGER"),
        ("cve_epss_max", "ALTER TABLE hosts ADD COLUMN cve_epss_max REAL"),
        ("risk_score", "ALTER TABLE hosts ADD COLUMN risk_score INTEGER"),
        ("risk_tier", "ALTER TABLE hosts ADD COLUMN risk_tier TEXT"),
        ("abuse_contact", "ALTER TABLE hosts ADD COLUMN abuse_contact TEXT"),
        ("abuse_checked_at", "ALTER TABLE hosts ADD COLUMN abuse_checked_at TEXT"),
        ("latitude", "ALTER TABLE hosts ADD COLUMN latitude REAL"),
        ("longitude", "ALTER TABLE hosts ADD COLUMN longitude REAL"),
        ("source", "ALTER TABLE hosts ADD COLUMN source TEXT NOT NULL DEFAULT 'shodan'"),
        ("censys_open_ports", "ALTER TABLE hosts ADD COLUMN censys_open_ports INTEGER"),
        ("censys_services_summary", "ALTER TABLE hosts ADD COLUMN censys_services_summary TEXT"),
        ("censys_os", "ALTER TABLE hosts ADD COLUMN censys_os TEXT"),
        ("censys_checked_at", "ALTER TABLE hosts ADD COLUMN censys_checked_at TEXT"),
    ]:
        if col not in existing:
            conn.execute(ddl)


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)
        migrate(conn)


def get_abuse_cache(conn, product: str) -> dict:
    """(ip, port) -> (abuse_contact, abuse_checked_at) for a product, so a
    fresh collector run can restore known abuse contacts for any host that
    happens to reappear, instead of losing that (slow, rate-limited) RDAP
    work every time the snapshot is replaced."""
    rows = conn.execute(
        "SELECT ip, port, abuse_contact, abuse_checked_at FROM hosts "
        "WHERE product = ? AND abuse_checked_at IS NOT NULL",
        (product,),
    ).fetchall()
    return {(ip, port): (contact, checked_at) for ip, port, contact, checked_at in rows}


def replace_product_snapshot(conn, product: str, source: str = "shodan"):
    """Delete existing rows for a (product, source) pair before inserting a
    fresh snapshot — keeps `hosts` meaning 'the current run's results', not
    an ever-growing union across runs. Verified this was happening: repeated
    collector.py runs (without a full DB rebuild) had silently doubled
    Ollama/Open WebUI/ComfyUI row counts because Shodan's page=1 sampling
    isn't stable, so each run's ~100 hosts were mostly NEW distinct hosts
    getting added on top of the old ones rather than replacing them.
    Scoped by source too — a Shodan re-run must not wipe out ZoomEye's rows
    for the same product, and vice versa."""
    conn.execute("DELETE FROM hosts WHERE product = ? AND source = ?", (product, source))


def upsert_host(conn, ip, port, product, version, org, asn, country, city,
                 latitude, longitude, looks_unauthenticated, hosting_category,
                 cve_flags_str, cve_kev, cve_epss_max, risk_score, risk_tier,
                 source="shodan"):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO hosts (ip, port, product, version, org, asn, country, city,
                            latitude, longitude, looks_unauthenticated,
                            hosting_category, cve_flags, cve_kev, cve_epss_max,
                            risk_score, risk_tier, source, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip, port, product, source) DO UPDATE SET
            version=excluded.version,
            org=excluded.org,
            asn=excluded.asn,
            country=excluded.country,
            city=excluded.city,
            latitude=excluded.latitude,
            longitude=excluded.longitude,
            looks_unauthenticated=excluded.looks_unauthenticated,
            hosting_category=excluded.hosting_category,
            cve_flags=excluded.cve_flags,
            cve_kev=excluded.cve_kev,
            cve_epss_max=excluded.cve_epss_max,
            risk_score=excluded.risk_score,
            risk_tier=excluded.risk_tier,
            source=excluded.source,
            last_seen=excluded.last_seen
        """,
        (ip, port, product, version, org, asn, country, city,
         latitude, longitude, int(looks_unauthenticated), hosting_category,
         cve_flags_str, int(cve_kev), cve_epss_max, risk_score, risk_tier, source, now, now),
    )


def restore_abuse_contact(conn, ip, port, product, abuse_contact, abuse_checked_at):
    """Like update_abuse_contact, but preserves the original check timestamp
    — used when a host reappears in a fresh snapshot and we're carrying
    forward already-known data, not re-verifying it right now."""
    conn.execute(
        "UPDATE hosts SET abuse_contact = ?, abuse_checked_at = ? "
        "WHERE ip = ? AND port = ? AND product = ?",
        (abuse_contact, abuse_checked_at, ip, port, product),
    )


def update_abuse_contact(conn, ip, port, product, abuse_contact):
    conn.execute(
        """
        UPDATE hosts SET abuse_contact = ?, abuse_checked_at = ?
        WHERE ip = ? AND port = ? AND product = ?
        """,
        (abuse_contact, datetime.now(timezone.utc).isoformat(), ip, port, product),
    )


def hosts_needing_abuse_check(conn, tiers: list[str], max_age_days: int = 30):
    """Hosts in the given risk tiers that have never been checked, or whose
    check is older than max_age_days (abuse contacts rarely change)."""
    placeholders = ",".join("?" * len(tiers))
    cutoff = datetime.now(timezone.utc).timestamp() - max_age_days * 86400
    rows = conn.execute(
        f"""
        SELECT ip, port, product, abuse_checked_at FROM hosts
        WHERE risk_tier IN ({placeholders})
        """,
        tiers,
    ).fetchall()
    result = []
    for ip, port, product, checked_at in rows:
        if checked_at is None:
            result.append((ip, port, product))
        else:
            checked_ts = datetime.fromisoformat(checked_at).timestamp()
            if checked_ts < cutoff:
                result.append((ip, port, product))
    return result


def record_run(conn, product, total_reported, fetched, query_credits_used):
    conn.execute(
        """
        INSERT INTO snapshot_runs (run_at, product, total_reported, fetched, query_credits_used)
        VALUES (?, ?, ?, ?, ?)
        """,
        (datetime.now(timezone.utc).isoformat(), product, total_reported, fetched, query_credits_used),
    )
