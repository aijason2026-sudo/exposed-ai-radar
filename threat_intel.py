"""
CISA KEV + FIRST.org EPSS enrichment for CVEs tracked in cve_check.py.
Both are free, no-API-key, authoritative data sources — cached locally
(24h TTL) so we don't hit either service on every collector run.

KEV = confirmed actively exploited in the wild right now (binary, strongest
signal). EPSS = predicted probability (0-1) of exploitation in the next 30
days (continuous, useful for ranking severity among non-KEV CVEs).
"""

import json
import time
from pathlib import Path

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = Path("kev_cache.json")

EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_CACHE = Path("epss_cache.json")

CACHE_MAX_AGE = 24 * 3600  # 1 day


def _load_cache(path: Path):
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > CACHE_MAX_AGE:
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def get_kev_set() -> set[str]:
    """Return the set of CVE IDs CISA confirms are actively exploited."""
    cached = _load_cache(KEV_CACHE)
    if cached is not None:
        return set(cached)
    try:
        resp = requests.get(KEV_URL, timeout=15)
        resp.raise_for_status()
        cve_ids = [v["cveID"] for v in resp.json().get("vulnerabilities", [])]
        KEV_CACHE.write_text(json.dumps(cve_ids))
        return set(cve_ids)
    except (requests.RequestException, ValueError, KeyError) as e:
        print(f"  WARNING: KEV fetch failed ({e})")
        # Fall back to a stale cache rather than nothing, if one exists
        try:
            return set(json.loads(KEV_CACHE.read_text()))
        except (OSError, json.JSONDecodeError):
            return set()


def get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Return {cve_id: epss_probability} for the given CVE IDs (0.0 if unknown)."""
    if not cve_ids:
        return {}
    cached = _load_cache(EPSS_CACHE) or {}
    missing = [c for c in cve_ids if c not in cached]
    if missing:
        try:
            resp = requests.get(EPSS_URL, params={"cve": ",".join(missing)}, timeout=15)
            resp.raise_for_status()
            for item in resp.json().get("data", []):
                cached[item["cve"]] = float(item["epss"])
            EPSS_CACHE.write_text(json.dumps(cached))
        except (requests.RequestException, ValueError, KeyError) as e:
            print(f"  WARNING: EPSS fetch failed ({e})")
    return {c: cached.get(c, 0.0) for c in cve_ids}
