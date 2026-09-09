"""
GreyNoise Community API enrichment — single-IP lookups only (the Community
API is a free lookup endpoint, not a search/discovery API; see README).

Adds a genuinely different signal from everything else in this project:
whether a host's own IP has independently been observed mass-scanning the
internet (`noise`), or is known-benign common infrastructure (`riot`, e.g.
cloud health-checkers/CDNs — GreyNoise's "Rule It Out" dataset). A
Critical/High-tier exposed-AI host whose IP is *also* GreyNoise-classified
"malicious" is a meaningfully stronger signal than exposure alone — it
suggests the box may be compromised/repurposed, not just misconfigured.

Confirmed empirically (2026-09-09): the endpoint returns HTTP 404 (not 200)
for a genuine "no data" negative — same "real negative vs. request failure"
distinction censys_lookup.py/abuse_lookup.py already make, so don't treat
404 as an error here.
"""

import requests

BASE_URL = "https://api.greynoise.io/v3/community/{ip}"


class LookupFailed(Exception):
    """Request itself failed (network/5xx/timeout/unexpected shape) —
    distinct from a successful 404 (genuinely no GreyNoise data for this
    IP), so callers don't cache a failure as a negative result."""


class RateLimited(LookupFailed):
    """Community API tier is limited to 50 lookups/week (shared with the
    GreyNoise Visualizer) with no quota-remaining header exposed to check
    in advance — confirmed empirically, only a plain 429 on the request
    that actually crosses the line. Callers should stop the whole run on
    this, not just skip the one host, since every subsequent call will
    also fail until the weekly reset."""


def lookup_host(ip: str, api_key: str, timeout: int = 15) -> dict | None:
    """Returns a summary dict, or None if GreyNoise has no data for this IP
    (a real negative, not a failure). Raises RateLimited if the Community
    API's weekly cap has been hit, or LookupFailed on other request errors."""
    try:
        resp = requests.get(
            BASE_URL.format(ip=ip),
            headers={"key": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise LookupFailed(f"{ip}: {e}")

    if resp.status_code == 429:
        raise RateLimited(f"{ip}: Community API rate limit hit (50/week)")
    if resp.status_code == 400:
        raise LookupFailed(f"{ip}: {resp.text[:200]}")

    try:
        data = resp.json()
    except ValueError as e:
        raise LookupFailed(f"{ip}: unexpected response shape ({e})")

    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise LookupFailed(f"{ip}: HTTP {resp.status_code} — {resp.text[:200]}")

    return {
        "noise": bool(data.get("noise", False)),
        "riot": bool(data.get("riot", False)),
        "classification": data.get("classification"),
        "name": data.get("name"),
    }
