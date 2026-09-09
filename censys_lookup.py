"""
Censys host enrichment — single-IP lookups only (Censys's free tier does
NOT support search via API, confirmed: the search endpoint returns 403
"requires an organization ID" for free accounts; only per-host lookups
by IP work, at 1 credit each, 94/95 remaining on a weekly-resetting
free-tier budget as of this writing).

Adds what Shodan's search API doesn't give us: the FULL open-service
inventory for a host (Shodan's search result only returns the one
service that matched our query), plus OS fingerprinting.

CAUTION — read before trusting "extra services" as belonging to the same
box: verified this can be misleading on residential/CGNAT-heavy ISPs
(confirmed on a China Unicom residential IP that also showed LDAP/Active
Directory, a router TR-069 port, and an SSL VPN appliance alongside the
AI service — almost certainly unrelated devices sharing one public IP via
carrier-grade NAT, not one box with all those exposures). Treat the
"other services" list as a lead worth noting, not a confirmed fact about
the same physical device, especially for Residential ISP hosting_category.
"""

import requests

BASE_URL = "https://api.platform.censys.io/v3/global/asset/host/{ip}"


class LookupFailed(Exception):
    """Request itself failed (network/5xx/timeout) — distinct from a
    successful 404 (genuinely no Censys data for this IP)."""


def lookup_host(ip: str, token: str, timeout: int = 20) -> dict | None:
    """Returns a summary dict, or None if Censys has no data for this IP
    (a real negative, not a failure). Raises LookupFailed on request errors
    so callers don't cache a failure as a negative result."""
    try:
        resp = requests.get(
            BASE_URL.format(ip=ip),
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise LookupFailed(f"{ip}: {e}")

    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise LookupFailed(f"{ip}: HTTP {resp.status_code} — {resp.text[:200]}")

    try:
        data = resp.json()
        services = data["result"]["resource"].get("services", [])
    except (ValueError, KeyError) as e:
        raise LookupFailed(f"{ip}: unexpected response shape ({e})")

    parts = []
    os_name = None
    for s in services:
        label = f"{s.get('protocol', '?')}:{s.get('port', '?')}"
        software = s.get("software") or []
        products = [f"{sw.get('vendor', '')}/{sw.get('product', '')}".strip("/")
                    for sw in software if sw.get("product")]
        if products:
            label += f" ({', '.join(products)})"
        parts.append(label)

        if os_name is None:
            for os_entry in s.get("operating_systems") or []:
                if os_entry.get("product"):
                    os_name = f"{os_entry.get('vendor', '')} {os_entry['product']}".strip()
                    break

    return {
        "open_port_count": len(services),
        "services_summary": "; ".join(parts) if parts else None,
        "os": os_name,
    }


def get_credit_balance(token: str) -> int | None:
    try:
        resp = requests.get(
            "https://api.platform.censys.io/v3/accounts/users/credits",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["result"]["balance"]
    except (requests.RequestException, ValueError, KeyError):
        return None
