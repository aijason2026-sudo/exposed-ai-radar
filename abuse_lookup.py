"""
RDAP-based abuse-contact lookup — passive, no API key, standard protocol
(RFC 7483). Uses rdap.org's public bootstrap redirector so we don't have to
figure out which RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC) owns a given IP
ourselves.

This exists to make the "raw host data is for responsible disclosure, not
publishing" promise in the README actually actionable — turning an IP into
"here's who to email about it."
"""

import time

import requests

RDAP_URL = "https://rdap.org/ip/{ip}"


def _find_entities_by_role(entities: list[dict], role: str) -> list[dict]:
    """RDAP nests entities inside entities (e.g. RIPE) — search recursively."""
    found = []
    for entity in entities or []:
        if role in entity.get("roles", []):
            found.append(entity)
        found.extend(_find_entities_by_role(entity.get("entities", []), role))
    return found


# Preference order for finding a usable contact. Not every registry uses an
# "abuse" role — verified empirically that APNIC records for Chinese ISPs
# (e.g. CHINANET allocations) have NO "abuse"-role entity at all; their
# actual abuse-handling contact (often literally an anti-spam mailbox) is
# labeled "technical" or "administrative" instead. Without this fallback,
# every APNIC-region host silently returns "no contact" even though a
# usable one exists — checked and confirmed this was happening before
# adding the fallback.
ROLE_PREFERENCE = ["abuse", "technical", "administrative", "registrant"]


def _extract_email(vcard_array) -> str | None:
    if not vcard_array or len(vcard_array) < 2:
        return None
    for field in vcard_array[1]:
        if len(field) >= 4 and field[0] == "email":
            return field[3]
    return None


def _extract_org(vcard_array) -> str | None:
    if not vcard_array or len(vcard_array) < 2:
        return None
    for field in vcard_array[1]:
        if len(field) >= 4 and field[0] == "org":
            return field[3]
    return None


class LookupFailed(Exception):
    """Raised when the RDAP request itself failed (network/5xx/timeout) —
    distinct from a successful lookup that genuinely found no contact.
    rdap.org is a shared public proxy and does fail transiently under
    repeated quick requests (verified: a batch run silently mis-reported
    several real contacts as 'not found' this way before this was added)."""


def lookup_abuse_contact(ip: str, timeout: int = 15, retries: int = 2) -> str | None:
    """
    Return a contact string for an IP, or None if a successful lookup
    genuinely found nothing usable. Raises LookupFailed if the request
    itself never succeeded after retries — callers should treat that
    differently from a real "no contact" (don't cache it as a negative
    result).

    Tries roles in ROLE_PREFERENCE order and tags the result with which
    role it came from, e.g. 'abuse@isp.com (Some ISP) [abuse]' vs the
    weaker 'anti_spam@carrier.cn (Some Carrier) [technical]' — the tag
    matters: an "abuse" role is a real commitment to handle reports, a
    repurposed "technical" contact is a best-effort fallback, not a
    guarantee.
    """
    data = None
    last_error = None
    for attempt in range(retries + 1):
        try:
            resp = requests.get(RDAP_URL.format(ip=ip), timeout=timeout)
            if resp.status_code == 404:
                return None  # RDAP explicitly has no record — a real negative
            resp.raise_for_status()
            data = resp.json()
            break
        except (requests.RequestException, ValueError) as e:
            last_error = e
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    if data is None:
        raise LookupFailed(f"{ip}: {last_error}")

    entities = data.get("entities", [])
    for role in ROLE_PREFERENCE:
        candidates = _find_entities_by_role(entities, role)
        for entity in candidates:
            email = _extract_email(entity.get("vcardArray"))
            if email:
                org = _extract_org(entity.get("vcardArray"))
                org_part = f" ({org})" if org else ""
                return f"{email}{org_part} [{role}]"
    return None


def lookup_many(ips: list[str], delay: float = 0.5) -> dict[str, str | None]:
    """Sequential lookups with a polite delay between requests."""
    results = {}
    for ip in ips:
        results[ip] = lookup_abuse_contact(ip)
        time.sleep(delay)
    return results
