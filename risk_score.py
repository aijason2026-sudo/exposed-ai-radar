"""
Composite risk scoring — a heuristic triage priority, not an objective
severity measure. Combines three signals we can actually observe passively:
auth status, who's hosting it, and known CVEs (Ollama only, see cve_check.py
and the caution notes in products.py about why this isn't extended further).

Reasoning behind the weights (adjust if it stops matching intuition):
- A known, currently-unpatched CVE is the single strongest signal —
  weighted heaviest, and boosted further if CISA KEV confirms it's being
  actively exploited right now, or EPSS predicts a high near-term
  exploitation probability.
- No authentication at all is worse than "unknown" auth status, which is
  worse than "has some login gate."
- A residential ISP connection is more concerning than a rented cloud box:
  it's more likely to be an individual's unmanaged, unmonitored machine
  than a professionally-run cloud tenant, and more likely to be forgotten.
  An institution (university etc.) sits in between.
"""

TIERS = ["Low", "Medium", "High", "Critical"]


def score_and_tier(hosting_category: str, looks_unauthenticated, cve_details: list[dict]):
    score = 0

    if looks_unauthenticated is True:
        score += 2
    elif looks_unauthenticated is None:
        score += 1
    # looks_unauthenticated is False -> +0

    if hosting_category == "Residential ISP":
        score += 2
    elif hosting_category == "Institution":
        score += 1
    elif hosting_category == "Other/Unknown":
        score += 1
    # Cloud/Hosting -> +0

    if cve_details:
        score += 3
        if len(cve_details) > 2:
            score += 1
        if any(c.get("is_kev") for c in cve_details):
            score += 3  # confirmed actively exploited in the wild right now
        max_epss = max((c.get("epss", 0.0) for c in cve_details), default=0.0)
        if max_epss >= 0.5:
            score += 2
        elif max_epss >= 0.1:
            score += 1

    if score <= 1:
        tier = "Low"
    elif score <= 3:
        tier = "Medium"
    elif score <= 5:
        tier = "High"
    else:
        tier = "Critical"

    return score, tier
