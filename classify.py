"""Rough classification of an org/ISP name into a hosting category.

Keyword-based, not exhaustive — good enough to separate "someone's home
connection" from "a cloud VM" from "a university" at a glance in the
dashboard. Unmatched orgs fall into Other/Unknown rather than being
force-fit into a guessed category.
"""

CLOUD_HOSTING_KEYWORDS = [
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
    "linode", "constant company", "vultr", "ovh", "hetzner", "contabo",
    "ionos", "oracle", "alibaba", "tencent", "huawei cloud", "runpod",
    "vast.ai", "scaleway", "leaseweb", "choopa", "hostinger", "godaddy",
    "cloudflare", "fastly", "akamai", "a100", "gpu", "datacenter",
    "data center", "colocation", "hosting",
]

RESIDENTIAL_ISP_KEYWORDS = [
    "comcast", "charter", "virgin media", "orange", "korea telecom",
    "chinanet", "china unicom", "china mobile", "deutsche telekom",
    "telefonica", "vodafone", "at&t", "verizon", " bt ", "sk broadband",
    "ntt", "telstra", "residential", "broadband", "telecom", "telkom",
    "cable", "fiber", "adsl", "dsl",
]

INSTITUTION_KEYWORDS = [
    "university", "institute", "college", "school", "academy",
    "polytechnic", "politehnica",
]


def classify_org(org: str) -> str:
    if not org:
        return "Other/Unknown"
    o = org.lower()
    if any(k in o for k in INSTITUTION_KEYWORDS):
        return "Institution"
    if any(k in o for k in CLOUD_HOSTING_KEYWORDS):
        return "Cloud/Hosting"
    if any(k in o for k in RESIDENTIAL_ISP_KEYWORDS):
        return "Residential ISP"
    return "Other/Unknown"
