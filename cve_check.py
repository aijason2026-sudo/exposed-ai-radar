"""
Best-effort CVE flagging by version, built from public CVE writeups
(Wiz, Oligo Security, OpenCVE — see sources below). Only includes entries
where the affected-version boundary was clearly and consistently reported;
ambiguous/contradictory entries found during research (e.g. a 2025 CVE ID
whose "fixed in" version predates it) were deliberately left out rather
than guessed. Re-verify against current CVE databases periodically —
this is not a maintained feed.

Version strings are assumed to be clean "X.Y.Z" semver, matching what
Shodan captures from Ollama's banner. Unparseable versions are skipped.
"""

from threat_intel import get_epss_scores, get_kev_set

# (cve_id, description, "fixed_in" version — flagged if installed < this)
OLLAMA_CVES = [
    (
        "CVE-2024-37032",
        "\"Probllama\" — path traversal leading to RCE via crafted model manifest",
        (0, 1, 34),
    ),
    (
        "CVE-2024-39719",
        "File existence disclosure",
        (0, 1, 47),
    ),
    (
        "CVE-2024-39720",
        "Application crash / DoS",
        (0, 1, 47),
    ),
    (
        "CVE-2024-39721",
        "DoS via CreateModel API",
        (0, 1, 47),
    ),
    (
        "CVE-2024-39722",
        "Path traversal",
        (0, 1, 47),
    ),
    (
        "CVE-2025-0312",
        "DoS via crafted GGUF model file",
        (0, 3, 15),
    ),
]

SOURCES = [
    "https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032",
    "https://www.oligo.security/blog/more-models-more-probllms",
    "https://app.opencve.io/cve/?vendor=ollama",
]


def parse_version(v: str):
    if not v:
        return None
    try:
        parts = tuple(int(x) for x in v.strip().lstrip("v").split("."))
        return parts
    except ValueError:
        return None


def flag_cves(version: str) -> list[dict]:
    """
    Return a list of dicts describing CVEs a given Ollama version is
    affected by, enriched with KEV (actively exploited, bool) and EPSS
    (predicted exploitation probability, 0-1) where available.
    """
    parsed = parse_version(version)
    if parsed is None:
        return []
    flagged = [
        {"cve_id": cve_id, "description": desc}
        for cve_id, desc, fixed_in in OLLAMA_CVES
        if parsed < fixed_in
    ]
    if not flagged:
        return []

    kev_set = get_kev_set()
    epss_scores = get_epss_scores([f["cve_id"] for f in flagged])
    for f in flagged:
        f["is_kev"] = f["cve_id"] in kev_set
        f["epss"] = epss_scores.get(f["cve_id"], 0.0)
    return flagged


def format_cve_flags(flagged: list[dict]) -> str | None:
    """Human-readable summary string for storage/display, e.g.
    'CVE-2024-37032 [KEV, EPSS 0.90]: Probllama - RCE via crafted manifest'."""
    if not flagged:
        return None
    parts = []
    for f in flagged:
        tags = []
        if f.get("is_kev"):
            tags.append("KEV")
        if f.get("epss", 0) >= 0.01:
            tags.append(f"EPSS {f['epss']:.2f}")
        tag_str = f" [{', '.join(tags)}]" if tags else ""
        parts.append(f"{f['cve_id']}{tag_str}: {f['description']}")
    return "; ".join(parts)
