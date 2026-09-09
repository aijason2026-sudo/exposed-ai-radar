"""
Candidate products for exposed-ai-radar — NOT wired into collector.py's
live PRODUCTS list (see products.py). That file's own header rule applies
here too: every entry must be manually verified against real sample
results before being trusted, because a noisy query is worse than no
query for this project. LM Studio and text-generation-webui were already
dropped for exactly this reason — see products.py.

These candidates were sanity-checked with Shodan's /count endpoint only
(api.count() — confirmed empirically to cost 0 query credits, unlike
api.search() which costs 1 credit per page once any filter is used, even
page 1). That was done during a period when the account had 0 search
credits left (see README's "Suggested next steps"). count() only tells
you plausible *magnitude* — it returns zero sample matches, so a query
can still be dominated by false positives even with a "reasonable" total.

Promote an entry to products.py's PRODUCTS list only after pulling real
samples (one page, one query credit) and eyeballing them, e.g.:

    uv run python -c "
import shodan, os
from dotenv import load_dotenv
load_dotenv()
api = shodan.Shodan(os.environ['SHODAN_API_KEY'])
r = api.search('<query>', page=1)
for m in r['matches'][:10]:
    print(m.get('ip_str'), m.get('port'), m.get('http', {}).get('title'), m.get('product'))
"

If the samples are genuinely the target product (not third-party pages
that merely mention it, unrelated software, or generic titles), move the
entry into products.py's PRODUCTS list. Otherwise tighten the query or
drop the candidate — record what was tried either way, same as
products.py's own header documents for the two products it rejected.
"""

CANDIDATE_PRODUCTS = [
    {
        "name": "Milvus",
        "query": 'product:"Milvus"',
        "count_checked": 959,
        "confidence": "high",
        "default_no_auth": True,
        "notes": "Uses Shodan's own dedicated product fingerprint — same "
                 "trust basis as the existing Ollama entry, so this is the "
                 "highest-confidence candidate here. Milvus does not enable "
                 "RBAC/authentication by default (opt-in feature) per its "
                 "own docs — documented-default hint, not a per-host check, "
                 "same caveat as every default_no_auth field in products.py. "
                 "Still needs a real sample pull before going live per "
                 "project policy. Count-checked 2026-09-09 while the "
                 "account had 0 search credits (see README).",
    },
    {
        "name": "Weaviate",
        "query": 'http.title:"Weaviate"',
        "count_checked": 12,
        "confidence": "medium",
        "default_no_auth": None,
        "notes": "No dedicated Shodan product tag exists. Kept to an exact "
                 "title match deliberately — the broader http.html:\"weaviate\" "
                 "returned 1,321 (likely much noisier, includes any page "
                 "merely mentioning the word). Small total is plausible for "
                 "an API-first tool that rarely renders an HTML title, but "
                 "may also be undercounting real exposure. default_no_auth "
                 "left unknown — Weaviate's anonymous-access default has "
                 "reportedly changed across versions; not confident enough "
                 "to assert either way without checking real samples.",
    },
    {
        "name": "Qdrant",
        "query": 'http.title:"Qdrant"',
        "count_checked": 9,
        "confidence": "medium",
        "default_no_auth": True,
        "notes": "Same reasoning as Weaviate — no dedicated product tag, "
                 "kept to exact title match over the noisier "
                 "http.html:\"qdrant\" (3,304 total, likely too broad). "
                 "Qdrant does not enforce API-key auth unless explicitly "
                 "configured (documented default).",
    },
    {
        "name": "MLflow",
        "query": 'http.title:"MLflow"',
        "count_checked": 3849,
        "confidence": "medium",
        "default_no_auth": True,
        "notes": "MLflow's tracking UI sets its HTML title to 'MLflow' by "
                 "default — plausible signal. MLflow ships with no built-in "
                 "authentication at all (well-documented gap). Not yet "
                 "sample-verified.",
    },
    {
        "name": "Kubeflow",
        "query": 'http.title:"Kubeflow"',
        "count_checked": 530,
        "confidence": "medium",
        "default_no_auth": None,
        "notes": "Central dashboard title match. Kubeflow deployments vary "
                 "widely in whether an auth proxy (Dex/Istio, etc.) sits in "
                 "front, so default_no_auth is intentionally left unknown "
                 "unlike most other entries — this would need a per-sample "
                 "look, not just a documented default.",
    },
    {
        "name": "BentoML",
        "query": 'http.title:"BentoML"',
        "count_checked": 56,
        "confidence": "medium",
        "default_no_auth": None,
        "notes": "Small total, plausible for a less widely self-hosted "
                 "tool. Not confident enough about its default auth posture "
                 "to assert True/False without checking real samples.",
    },
    {
        "name": "ChromaDB",
        "query": 'http.title:"Chroma"',
        "count_checked": 175,
        "confidence": "low",
        "default_no_auth": None,
        "notes": "CAUTION: 'Chroma' is a common English/tech word (color "
                 "tools, camera apps, unrelated software also use it) — "
                 "highest false-positive risk of this batch. Needs a real "
                 "sample pull before being trusted at all; may need a "
                 "stricter query (e.g. a JSON body field unique to "
                 "ChromaDB's own API, or its default port 8000 combined "
                 "with a body fingerprint) instead of a bare title match.",
    },
]

# Rejected during count-only research (2026-09-09) — kept as a record so
# nobody re-tries the same dead end:
#
# - Ray Dashboard: http.title:"Ray Dashboard" -> 189,555 total. Implausibly
#   huge for a niche MLOps tool (more than ComfyUI's ~191k, and ComfyUI is
#   a genuinely popular consumer tool) — "Ray Dashboard" is evidently a
#   common generic title used by unrelated things too. Rejected as noisy,
#   same reasoning products.py already used to drop LM Studio and
#   text-generation-webui.
# - TorchServe: http.title:"TorchServe" -> 0. No signal — likely an
#   API-only service with no HTML title to match against.
# - text-generation-webui: http.title:"Text generation web UI" -> 0.
#   Consistent with products.py's existing documented rejection of this
#   tool (originally dropped for false positives via a different query).
