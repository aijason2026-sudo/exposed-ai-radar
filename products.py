"""
Product definitions for exposed-ai-radar.

`default_no_auth` reflects the *documented default configuration* of each
project (i.e. "does this tool ship with authentication off by default"),
not a per-host active check. We never connect to a discovered host
ourselves — only Shodan's own pre-collected banner data is used — so we
cannot verify a specific instance's actual auth state without crossing
from "reading a public dataset" into "accessing someone else's system".
Treat this field as a documented-default hint, not a per-host fact.
"""

# Every query below was manually verified against sample results before being
# trusted (see project history) — don't add a new product without doing the
# same. Two candidates (LM Studio, text-generation-webui) were tried and
# DROPPED because every title-based query for them returned mostly false
# positives (third-party wrapper apps/chat frontends that merely mention the
# product name, and unrelated directory/listicle sites) rather than actual
# exposed instances. A noisy query is worse than no query for this project.

PRODUCTS = [
    {
        "name": "Ollama",
        "query": 'product:"Ollama"',
        "default_no_auth": True,
        "notes": "No authentication concept exists in Ollama's API at all. "
                 "Uses Shodan's own product fingerprint tag (verified clean "
                 "on port 11434 samples).",
    },
    {
        "name": "Open WebUI",
        "query": 'http.title:"Open WebUI"',
        "default_no_auth": None,
        "notes": "Ships with login enabled by default, but can be disabled "
                 "via WEBUI_AUTH=False. SPA frontend means Shodan's cached "
                 "HTML won't reliably show whether a login gate is active. "
                 "Exact-title match verified clean on samples. CAUTION: "
                 "Shodan's 'version' field for this product does NOT match "
                 "real Open WebUI version numbers (real Open WebUI is "
                 "currently ~0.6-0.11.x, we've seen stored values like "
                 "'1.27.5') — same root cause as vLLM (generic banner "
                 "metadata, not the app version). Do not build CVE flagging "
                 "on this field.",
    },
    {
        "name": "vLLM",
        "query": 'http.html:"vllm"',
        "pages": 5,  # total is only ~448 — 5 pages gets close to the FULL
                     # population instead of a ~22% sample, unlike the other
                     # three products where totals are in the tens/hundreds
                     # of thousands and multi-page sampling wouldn't help.
        "default_no_auth": True,
        "notes": "OpenAI-compatible server; no API key enforced unless "
                 "explicitly configured with --api-key. Noisier signature "
                 "than the others (bare API servers rarely set a title) — "
                 "revisit if false-positive rate looks high over time. "
                 "CAUTION: Shodan's 'version' field for this product does "
                 "NOT match real vLLM version numbers (real vLLM is 0.x, "
                 "we've seen stored values like '1.24.0'/'2.4.46') — it's "
                 "generic banner metadata, not the app version, since this "
                 "match isn't from a dedicated Shodan product-fingerprint "
                 "module. Do not build CVE flagging on this field.",
    },
    {
        "name": "ComfyUI",
        "query": 'http.title:"ComfyUI"',
        "default_no_auth": True,
        "notes": "Well-documented to ship with zero authentication. No port "
                 "filter — verified real deployments commonly sit behind "
                 "randomized cloud-GPU-rental ports (RunPod/Vast.ai etc.), "
                 "not just the default 8188.",
    },
]
