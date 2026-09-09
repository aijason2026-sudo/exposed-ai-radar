"""
Pull one real Shodan search page for a candidate_products.py entry so its
accuracy can be eyeballed before promoting it into products.py's live
PRODUCTS list. Costs 1 query credit. See candidate_products.py's module
docstring for the full promotion workflow and why count()-only checking
isn't enough on its own.

Usage:
    uv run verify_candidate.py "Milvus"
"""

import argparse
import os
import sys

import shodan
from dotenv import load_dotenv

from candidate_products import CANDIDATE_PRODUCTS

load_dotenv()


def run(name: str) -> None:
    candidate = next(
        (c for c in CANDIDATE_PRODUCTS if c["name"].lower() == name.lower()), None
    )
    if candidate is None:
        names = ", ".join(c["name"] for c in CANDIDATE_PRODUCTS)
        sys.exit(f"No candidate named {name!r} in candidate_products.py. Available: {names}")

    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        sys.exit("SHODAN_API_KEY not set (check your .env file)")
    api = shodan.Shodan(key)

    info = api.info()
    remaining = info.get("query_credits", 0)
    print(f"Shodan query credits remaining: {remaining}")
    if remaining < 1:
        sys.exit("No query credits left — wait for the monthly reset (see README).")

    print(f"\n[{candidate['name']}] query: {candidate['query']} "
          f"(count-checked total: {candidate['count_checked']}, "
          f"confidence: {candidate['confidence']})")
    try:
        results = api.search(candidate["query"], page=1)
    except shodan.APIError as e:
        sys.exit(f"Search failed: {e}")

    matches = results.get("matches", [])
    print(f"Live total: {results.get('total', 0)} | showing first "
          f"{min(10, len(matches))} of {len(matches)} fetched\n")

    for m in matches[:10]:
        http = m.get("http") or {}
        print(f"  {m.get('ip_str')}:{m.get('port')}  "
              f"title={http.get('title')!r}  product={m.get('product')!r}  "
              f"org={m.get('org')!r}  version={m.get('version')!r}")

    print(
        "\nEyeball the above: are these genuinely the target product, or "
        "third-party pages/unrelated software that merely mention the name? "
        "If they look right, move this entry from CANDIDATE_PRODUCTS in "
        "candidate_products.py into products.py's PRODUCTS list. If not, "
        "tighten the query or drop it and record why, same as "
        "candidate_products.py's rejected-candidates comment block."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="Candidate product name from candidate_products.py, e.g. 'Milvus'")
    args = parser.parse_args()
    run(args.name)
