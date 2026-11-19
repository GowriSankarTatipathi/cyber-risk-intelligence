"""Build a company-domains CSV from Wikidata's "official website" (P856), matched by SEC CIK (P5531).

    python -m cyber_risk_intelligence.domains wikidata companies-seed.csv > company_domains.csv

Read-only queries to the public Wikidata SPARQL endpoint (CC0 data). A company
with no Wikidata match is listed on stderr and left out: unknown, not "no domain".
Only Wikidata's best-ranked value is used. Review the file before importing it.
"""

from __future__ import annotations

import csv
import io
import os
import sys
import time

import httpx

from ..ingest.seed_companies import company_key
from ..normalize import normalize_cik
from .job import normalize_domain

ENDPOINT = "https://query.wikidata.org/sparql"
QUERY = """SELECT ?cik ?item ?site WHERE {{
  VALUES ?cik {{ {values} }}
  ?item wdt:P5531 ?cik ; wdt:P856 ?site .
}}"""


def _ciks(seed_csv: bytes) -> dict[str, str]:
    """normalized CIK -> company_key, from the 200-company seed file."""
    out = {}
    for row in csv.DictReader(io.StringIO(seed_csv.decode("utf-8-sig"))):
        try:
            cik = normalize_cik(row.get("Current issuer CIK", ""))
        except ValueError:
            continue
        if row.get("Company name"):
            out[cik] = company_key(row["Company name"])
    return out


def build(seed_csv: bytes, client: httpx.Client | None = None, batch: int = 250) -> tuple[str, list[str]]:
    by_cik = _ciks(seed_csv)
    agent = os.environ.get("COLLECTOR_USER_AGENT", "cyber-risk-research/0.1")
    client = client or httpx.Client(timeout=60, headers={"User-Agent": agent, "Accept": "application/json"})
    found: dict[str, list[tuple[str, str]]] = {}
    ciks = sorted(by_cik)
    for i in range(0, len(ciks), batch):
        part = ciks[i:i + batch]
        # Wikidata stores CIKs zero-padded to 10 digits, but not always; ask for both.
        values = " ".join(f'"{c.zfill(10)}" "{c.lstrip("0")}"' for c in part)
        params = {"query": QUERY.format(values=values), "format": "json"}
        for attempt in range(4):
            resp = client.get(ENDPOINT, params=params)
            if resp.status_code != 429:
                break
            time.sleep(min(int(resp.headers.get("Retry-After", "60") or 60), 120))  # the endpoint asks us to wait
        resp.raise_for_status()
        for b in resp.json()["results"]["bindings"]:
            try:
                cik = normalize_cik(b["cik"]["value"])
            except ValueError:
                continue
            domain = normalize_domain(b["site"]["value"])
            if cik in by_cik and domain:
                found.setdefault(cik, []).append((domain, b["item"]["value"]))
        if i + batch < len(ciks):
            time.sleep(60)  # the public endpoint allows about one query a minute
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["company_key", "domain", "role", "source_url", "notes"])
    for cik in ciks:
        seen: set[str] = set()
        names = {d for d, _ in found.get(cik, [])}
        for domain, item in found.get(cik, []):
            # de.delta.com, fr.delta.com ... are language sites of delta.com: keep the parent only.
            if domain not in seen and not any(domain.endswith("." + other) for other in names):
                seen.add(domain)
                w.writerow([by_cik[cik], domain, "primary_website", item.replace("http://", "https://"),
                            "Wikidata P856 official website"])
    missing = [by_cik[c] for c in ciks if c not in found]
    return buf.getvalue(), missing


def main(path: str) -> int:
    with open(path, "rb") as fh:
        text, missing = build(fh.read())
    sys.stdout.write(text)
    if missing:
        print(f"no Wikidata website for {len(missing)} companies: {', '.join(missing)}", file=sys.stderr)
    return 0
