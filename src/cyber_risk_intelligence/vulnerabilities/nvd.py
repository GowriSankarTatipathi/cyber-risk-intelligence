"""NVD records: CVSS severity, CWE weakness and affected products (issue 5.3).

The NVD (National Vulnerability Database, NIST) API returns one CVE at a time
(``https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...``), free. Without a key NVD allows
about 5 requests per 30 seconds, so the client waits about 6.5 s between requests; with a free key
(``NVD_API_KEY`` in the environment, sent as a header and never stored) it is 50 per 30 seconds.

Each run asks only for tracked CVEs (exposure + KEV, as in 5.2) that we have no NVD record for yet,
whose last lookup failed, or whose record is older than ``refresh_days``. The CVE's NVD record is
stored as evidence; ``vulnerabilities``, ``cvss_scores`` and ``vulnerability_weaknesses`` take its
values. Every CVSS score keeps its version, vector and who scored it; a record without a score stays
without one. A rate limit or server error is retried, then recorded as ``lookup_failed`` (unknown).
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
from sqlalchemy import delete, select, text

from ..evidence import SecretDetected, record_evidence
from ..evidence.store import ObjectStore
from ..ingest.framework import (
    InputRow,
    Job,
    RowRejected,
    RowStatus,
    Rule,
    SourceSpec,
    TransientError,
    WriteContext,
    ensure_source,
)
from ..models.vulnerabilities import (
    CVE_PATTERN,
    CVSS_VERSIONS,
    CvssScore,
    Vulnerability,
    VulnerabilityWeakness,
)
from .epss import tracked_cves

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_USER_AGENT = "cyber-risk-intelligence-research/0.1 (NVD CVE lookup)"
NVD_SOURCE = SourceSpec(
    source_key="nist_nvd",
    name="NIST National Vulnerability Database (NVD) CVE API 2.0",
    source_type="vulnerability_db",
    access_method="api",
    base_url=API_URL,
    terms_url="https://nvd.nist.gov/developers/terms-of-use",
    license="US government work (public domain); not endorsed by NVD",
    notes="One CVE per request: descriptions, CVSS v2/v3/v4 scores with their source, CWE weaknesses, "
          "affected configurations (CPE) and references. Rate limited; free API key raises the limit.",
)
INPUT_SOURCE = SourceSpec(source_key="tracked_cves", name="Tracked CVEs (exposure + KEV)", source_type="dataset",
                          access_method="other", notes="CVE ids chosen from the database for an NVD run.")
_CVE = re.compile(CVE_PATTERN)
MAX_PRODUCTS = 200


class NvdKeyRejected(TransientError):
    """NVD refused the API key (``NVD_API_KEY``): wrong, expired or not activated yet."""


@dataclass
class NvdRecord:
    outcome: str  # found / not_found / lookup_failed
    cve_id: str
    url: str
    cve: dict | None = None
    message: str | None = None

    def document(self) -> bytes:
        """The CVE record alone (NVD's response also carries a request timestamp), so the same
        record fetched twice is the same evidence."""
        return json.dumps(self.cve, sort_keys=True, ensure_ascii=False).encode()


class NvdClient:
    def __init__(self, client: httpx.Client | None = None, api_key: str | None = None, timeout: float = 30.0,
                 pause: float | None = None, retries: int = 3, backoff_s: float = 30.0):
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY") or None
        headers = {"User-Agent": DEFAULT_USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key
        self._client = client or httpx.Client(timeout=timeout, headers=headers)
        if client is not None and self.api_key:
            self._client.headers["apiKey"] = self.api_key
        # NVD: 5 requests per 30 s without a key, 50 with one.
        self.pause = pause if pause is not None else (0.7 if self.api_key else 6.5)
        self.retries, self.backoff_s = retries, backoff_s
        self._last = 0.0

    def _wait(self) -> None:
        gap = self.pause - (time.monotonic() - self._last)
        if gap > 0:
            time.sleep(gap)
        self._last = time.monotonic()

    def cve(self, cve_id: str) -> NvdRecord:
        url = f"{API_URL}?cveId={cve_id}"
        problem = "no attempt"
        for attempt in range(self.retries):
            if attempt:
                time.sleep(self.backoff_s * attempt)
            self._wait()
            try:
                r = self._client.get(API_URL, params={"cveId": cve_id})
            except httpx.HTTPError as exc:
                problem = f"{type(exc).__name__}: {exc}"
                continue
            if r.status_code == 200:
                try:
                    items = r.json().get("vulnerabilities") or []
                except ValueError:
                    problem = "answer is not JSON"
                    continue
                if not items:
                    return NvdRecord("not_found", cve_id, url, message="NVD has no record for this CVE")
                return NvdRecord("found", cve_id, url, cve=items[0].get("cve") or {})
            note = r.headers.get("message") or ""
            problem = f"HTTP {r.status_code}" + (f" ({note})" if note else "")
            if "apikey" in note.lower():
                # NVD answers 404 "Invalid apiKey." for a wrong or not yet activated key: every lookup
                # would fail the same way, so the run stops instead of recording thousands of them.
                raise NvdKeyRejected(f"NVD rejected the API key: {note}")
            # An unknown CVE is a 200 with no results; any other status says nothing about the CVE.
            if r.status_code not in (403, 429) and r.status_code < 500:  # NVD answers 403 when rate limited
                break
        return NvdRecord("lookup_failed", cve_id, url, message=problem)


def _when(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        t = datetime.fromisoformat(value)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)  # NVD times are UTC


def _decimal(value) -> Decimal | None:
    try:
        return Decimal(str(value)) if value is not None else None
    except ArithmeticError:
        return None


def cvss_rows(metrics: dict) -> list[dict]:
    """Every CVSS score in an NVD ``metrics`` block, each labelled with its version and source."""
    rows = []
    for key, items in (metrics or {}).items():
        if not key.startswith("cvssMetric") or not isinstance(items, list):
            continue
        for m in items:
            data = m.get("cvssData") or {}
            version, vector, score = str(data.get("version") or ""), data.get("vectorString"), data.get("baseScore")
            if version not in CVSS_VERSIONS or not vector or score is None:
                continue  # an assessment we can't label is not stored as a score
            rows.append({
                "cvss_version": version, "source": m.get("source") or "unknown", "score_type": m.get("type"),
                "vector_string": vector, "base_score": _decimal(score),
                "base_severity": data.get("baseSeverity") or m.get("baseSeverity"),
                "attack_vector": data.get("attackVector") or data.get("accessVector"),
                "user_interaction": data.get("userInteraction"),
                "privileges_required": data.get("privilegesRequired"),
                "exploitability_score": _decimal(m.get("exploitabilityScore")),
                "impact_score": _decimal(m.get("impactScore")),
            })
    return rows


def weakness_rows(weaknesses: list) -> list[dict]:
    seen, rows = set(), []
    for w in weaknesses or []:
        for d in w.get("description") or []:
            cwe = (d.get("value") or "").strip()
            key = (cwe, w.get("source") or "unknown")
            if cwe and key not in seen:
                seen.add(key)
                rows.append({"cwe_id": cwe, "source": key[1], "weakness_type": w.get("type")})
    return rows


def affected(configurations: list) -> tuple[list[str], int]:
    """(vendor:product pairs NVD marks vulnerable, number of vulnerable CPE criteria)."""
    products, count = set(), 0
    stack = list(configurations or [])
    while stack:
        node = stack.pop()
        stack.extend(node.get("nodes") or [])
        for m in node.get("cpeMatch") or []:
            if m.get("vulnerable"):
                count += 1
                parts = (m.get("criteria") or "").split(":")
                if len(parts) > 4:
                    products.add(f"{parts[3]}:{parts[4]}")
    return sorted(products)[:MAX_PRODUCTS], count


# How the preferred CVSS score of a CVE reads, for ranking. Not a verdict on any company.
IMPACT_CLASSES = ("remote", "local", "needs_user", "dos_only", "unscored")


def impact_class(vector: str | None) -> str:
    """``remote``: over the network, no user action, and it can read or change data; ``local``: needs
    local or physical access; ``needs_user``: someone has to click or open something (XSS and the
    like); ``dos_only``: it can only slow or stop a service; ``unscored``: no CVSS vector."""
    if not vector:
        return "unscored"
    parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    if parts.get("AV") in ("L", "P"):
        return "local"
    if parts.get("UI") in ("R", "P", "A"):
        return "needs_user"
    conf = parts.get("C", parts.get("VC"))
    integ = parts.get("I", parts.get("VI"))
    if conf in ("N",) and integ in ("N",):
        return "dos_only"
    return "remote"


def targets_csv(session, refresh_days: int = 30, limit: int | None = None) -> bytes:
    """Tracked CVEs that need an NVD lookup: never looked up, last lookup failed or found nothing (asked
    again every run; there are few), or a record older than ``refresh_days``. CVEs Shodan inferred in the exposure lookups come first (they feed the priority
    list), then the KEV-only ones; newest CVE ids first within each."""
    tracked = tracked_cves(session)
    exposure = set(session.scalars(text(
        "SELECT DISTINCT upper(v) FROM indexed_host_lookups, jsonb_array_elements_text(potential_vulns) AS v")).all())
    since = datetime.now(UTC) - timedelta(days=refresh_days)
    fresh = set(session.scalars(text(
        "SELECT cve_id FROM vulnerabilities WHERE outcome = 'found' AND retrieved_at >= :since"),
        {"since": since}).all())

    def order(cve: str):
        _, year, number = cve.split("-")
        return (cve not in exposure, -int(year), -int(number))

    todo = sorted((c for c in tracked - fresh if _CVE.match(c)), key=order)
    if limit is not None:
        todo = todo[:limit]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["cve_id"])
    w.writerows([c] for c in todo)
    return buf.getvalue().encode()


class NvdJob(Job):
    name = "nvd_cves"
    dataset_key = "nvd_cve_targets"
    media_type = "text/csv"
    source = INPUT_SOURCE
    rules = (Rule("cve_id_valid", lambda r: None if _CVE.match((r.get("cve_id") or "").strip().upper())
                  else f"cve_id {r.get('cve_id')!r} is not a CVE id", field="cve_id"),)

    def __init__(self, store: ObjectStore, client: NvdClient | None = None):
        self.store = store
        self._client = client
        self.tally = {"found": 0, "not_found": 0, "lookup_failed": 0}

    @property
    def client(self) -> NvdClient:
        if self._client is None:
            self._client = NvdClient()
        return self._client

    def parse(self, content: bytes):
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        if not reader.fieldnames or "cve_id" not in reader.fieldnames:
            raise ValueError("CSV has no 'cve_id' header")
        for number, row in enumerate(reader, start=1):
            cve = (row.get("cve_id") or "").strip().upper()
            yield InputRow(number, cve if _CVE.match(cve) else f"row-{number}", {"cve_id": cve})

    def write(self, ctx: WriteContext) -> RowStatus:
        s, cve_id = ctx.session, ctx.row.key
        rec = self.client.cve(cve_id)
        self.tally[rec.outcome] += 1
        now = datetime.now(UTC)
        row = s.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
        if rec.outcome != "found":
            if row is None:
                s.add(Vulnerability(cve_id=cve_id, outcome=rec.outcome, message=rec.message, retrieved_at=now,
                                    ingestion_run_id=ctx.run.id))
                return "inserted"
            if rec.outcome == "lookup_failed" and row.outcome == "found":
                return "unchanged"  # keep what we know; a failed lookup isn't news about the CVE
            row.outcome, row.message, row.retrieved_at, row.ingestion_run_id = rec.outcome, rec.message, now, ctx.run.id
            return "updated"

        try:
            version = record_evidence(s, self.store, source=ensure_source(s, NVD_SOURCE), source_url=rec.url,
                                      content=rec.document(), media_type="application/json", http_status=200,
                                      title=f"NVD record for {cve_id}")
        except SecretDetected as exc:
            raise RowRejected("withheld", f"NVD record for {cve_id} not stored: {exc}", "cve_id") from None
        c = rec.cve or {}
        products, cpe_count = affected(c.get("configurations"))
        description = next((d.get("value") for d in c.get("descriptions") or [] if d.get("lang") == "en"), None)
        values = {
            "outcome": "found", "message": None, "vuln_status": c.get("vulnStatus"),
            "source_identifier": c.get("sourceIdentifier"), "description": description,
            "published_at": _when(c.get("published")), "last_modified_at": _when(c.get("lastModified")),
            "affected_products": products or None, "affected_cpe_count": cpe_count,
            "references": [{"url": r.get("url"), "source": r.get("source"), "tags": r.get("tags") or []}
                           for r in c.get("references") or [] if r.get("url")] or None,
        }
        same = row is not None and row.evidence_version_id == version.id and row.outcome == "found"
        new = row is None
        if new:
            row = Vulnerability(cve_id=cve_id, retrieved_at=now, **values)
            s.add(row)
        row.retrieved_at, row.ingestion_run_id = now, ctx.run.id
        if same:
            return "unchanged"
        for k, v in values.items():
            setattr(row, k, v)
        row.evidence_version_id = version.id
        s.flush()
        # Replace the scores and weaknesses with this record's; earlier ones stay in earlier evidence.
        s.execute(delete(CvssScore).where(CvssScore.vulnerability_id == row.id))
        s.execute(delete(VulnerabilityWeakness).where(VulnerabilityWeakness.vulnerability_id == row.id))
        for score in cvss_rows(c.get("metrics")):
            s.add(CvssScore(vulnerability_id=row.id, evidence_version_id=version.id, **score))
        for weak in weakness_rows(c.get("weaknesses")):
            s.add(VulnerabilityWeakness(vulnerability_id=row.id, evidence_version_id=version.id, **weak))
        return "inserted" if new else "updated"
