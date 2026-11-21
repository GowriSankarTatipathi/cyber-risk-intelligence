"""FIRST EPSS daily scores (issue 5.2).

EPSS (Exploit Prediction Scoring System, by FIRST) publishes once a day a free CSV of every published
CVE with two numbers: ``epss``, the estimated probability (0-1) of exploitation activity against that
CVE anywhere in the next 30 days, and ``percentile``, how it ranks among all scored CVEs that day.
The file's first line gives the model version and the scoring date.

One import downloads one day's file (about 3 MB gzipped, 400k CVEs) and stores it whole as evidence.
Rows are written to ``epss_scores`` only for the CVEs we track (``scope``): the CVEs Shodan inferred
in the exposure lookups (10.3) and the CISA KEV entries (5.1). Any other CVE's score for that day is
still in the stored file. A new day adds rows; earlier days are never overwritten. A score outside
0-1 or a malformed CVE id is rejected into ``ingestion_errors``.

An EPSS score is about the CVE, not about a company: it is never a company's chance of a loss.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
import time
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation

import httpx
from sqlalchemy import select, text

from ..ingest.framework import InputRow, Job, RowStatus, Rule, SourceSpec, WriteContext
from ..models.vulnerabilities import CVE_PATTERN, EpssScore

BASE_URL = "https://epss.empiricalsecurity.com/"
DEFAULT_USER_AGENT = "cyber-risk-intelligence-research/0.1 (EPSS daily scores download)"
EPSS_SOURCE = SourceSpec(
    source_key="first_epss",
    name="FIRST Exploit Prediction Scoring System (EPSS)",
    source_type="vulnerability_db",
    access_method="bulk_download",
    base_url=BASE_URL,
    terms_url="https://www.first.org/epss/",
    license="Free to use (FIRST EPSS)",
    notes="Daily CSV: per CVE, probability (0-1) of exploitation activity in the next 30 days and its "
          "percentile. About the CVE, not any company; never a company's loss probability.",
)
_CVE = re.compile(CVE_PATTERN)
_HEADER = re.compile(r"model_version:(?P<model>[^,]*),score_date:(?P<when>\S+)")


class EpssUnavailable(RuntimeError):
    """The day's file could not be downloaded (not published yet, rate limit, server error)."""


def file_url(day: date | None = None) -> str:
    return BASE_URL + (f"epss_scores-{day.isoformat()}.csv.gz" if day else "epss_scores-current.csv.gz")


class EpssClient:
    def __init__(self, client: httpx.Client | None = None, timeout: float = 120.0, retries: int = 3,
                 backoff_s: float = 5.0):
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=True,
                                              headers={"User-Agent": DEFAULT_USER_AGENT})
        self.retries, self.backoff_s = retries, backoff_s

    def fetch(self, day: date | None = None) -> tuple[str, bytes]:
        """Download one day's file (default: the latest). Returns (final URL, gzipped bytes). A rate
        limit or server error is retried; a missing day (404) is not."""
        url, problem = file_url(day), "no attempt"
        for attempt in range(self.retries):
            if attempt:
                time.sleep(self.backoff_s * attempt)
            try:
                r = self._client.get(url)
            except httpx.HTTPError as exc:
                problem = f"{type(exc).__name__}: {exc}"
                continue
            if r.status_code == 200:
                return str(r.url), r.content
            problem = f"HTTP {r.status_code}"
            if r.status_code != 429 and r.status_code < 500:
                break
        raise EpssUnavailable(f"EPSS file not downloaded from {url}: {problem}")


def tracked_cves(session) -> set[str]:
    """CVEs worth keeping a daily score for: those Shodan inferred on any looked-up IP, and KEV's."""
    return set(session.scalars(text(
        "SELECT DISTINCT upper(v) FROM indexed_host_lookups, jsonb_array_elements_text(potential_vulns) AS v "
        "UNION SELECT cve_id FROM kev_entries")).all())


def _unit(field: str):
    def check(r):
        try:
            value = Decimal(r.get(field) or "")
        except InvalidOperation:
            return f"{field} {r.get(field)!r} is not a number"
        return None if value.is_finite() and 0 <= value <= 1 else f"{field} {value} is outside 0-1"
    return check


class EpssJob(Job):
    name = "first_epss"
    dataset_key = "first_epss_daily"
    media_type = "application/gzip"
    source = EPSS_SOURCE
    rules = (
        Rule("cve_id_valid", lambda r: None if _CVE.match((r.get("cve") or "").strip().upper())
             else f"cve {r.get('cve')!r} is not a CVE id", field="cve"),
        Rule("epss_in_range", _unit("epss"), field="epss"),
        Rule("percentile_in_range", _unit("percentile"), field="percentile"),
    )

    def __init__(self, scope: set[str] | None = None):
        """``scope``: the CVEs to store (None = every CVE in the file)."""
        self.scope = {c.upper() for c in scope} if scope is not None else None
        self.score_date: date | None = None
        self.scored_at: datetime | None = None
        self.model_version: str | None = None
        self.rows_in_file = 0
        self.found: set[str] = set()

    def parse(self, content: bytes):
        raw = gzip.decompress(content) if content[:2] == b"\x1f\x8b" else content
        lines = io.StringIO(raw.decode("utf-8-sig"))
        first = lines.readline()
        m = _HEADER.search(first)
        if not first.startswith("#") or not m:
            raise ValueError("not an EPSS file: no '#model_version:...,score_date:...' first line")
        self.model_version = m["model"].strip() or None
        self.scored_at = datetime.fromisoformat(m["when"].replace("+0000", "+00:00"))
        if self.scored_at.tzinfo is None:
            self.scored_at = self.scored_at.replace(tzinfo=UTC)
        self.score_date = self.scored_at.date()
        reader = csv.DictReader(lines)
        if not reader.fieldnames or not {"cve", "epss", "percentile"} <= set(reader.fieldnames):
            raise ValueError("EPSS file has no cve,epss,percentile header")
        self.rows_in_file, self.found = 0, set()
        for number, row in enumerate(reader, start=1):
            self.rows_in_file += 1
            cve = (row.get("cve") or "").strip().upper()
            if self.scope is not None and cve not in self.scope:
                continue
            self.found.add(cve)
            yield InputRow(number, cve if _CVE.match(cve) else f"row-{number}",
                           {k: (v or "").strip() for k, v in row.items() if k})

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        values = {"epss": Decimal(r["epss"]), "percentile": Decimal(r["percentile"]),
                  "model_version": self.model_version, "scored_at": self.scored_at}
        row = s.scalar(select(EpssScore).where(EpssScore.cve_id == ctx.row.key, EpssScore.score_date == self.score_date))
        if row is None:
            s.add(EpssScore(cve_id=ctx.row.key, score_date=self.score_date, **values,
                            evidence_version_id=ctx.evidence.id, ingestion_run_id=ctx.run.id))
            return "inserted"
        if all(getattr(row, k) == v for k, v in values.items()):
            return "unchanged"
        # The same day published again with different numbers: keep the newer file's values.
        for k, v in values.items():
            setattr(row, k, v)
        row.evidence_version_id, row.ingestion_run_id = ctx.evidence.id, ctx.run.id
        return "updated"
