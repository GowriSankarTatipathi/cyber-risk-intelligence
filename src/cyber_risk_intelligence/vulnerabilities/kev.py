"""CISA Known Exploited Vulnerabilities catalog (issue 5.1).

CISA publishes the whole catalog as one JSON file (free, no key, public domain), with a version label,
a release time and one entry per CVE known to have been exploited in the wild. Each import stores the
whole file as evidence, records the release, and inserts or updates one ``kev_entries`` row per CVE.
Re-importing the same file changes nothing. An entry with a malformed CVE id or a missing required
field (vendor, product, date added, required action) is rejected and recorded in
``ingestion_errors``; the rest of the catalog is still imported.

Each import also records changes against the previous release in ``kev_change_events`` (issue 12.1):
a CVE ``added`` to the catalog, ``updated`` (which fields, old and new values) or, via
``record_removals`` after the import, ``removed``. An unchanged catalog adds no event; the entries of
the very first catalog imported are marked ``baseline`` so alerts can skip them.

KEV says a CVE was exploited somewhere. It says nothing about whether a given company is affected.
"""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, date, datetime

import httpx
from sqlalchemy import select

from ..ingest.framework import InputRow, Job, RowStatus, Rule, SourceSpec, WriteContext
from ..models.vulnerabilities import (
    CVE_PATTERN,
    RANSOMWARE_USE,
    KevCatalogRelease,
    KevChangeEvent,
    KevEntry,
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_USER_AGENT = "cyber-risk-intelligence-research/0.1 (KEV catalog download)"
KEV_SOURCE = SourceSpec(
    source_key="cisa_kev",
    name="CISA Known Exploited Vulnerabilities catalog",
    source_type="vulnerability_db",
    access_method="bulk_download",
    base_url=KEV_URL,
    terms_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    license="US government work (public domain)",
    notes="Whole catalog as one JSON file; one entry per CVE with confirmed exploitation in the wild. "
          "Says a CVE was exploited somewhere, not that a company is affected.",
)
_CVE = re.compile(CVE_PATTERN)


class KevUnavailable(RuntimeError):
    """The catalog could not be downloaded (network error, rate limit, server error)."""


class KevClient:
    def __init__(self, client: httpx.Client | None = None, timeout: float = 60.0, retries: int = 3,
                 backoff_s: float = 5.0):
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=True,
                                              headers={"User-Agent": DEFAULT_USER_AGENT})
        self.retries, self.backoff_s = retries, backoff_s

    def fetch(self, url: str = KEV_URL) -> bytes:
        """Download the catalog. Retries a rate limit (429) or server error; raises ``KevUnavailable``
        when it still fails, so nothing is imported from a partial or missing download."""
        problem = "no attempt"
        for attempt in range(self.retries):
            if attempt:
                time.sleep(self.backoff_s * attempt)
            try:
                r = self._client.get(url)
            except httpx.HTTPError as exc:
                problem = f"{type(exc).__name__}: {exc}"
                continue
            if r.status_code == 200:
                return r.content
            problem = f"HTTP {r.status_code}"
            if r.status_code != 429 and r.status_code < 500:
                break
        raise KevUnavailable(f"KEV catalog not downloaded from {url}: {problem}")


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _required(field: str):
    return lambda r: None if _text(r.get(field)) else f"{field} is missing"


def _date_check(field: str, required: bool):
    def check(r):
        value = _text(r.get(field))
        if not value:
            return f"{field} is missing" if required else None
        try:
            date.fromisoformat(value)
        except ValueError:
            return f"{field} {value!r} is not a date"
        return None
    return check


def _optional_date(value) -> date | None:
    try:
        return date.fromisoformat(_text(value)) if _text(value) else None
    except ValueError:
        return None


def _released(value: str) -> datetime:
    when = datetime.fromisoformat(value.strip())
    return when if when.tzinfo else when.replace(tzinfo=UTC)


class KevJob(Job):
    name = "cisa_kev"
    dataset_key = "cisa_kev_catalog"
    media_type = "application/json"
    source = KEV_SOURCE
    rules = (
        Rule("cve_id_valid", lambda r: None if _CVE.match(_text(r.get("cveID")).upper())
             else f"cveID {r.get('cveID')!r} is not a CVE id", field="cveID"),
        Rule("vendor_required", _required("vendorProject"), field="vendorProject"),
        Rule("product_required", _required("product"), field="product"),
        Rule("date_added_valid", _date_check("dateAdded", required=True), field="dateAdded"),
        Rule("required_action_required", _required("requiredAction"), field="requiredAction"),
        # Optional fields: a bad value is recorded and stored as unknown (NULL), not guessed.
        Rule("due_date_valid", _date_check("dueDate", required=False), severity="warning", field="dueDate"),
        Rule("ransomware_use_known",
             lambda r: None if _text(r.get("knownRansomwareCampaignUse")) in ("", *RANSOMWARE_USE)
             else f"knownRansomwareCampaignUse {r.get('knownRansomwareCampaignUse')!r} is not Known/Unknown",
             severity="warning", field="knownRansomwareCampaignUse"),
    )

    def __init__(self):
        self.catalog: dict = {}
        self._release_id: int | None = None
        self._baseline = False
        self.changes = {"added": 0, "updated": 0}

    def parse(self, content: bytes):
        doc = json.loads(content)
        if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
            raise ValueError("not a KEV catalog: no 'vulnerabilities' list")  # noqa: TRY004 - bad input, not a bug
        version, released = _text(doc.get("catalogVersion")), _text(doc.get("dateReleased"))
        if not version or not released:
            raise ValueError("KEV catalog has no catalogVersion or dateReleased")
        self.catalog = {"catalog_version": version, "date_released": _released(released),
                        "entry_count": doc.get("count") if isinstance(doc.get("count"), int) else None}
        self._release_id = None
        for number, item in enumerate(doc["vulnerabilities"], start=1):
            if not isinstance(item, dict):
                yield InputRow(number, f"row-{number}", {"__parse_error__": "entry is not an object"})
                continue
            cve = _text(item.get("cveID")).upper()
            yield InputRow(number, cve if _CVE.match(cve) else f"row-{number}", item)

    def _release(self, ctx: WriteContext) -> KevCatalogRelease:
        s = ctx.session
        if self._release_id is not None:
            return s.get(KevCatalogRelease, self._release_id)
        rel = s.scalar(select(KevCatalogRelease).where(
            KevCatalogRelease.catalog_version == self.catalog["catalog_version"],
            KevCatalogRelease.date_released == self.catalog["date_released"]))
        if rel is None:
            self._baseline = s.scalar(select(KevCatalogRelease.id).limit(1)) is None
            rel = KevCatalogRelease(**self.catalog, evidence_version_id=ctx.evidence.id, ingestion_run_id=ctx.run.id,
                                    retrieved_at=datetime.now(UTC))
            s.add(rel)
            s.flush()
        self._release_id = rel.id
        return rel

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        release = self._release(ctx)
        cwes = sorted({_text(c) for c in r.get("cwes") or [] if _text(c)}) if isinstance(r.get("cwes"), list) else []
        ransomware = _text(r.get("knownRansomwareCampaignUse"))
        values = {
            "vendor_project": _text(r["vendorProject"]),
            "product": _text(r["product"]),
            "vulnerability_name": _text(r.get("vulnerabilityName")) or None,
            "short_description": _text(r.get("shortDescription")) or None,
            "date_added": date.fromisoformat(_text(r["dateAdded"])),
            "required_action": _text(r["requiredAction"]),
            "due_date": _optional_date(r.get("dueDate")),
            "known_ransomware_use": ransomware if ransomware in RANSOMWARE_USE else None,
            "forensic_triage": _text(r.get("forensicTriage")) or None,
            "notes": _text(r.get("notes")) or None,
            "cwes": cwes or None,
        }
        entry = s.scalar(select(KevEntry).where(KevEntry.cve_id == ctx.row.key))
        if entry is None:
            entry = KevEntry(cve_id=ctx.row.key, **values, first_seen_release_id=release.id,
                             last_seen_release_id=release.id, evidence_version_id=ctx.evidence.id)
            s.add(entry)
            s.flush()
            self._event(ctx, entry, release, "added", baseline=self._baseline)
            return "inserted"
        last = s.get(KevCatalogRelease, entry.last_seen_release_id)
        if last.date_released > release.date_released:  # an older catalog file: keep the newer values
            if s.get(KevCatalogRelease, entry.first_seen_release_id).date_released > release.date_released:
                entry.first_seen_release_id = release.id
            return "unchanged"
        was_removed = entry.last_seen_release_id != release.id and s.scalar(
            select(KevChangeEvent.id).where(KevChangeEvent.kev_entry_id == entry.id,
                                            KevChangeEvent.change_type == "removed",
                                            KevChangeEvent.release_id == entry.last_seen_release_id)) is not None
        entry.last_seen_release_id = release.id
        changed = [k for k, v in values.items() if getattr(entry, k) != v]
        if was_removed:  # back in the catalog after CISA removed it
            self._event(ctx, entry, release, "added")
        if not changed:
            return "updated" if was_removed else "unchanged"
        before = {k: _jsonable(getattr(entry, k)) for k in changed}
        for k, v in values.items():
            setattr(entry, k, v)
        entry.evidence_version_id = ctx.evidence.id
        self._event(ctx, entry, release, "updated", fields=changed, before=before,
                    after={k: _jsonable(values[k]) for k in changed})
        return "updated"

    def _event(self, ctx: WriteContext, entry: KevEntry, release: KevCatalogRelease, change_type: str, *,
               baseline: bool = False, fields=None, before=None, after=None) -> None:
        ctx.session.add(KevChangeEvent(
            cve_id=entry.cve_id, kev_entry_id=entry.id, release_id=release.id, change_type=change_type,
            baseline=baseline, changed_fields=fields, previous_values=before, new_values=after,
            date_added=entry.date_added, required_action=entry.required_action, detected_at=datetime.now(UTC),
            evidence_version_id=ctx.evidence.id, ingestion_run_id=ctx.run.id))
        if not baseline:
            self.changes[change_type] = self.changes.get(change_type, 0) + 1


def _jsonable(value):
    return value.isoformat() if isinstance(value, date) else value


def record_removals(session, run_id: int | None = None) -> int:
    """After importing the newest release: add a ``removed`` event for each entry that was in the
    previous release we hold but is not in the newest one (once per entry and release). Returns how many."""
    releases = session.execute(select(KevCatalogRelease).order_by(
        KevCatalogRelease.date_released.desc(), KevCatalogRelease.id.desc()).limit(2)).scalars().all()
    if len(releases) < 2:
        return 0
    newest, previous = releases
    gone = session.scalars(select(KevEntry).where(KevEntry.last_seen_release_id == previous.id)).all()
    added = 0
    for entry in gone:
        exists = session.scalar(select(KevChangeEvent.id).where(
            KevChangeEvent.kev_entry_id == entry.id, KevChangeEvent.change_type == "removed",
            KevChangeEvent.release_id == previous.id))
        if exists is None:
            # release_id = the last release it was in; the newest release (without it) is the evidence
            session.add(KevChangeEvent(
                cve_id=entry.cve_id, kev_entry_id=entry.id, release_id=previous.id, change_type="removed",
                date_added=entry.date_added, required_action=entry.required_action, detected_at=datetime.now(UTC),
                evidence_version_id=newest.evidence_version_id, ingestion_run_id=run_id))
            added += 1
    session.commit()
    return added
