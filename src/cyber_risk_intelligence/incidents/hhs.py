"""HHS OCR breach portal: healthcare breaches affecting 500 or more people (issue 3.3).

HHS publishes every breach of unsecured protected health information affecting 500+ individuals at
https://ocrportal.hhs.gov/ocr/breach/ in two lists: cases "under investigation" (reported in the last 24
months) and the "archive". Each list can be exported as CSV from the page (a JSF form, so ``HhsClient``
posts the same form a browser does). One import stores the CSV as evidence and inserts or updates one
``healthcare_breach_records`` row per report; a person can also export the CSV and import it with --file.

The CSV has no record id. A report is identified by the entity's normalized name, state and submission
date; reports sharing all three get ``same_day_seq`` 1, 2, ... in list order and ``ambiguous_identity``.
A changed count, type, location, description or list is a new version of the same report: the row is
updated and the earlier values are appended to ``revisions``. Values the CSV leaves empty stay NULL.

Company links are only *candidates* found by name (``match_candidates``), kept ``unverified`` until a
source confirms or rejects them (``review_candidate``). The portal's "Breach Submission Date" is when the
entity reported to HHS, not when the breach happened.
"""

from __future__ import annotations

import csv
import io
import re
import time
from collections import Counter
from datetime import UTC, date, datetime

import httpx
from sqlalchemy import select

from ..ingest.framework import InputRow, Job, RowStatus, Rule, SourceSpec, WriteContext
from ..models import Company, CompanyAlias, LegalEntity
from ..models.incidents import HealthcareBreachCompanyCandidate, HealthcareBreachRecord
from ..normalize import normalize_name

PORTAL = "https://ocrportal.hhs.gov/ocr/breach/"
DEFAULT_USER_AGENT = "cyber-risk-intelligence-research/0.1 (HHS breach report download)"
HHS_SOURCE = SourceSpec(
    source_key="hhs_ocr_breach_portal",
    name="HHS OCR breach portal (breaches affecting 500 or more individuals)",
    source_type="regulator",
    access_method="web_page",
    base_url=PORTAL + "breach_report.jsf",
    terms_url="https://www.hhs.gov/web/policies-and-standards/hhs-web-policies/index.html",
    license="US government work (public domain)",
    notes="Published under HITECH Act section 13402(e)(4). CSV export of the 'under investigation' and "
          "'archive' lists. Submission date = reported to HHS, not the breach date. No record ids.",
)
LISTS = {"investigation": ("under_investigation", 0), "archive": ("archived", 1)}
# CSV column order (the export's header names two columns as internal JSF ids, so map by position).
COLUMNS = ("entity_name", "state", "entity_type", "individuals_affected", "submitted_on", "breach_type",
           "location", "business_associate_present", "web_description")
_TRACKED = ("entity_name", "state", "entity_type", "individuals_affected", "breach_types", "locations",
            "business_associate_present", "web_description", "list_status")


class HhsUnavailable(RuntimeError):
    """The portal could not be read or the export failed."""


class HhsClient:
    def __init__(self, client: httpx.Client | None = None, timeout: float = 180.0, retries: int = 3,
                 backoff_s: float = 10.0):
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=True,
                                              headers={"User-Agent": DEFAULT_USER_AGENT})
        self.retries, self.backoff_s = retries, backoff_s

    @staticmethod
    def _state(html: str) -> str:
        m = re.search(r'name="javax\.faces\.ViewState"[^>]*value="([^"]+)"', html)
        if not m:
            raise HhsUnavailable("portal page has no JSF view state (layout changed?)")
        return m[1]

    @staticmethod
    def _link(html: str, label_pattern: str, skip_tags: bool = True) -> str:
        between = r"\s*(?:<[^>]+>\s*)*" if skip_tags else r"\s*"
        m = re.search(r"\{'(ocrForm:[\w:]+)':'ocrForm:[\w:]+'\},''\);return false\"[^>]*>" + between
                      + label_pattern, html)
        if not m:
            raise HhsUnavailable(f"portal link {label_pattern!r} not found (layout changed?)")
        return m[1]

    def _post(self, url: str, data: dict, **kw) -> httpx.Response:
        if kw.pop("multipart", True):
            return self._client.post(url, files={k: (None, v) for k, v in data.items()}, **kw)
        return self._client.post(url, data=data, **kw)

    def download(self, which: str) -> tuple[str, bytes]:
        """Export one list ('investigation' or 'archive') as CSV, as the page's CSV button does."""
        problem = "no attempt"
        for attempt in range(self.retries):
            if attempt:
                time.sleep(self.backoff_s * attempt)
            try:
                return self._download(which)
            except (httpx.HTTPError, HhsUnavailable) as exc:
                problem = f"{type(exc).__name__}: {exc}"
        raise HhsUnavailable(f"HHS {which} list not downloaded: {problem}")

    def _download(self, which: str) -> tuple[str, bytes]:
        _, tab_index = LISTS[which]
        front = self._client.get(PORTAL + "breach_frontpage.jsf")
        front.raise_for_status()
        view = self._link(front.text, "View HIPAA Breach Reports")
        page = self._post(PORTAL + "breach_frontpage.jsf",
                          {"ocrForm": "ocrForm", "javax.faces.ViewState": self._state(front.text), view: view})
        page.raise_for_status()
        report_url = str(page.url)
        state = self._state(page.text)
        tab = re.search(r'PrimeFaces\.cw\("TabView","[^"]+",\{id:"([^"]+)"', page.text)
        html = page.text
        if tab_index:
            if not tab:
                raise HhsUnavailable("list tabs not found (layout changed?)")
            t = tab[1]
            ajax = self._post(report_url, {
                "javax.faces.partial.ajax": "true", "javax.faces.source": t, "javax.faces.partial.execute": t,
                "javax.faces.partial.render": "ocrForm:breachReports ocrForm:results",
                "javax.faces.behavior.event": "tabChange", "javax.faces.partial.event": "tabChange",
                f"{t}_newTab": f"{t}:archiveTab", f"{t}_tabindex": str(tab_index), f"{t}_activeIndex": str(tab_index),
                "ocrForm": "ocrForm", "javax.faces.ViewState": state},
                multipart=False, headers={"Faces-Request": "partial/ajax", "X-Requested-With": "XMLHttpRequest"})
            ajax.raise_for_status()
            html = ajax.text
        export = self._link(html, r'<img[^>]*title=\\?"Export as CSV', skip_tags=False)
        data = {"ocrForm": "ocrForm", "javax.faces.ViewState": state, export: export}
        if tab:
            data[f"{tab[1]}_activeIndex"] = str(tab_index)
        r = self._post(report_url, data)
        r.raise_for_status()
        if "csv" not in (r.headers.get("content-type") or "") or not r.content.strip():
            raise HhsUnavailable(f"export did not return a CSV (content-type {r.headers.get('content-type')!r})")
        return report_url, r.content


def _text(v) -> str:
    return re.sub(r"\s+", " ", v).strip() if isinstance(v, str) else ""


def _day(v) -> date | None:
    m = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", _text(v))
    try:
        return date(int(m[3]), int(m[1]), int(m[2])) if m else None
    except ValueError:
        return None


def _count(v) -> int | None:
    t = _text(v).replace(",", "")
    return int(t) if t.isdigit() else None


def _split(v) -> list[str] | None:
    items = sorted({x.strip() for x in _text(v).split(",") if x.strip()})
    return items or None


def _yes_no(v) -> bool | None:
    return {"yes": True, "no": False}.get(_text(v).lower())


class HhsBreachJob(Job):
    name = "hhs_breach_reports"
    dataset_key = "hhs_breach_reports"
    media_type = "text/csv"
    source = HHS_SOURCE
    rules = (
        Rule("entity_name_required", lambda r: None if _text(r.get("entity_name")) else "covered entity name is empty",
             field="entity_name"),
        Rule("submitted_on_valid", lambda r: None if _day(r.get("submitted_on"))
             else f"submission date {r.get('submitted_on')!r} is not MM/DD/YYYY", field="submitted_on"),
        Rule("individuals_valid", lambda r: None if not _text(r.get("individuals_affected"))
             or _count(r.get("individuals_affected")) is not None
             else f"individuals affected {r.get('individuals_affected')!r} is not a count (stored as unknown)",
             severity="warning", field="individuals_affected"),
    )

    def __init__(self, which: str):
        if which not in LISTS:
            raise ValueError(f"list must be one of {', '.join(LISTS)}")
        self.list_status = LISTS[which][0]
        self.changes: Counter = Counter()

    def parse(self, content: bytes):
        reader = csv.reader(io.StringIO(content.decode("utf-8-sig", errors="replace")))
        header = next(reader, None)
        if not header or len(header) < len(COLUMNS) or "State" not in header or "Individuals Affected" not in header:
            raise ValueError("not an HHS breach report CSV (expected State, Individuals Affected ... columns)")
        groups: Counter = Counter()
        rows = []
        for number, raw in enumerate(reader, start=1):
            data = dict(zip(COLUMNS, raw, strict=False))
            base = f"{normalize_name(_text(data.get('entity_name')))}|{_text(data.get('state')).upper()}|" \
                   f"{_day(data.get('submitted_on')) or _text(data.get('submitted_on'))}"
            groups[base] += 1
            rows.append((number, base, groups[base], data))
        for number, base, seq, data in rows:
            data["same_day_seq"], data["ambiguous_identity"] = seq, groups[base] > 1
            yield InputRow(number, f"{base}|{seq}", data)

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        values = {
            "entity_name": _text(r["entity_name"]),
            "state": _text(r.get("state")).upper() or None,
            "entity_type": _text(r.get("entity_type")) or None,
            "individuals_affected": _count(r.get("individuals_affected")),
            "breach_types": _split(r.get("breach_type")),
            "locations": _split(r.get("location")),
            "business_associate_present": _yes_no(r.get("business_associate_present")),
            "web_description": _text(r.get("web_description")) or None,
            "list_status": self.list_status,
        }
        row = s.scalar(select(HealthcareBreachRecord).where(HealthcareBreachRecord.incident_key == ctx.row.key))
        if row is None:
            s.add(HealthcareBreachRecord(
                incident_key=ctx.row.key, normalized_name=normalize_name(values["entity_name"]),
                submitted_on=_day(r["submitted_on"]), same_day_seq=r["same_day_seq"],
                ambiguous_identity=r["ambiguous_identity"], **values, first_seen_run_id=ctx.run.id,
                last_seen_run_id=ctx.run.id, evidence_version_id=ctx.evidence.id))
            return "inserted"
        row.last_seen_run_id = ctx.run.id
        row.ambiguous_identity = row.ambiguous_identity or r["ambiguous_identity"]
        changed = [k for k in _TRACKED if getattr(row, k) != values[k]]
        if not changed:
            return "unchanged"
        earlier = {k: getattr(row, k) for k in changed}
        row.revisions = [*(row.revisions or []), {**earlier, "replaced_at": datetime.now(UTC).isoformat(),
                                                  "evidence_version_id": row.evidence_version_id}]
        for k, v in values.items():
            setattr(row, k, v)
        row.evidence_version_id = ctx.evidence.id
        self.changes.update(changed)
        return "updated"


# After a one-word company name ("walmart", "target"), a prefix match needs one of these next ("Walmart Stores",
# "Target Corporation Health Plan"); otherwise "Southern Illinois Dermatology" or "Apple Valley Clinic" would match.
_CORPORATE_NEXT = {"corporation", "corp", "inc", "co", "company", "group", "stores", "associates", "employee",
                   "employees", "benefit", "benefits", "welfare", "llc", "ltd", "plc", "international", "pharmacy",
                   "insurance", "health plan"}


def _prefix_ok(record_name: str, company_name: str) -> bool:
    if not record_name.startswith(company_name + " "):
        return False
    if " " in company_name:
        return True
    rest = record_name[len(company_name) + 1:]
    return rest.split(" ", 1)[0] in _CORPORATE_NEXT or rest.startswith("health plan")


def match_candidates(session) -> int:
    """Add name-only company candidates for breach records (idempotent). Returns how many were added."""
    names: list[tuple[int, str, str]] = []  # (company_id, normalized name, basis)
    for cid, n in session.execute(select(Company.id, Company.normalized_name)):
        names.append((cid, n, "exact_name"))
    for cid, n in session.execute(select(LegalEntity.company_id, LegalEntity.normalized_name)):
        names.append((cid, n, "exact_name"))
    for cid, n in session.execute(select(CompanyAlias.company_id, CompanyAlias.normalized_alias)):
        names.append((cid, n, "exact_alias"))
    exact: dict[str, list[tuple[int, str]]] = {}
    for cid, n, basis in names:
        if n:
            exact.setdefault(n, []).append((cid, basis))
    prefixes = [(cid, n) for cid, n, _ in names if n and len(n.replace(" ", "")) >= 4]
    existing = set(session.execute(select(HealthcareBreachCompanyCandidate.breach_record_id,
                                          HealthcareBreachCompanyCandidate.company_id)).all())
    added, now = 0, datetime.now(UTC)
    for rid, rname in session.execute(select(HealthcareBreachRecord.id, HealthcareBreachRecord.normalized_name)):
        found: dict[int, tuple[str, str]] = {}
        for cid, basis in exact.get(rname, []):
            found.setdefault(cid, (basis, rname))
        for cid, n in prefixes:
            if cid not in found and _prefix_ok(rname, n):
                found[cid] = ("name_prefix", n)
        for cid, (basis, matched) in found.items():
            if (rid, cid) not in existing:
                session.add(HealthcareBreachCompanyCandidate(breach_record_id=rid, company_id=cid, match_basis=basis,
                                                             matched_name=matched, found_at=now))
                added += 1
    session.commit()
    return added


def review_candidate(session, candidate_id: int, status: str, source_url: str, note: str | None = None):
    """Confirm or reject a candidate link; a source that supports the decision is required."""
    if status not in ("confirmed", "rejected"):
        raise ValueError("status must be confirmed or rejected")
    if not (source_url or "").startswith(("http://", "https://")):
        raise ValueError("a source URL supporting the decision is required")
    cand = session.get(HealthcareBreachCompanyCandidate, candidate_id)
    if cand is None:
        raise ValueError(f"no candidate {candidate_id}")
    cand.status, cand.review_source_url, cand.review_note = status, source_url, note
    cand.reviewed_at = datetime.now(UTC)
    session.commit()
    return cand
