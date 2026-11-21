"""Have I Been Pwned public breach catalogue (issue 11.1).

HIBP publishes the metadata of every breach it holds at ``/api/v3/breaches``: free, no key, licensed
CC BY 4.0 (attribute Have I Been Pwned). Each import stores the whole catalogue as evidence and inserts
or updates one ``public_breach_metadata`` row per breach. Re-importing the same catalogue changes nothing.

Only HIBP's public, unauthenticated endpoints can be called. Searching a domain's or a person's breached
addresses needs a paid key, and a domain search also needs proof that we control the domain. We control
none of the companies' domains and don't search people, so ``HibpClient`` refuses those endpoints before
any request is sent (``RestrictedEndpoint``). ``ACCESS_NOTES`` records what each capability gives and
why we don't use it; they are written to ``breach_source_access_notes`` on each import.

A breach row is metadata about a breached site. It contains no email address, account or credential.
"""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, date, datetime

import httpx
from sqlalchemy import select

from ..ingest.framework import (
    InputRow,
    Job,
    RowStatus,
    Rule,
    SourceSpec,
    WriteContext,
    ensure_source,
)
from ..models.breaches import BreachSourceAccessNote, PublicBreachMetadata

API_BASE = "https://haveibeenpwned.com/api/v3"
CATALOGUE_URL = f"{API_BASE}/breaches"
DOCS_URL = "https://haveibeenpwned.com/API/v3"
DEFAULT_USER_AGENT = "cyber-risk-intelligence-research/0.1 (public breach catalogue)"
HIBP_SOURCE = SourceSpec(
    source_key="hibp",
    name="Have I Been Pwned breach catalogue",
    source_type="breach_disclosure",
    access_method="api",
    base_url=CATALOGUE_URL,
    terms_url=DOCS_URL,
    license="CC BY 4.0 (attribute Have I Been Pwned)",
    notes="Public metadata of every breach HIBP holds. Domain and account searches need a paid key "
          "(domain search also a verified domain) and are not used.",
)

# Paths HibpClient may call: the unauthenticated catalogue endpoints only.
_PUBLIC_PATH = re.compile(r"^(breaches|latestbreach|dataclasses|breach/[A-Za-z0-9][A-Za-z0-9_\-]*)$", re.IGNORECASE)


def _note(capability, endpoint, access, used, returns, limitation) -> dict:
    return {"capability": capability, "endpoint": endpoint, "access": access, "used": used,
            "returns": returns, "limitation": limitation}


ACCESS_NOTES = (
    _note("breach_catalogue", "GET /api/v3/breaches", "public", True,
          returns=("Every breach HIBP holds: name, title, breached site's domain, breach date, added and modified "
                   "dates, account count, description, data classes and flags (verified, fabricated, sensitive, "
                   "spam list, malware, stealer log, retired)."),
          limitation=("Metadata about breached sites only. It says a site was breached, not which company's staff "
                      "or customers were in it. A company is linked only when the breached domain is one of its "
                      "known domains.")),
    _note("single_breach", "GET /api/v3/breach/{name}", "public", False,
          returns="One breach by its stable Name.",
          limitation="Same data as the catalogue, so not called separately."),
    _note("latest_breach", "GET /api/v3/latestbreach", "public", False,
          returns="The most recently added breach.",
          limitation=("Could be used to skip unchanged imports; the catalogue is small enough to download "
                      "each time.")),
    _note("domain_search", "GET /api/v3/breachedDomain/{domain}", "verified_domain", False,
          returns="Every breached email alias on a domain and the breaches each appeared in.",
          limitation=("Needs a paid HIBP key and proof that we control the domain (DNS record, email, file or "
                      "meta tag); an unverified domain gets HTTP 403. We control none of the companies' domains, "
                      "so how many company addresses were breached is unknown, not zero. The client refuses "
                      "this endpoint.")),
    _note("stealer_logs_by_domain", "GET /api/v3/stealerLogsByWebsiteDomain/{domain} (and by email domain)",
          "verified_domain", False,
          returns="Email addresses captured by info-stealer malware for a website or email domain.",
          limitation=("Needs a Pro subscription and a verified domain. Not available to us; infostealer exposure "
                      "is unknown. The client refuses this endpoint.")),
    _note("account_search", "GET /api/v3/breachedAccount/{email}", "api_key", False,
          returns="The breaches one email address appeared in.",
          limitation=("Needs a paid key, and searching individual people is outside our scope (privacy). Not "
                      "used; the client refuses this endpoint.")),
    _note("paste_search", "GET /api/v3/pasteAccount/{email}", "api_key", False,
          returns="Pastes one email address appeared in.",
          limitation="Needs a paid key and searches individuals. Not used; the client refuses this endpoint."),
)


class HibpUnavailable(RuntimeError):
    """The catalogue could not be downloaded (network error, rate limit, server error)."""


class RestrictedEndpoint(PermissionError):
    """An HIBP endpoint that needs a key or a verified domain. Never called: nothing is sent."""


class HibpClient:
    def __init__(self, client: httpx.Client | None = None, timeout: float = 60.0, retries: int = 3,
                 backoff_s: float = 5.0):
        # No API key is ever sent: only the public catalogue endpoints are used.
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=True,
                                              headers={"User-Agent": DEFAULT_USER_AGENT})
        self.retries, self.backoff_s = retries, backoff_s

    def get(self, path: str) -> bytes:
        """GET a public catalogue endpoint (``breaches``, ``breach/{name}``, ``latestbreach``,
        ``dataclasses``). Any other path, such as a domain or account search, raises
        ``RestrictedEndpoint`` without sending anything. Retries a rate limit (429, honouring
        Retry-After) or server error; raises ``HibpUnavailable`` when it still fails."""
        path = path.strip().strip("/")
        if not _PUBLIC_PATH.match(path):
            raise RestrictedEndpoint(f"HIBP /{path} is not a public catalogue endpoint: domain, stealer-log, "
                                     f"account and paste searches need a paid key (and a verified domain) "
                                     f"and are not used")
        url = f"{API_BASE}/{path}"
        problem = "no attempt"
        for attempt in range(self.retries):
            try:
                r = self._client.get(url)
            except httpx.HTTPError as exc:
                problem = f"{type(exc).__name__}: {exc}"
            else:
                if r.status_code == 200:
                    return r.content
                problem = f"HTTP {r.status_code}"
                if r.status_code != 429 and r.status_code < 500:
                    break
                if r.status_code == 429 and (r.headers.get("retry-after") or "").isdigit():
                    time.sleep(min(int(r.headers["retry-after"]), 60))
                    continue
            if attempt + 1 < self.retries:
                time.sleep(self.backoff_s * (attempt + 1))
        raise HibpUnavailable(f"HIBP {url} not downloaded: {problem}")

    def catalogue(self) -> bytes:
        return self.get("breaches")


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _day(value) -> date | None:
    try:
        return date.fromisoformat(_text(value)[:10]) if _text(value) else None
    except ValueError:
        return None


def _when(value) -> datetime | None:
    try:
        when = datetime.fromisoformat(_text(value)) if _text(value) else None
    except ValueError:
        return None
    return when.replace(tzinfo=UTC) if when and when.tzinfo is None else when


_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")


def _domain(value) -> str | None:
    d = _text(value).lower().rstrip(".")
    return d if _DOMAIN.match(d) else None


def _flag(value) -> bool | None:
    return value if isinstance(value, bool) else None


def _check_day(field: str):
    return lambda r: (None if not _text(r.get(field)) or _day(r.get(field))
                      else f"{field} {r.get(field)!r} is not a date (stored as unknown)")


def _check_domain(r):
    return (None if not _text(r.get("Domain")) or _domain(r.get("Domain"))
            else f"Domain {r.get('Domain')!r} is not a domain name (stored as unknown)")


def _check_count(r):
    v = r.get("PwnCount")
    return None if v is None or (isinstance(v, int) and not isinstance(v, bool) and v >= 0) \
        else f"PwnCount {v!r} is not a count (stored as unknown)"


class HibpBreachesJob(Job):
    name = "hibp_breaches"
    dataset_key = "hibp_breach_catalogue"
    media_type = "application/json"
    source = HIBP_SOURCE
    rules = (
        Rule("name_required", lambda r: None if _text(r.get("Name")) else "Name is missing", field="Name"),
        # Optional values: a bad one is recorded and stored as unknown (NULL), never guessed.
        Rule("breach_date_valid", _check_day("BreachDate"), severity="warning", field="BreachDate"),
        Rule("domain_valid", _check_domain, severity="warning", field="Domain"),
        Rule("pwn_count_valid", _check_count, severity="warning", field="PwnCount"),
    )

    def __init__(self):
        self._notes_written = False

    def parse(self, content: bytes):
        doc = json.loads(content)
        if not isinstance(doc, list):
            raise ValueError("not an HIBP breach catalogue: expected a list of breaches")  # noqa: TRY004
        self._notes_written = False
        for number, item in enumerate(doc, start=1):
            if not isinstance(item, dict):
                yield InputRow(number, f"row-{number}", {"__parse_error__": "breach is not an object"})
                continue
            yield InputRow(number, _text(item.get("Name")) or f"row-{number}", item)

    def _write_access_notes(self, ctx: WriteContext) -> None:
        if self._notes_written:
            return
        s = ctx.session
        src = ensure_source(s, HIBP_SOURCE)
        now = datetime.now(UTC)
        for spec in ACCESS_NOTES:
            note = s.scalar(select(BreachSourceAccessNote).where(
                BreachSourceAccessNote.source_id == src.id, BreachSourceAccessNote.capability == spec["capability"]))
            if note is None:
                note = BreachSourceAccessNote(source_id=src.id, capability=spec["capability"])
                s.add(note)
            for k, v in spec.items():
                setattr(note, k, v)
            note.documentation_url, note.checked_at = DOCS_URL, now
        self._notes_written = True

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        self._write_access_notes(ctx)
        classes = r.get("DataClasses")
        count = r.get("PwnCount")
        values = {
            "title": _text(r.get("Title")) or None,
            "domain": _domain(r.get("Domain")),
            "breach_date": _day(r.get("BreachDate")),
            "added_at": _when(r.get("AddedDate")),
            "modified_at": _when(r.get("ModifiedDate")),
            "pwn_count": count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None,
            "description": _text(r.get("Description")) or None,
            "data_classes": (sorted({_text(c) for c in classes if _text(c)}) or None)
            if isinstance(classes, list) else None,
            "is_verified": _flag(r.get("IsVerified")),
            "is_fabricated": _flag(r.get("IsFabricated")),
            "is_sensitive": _flag(r.get("IsSensitive")),
            "is_retired": _flag(r.get("IsRetired")),
            "is_spam_list": _flag(r.get("IsSpamList")),
            "is_malware": _flag(r.get("IsMalware")),
            "is_stealer_log": _flag(r.get("IsStealerLog")),
            "is_subscription_free": _flag(r.get("IsSubscriptionFree")),
            "disclosure_url": _text(r.get("DisclosureUrl")) or None,
            "attribution": _text(r.get("Attribution")) or None,
        }
        row = s.scalar(select(PublicBreachMetadata).where(PublicBreachMetadata.name == ctx.row.key))
        if row is None:
            s.add(PublicBreachMetadata(name=ctx.row.key, **values, first_seen_run_id=ctx.run.id,
                                       last_seen_run_id=ctx.run.id, evidence_version_id=ctx.evidence.id))
            return "inserted"
        row.last_seen_run_id = ctx.run.id
        if all(getattr(row, k) == v for k, v in values.items()):
            return "unchanged"
        for k, v in values.items():
            setattr(row, k, v)
        row.evidence_version_id = ctx.evidence.id  # earlier values stay in the earlier stored catalogue
        return "updated"
