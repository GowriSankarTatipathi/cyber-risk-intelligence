"""Aggregate infostealer exposure per company domain from Hudson Rock's free domain search (issue 11.2).

Hudson Rock (hudsonrock.com/free-tools) offers a free, keyless domain search over its database of
computers infected by infostealer malware. For a domain it reports how many infected computers had
saved logins for the company's own login pages (``employees``), its customer login pages (``users``)
and third parties, the dates of the latest infections, the malware families and a password-strength
breakdown. It returns counts and login-page URLs, never passwords or email addresses.

What we keep is a redacted summary: the counts, dates, family and strength tallies, and the *host names*
of employee and customer login pages with their counts (``vpn.acme.com``: 12). URL paths, queries and
anything that looks like an address are dropped before storage, and the summary is what is stored as
evidence. Requests go one domain at a time with a pause, like a person using the free tool.

Hudson Rock's terms of service grant no licence to reuse its content without permission, so this is
for internal underwriting research: counts are kept with their source and date, and not republished.

A rate limit or error is ``lookup_failed`` with no counts (never zero). A domain with nothing in the
source is ``none_reported``: the source has no infection for it, which is not proof there was none.
"""

from __future__ import annotations

import csv
import io
import json
import time
from collections import Counter
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select

from ..domains import normalize_domain
from ..evidence import SecretDetected, record_evidence
from ..evidence.store import ObjectStore
from ..ingest.framework import (
    InputRow,
    Job,
    RowRejected,
    RowStatus,
    Rule,
    SourceSpec,
    WriteContext,
    ensure_source,
)
from ..models import Company, CompanyDomain, Domain
from ..models.breaches import AggregateExposureObservation

PROVIDER = "hudson_rock"
SEARCH_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
DEFAULT_USER_AGENT = "cyber-risk-intelligence-research/0.1 (aggregate infostealer counts per domain)"
HUDSON_ROCK_SOURCE = SourceSpec(
    source_key="hudson_rock_osint",
    name="Hudson Rock free infostealer domain search",
    source_type="breach_disclosure",
    access_method="api",
    base_url=SEARCH_URL,
    terms_url="https://www.hudsonrock.com/tos",
    license="Hudson Rock terms of service: no licence granted to reuse content; internal research use only",
    notes="Free, keyless domain search (hudsonrock.com/free-tools). Aggregate counts of infostealer-infected "
          "computers with saved logins for a domain; we store counts and login host names only.",
)
_HINTS = (("remote_access", ("vpn", "remote", "citrix", "gateway", "rdweb", "anyconnect", "+cscoe+", "globalprotect")),
          ("identity", ("adfs", "sso", "okta", "login.microsoftonline", "auth", "idp", "saml", "ping")),
          ("mail", ("mail", "owa", "outlook", "exchange")))
MAX_HOSTS = 50


class InfostealerClient:
    def __init__(self, client: httpx.Client | None = None, timeout: float = 30.0, pause: float = 2.0,
                 retries: int = 3, backoff_s: float = 10.0):
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=True,
                                              headers={"User-Agent": DEFAULT_USER_AGENT})
        self.pause, self.retries, self.backoff_s = pause, retries, backoff_s
        self._last = 0.0

    def domain(self, name: str) -> tuple[str, dict | None, str | None]:
        """(url, answer, problem). ``answer`` is None when the lookup failed; ``problem`` says why."""
        url = f"{SEARCH_URL}?domain={name}"
        problem = "no attempt"
        for attempt in range(self.retries):
            wait = self.pause - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            try:
                r = self._client.get(SEARCH_URL, params={"domain": name})
            except httpx.HTTPError as exc:
                problem = f"{type(exc).__name__}: {exc}"
            else:
                if r.status_code == 200:
                    try:
                        doc = r.json()
                    except ValueError:
                        return url, None, "answer is not JSON"
                    if not isinstance(doc, dict) or not isinstance(doc.get("total"), int):
                        return url, None, "unexpected answer (no total)"
                    return url, doc, None
                problem = f"HTTP {r.status_code}"
                if r.status_code != 429 and r.status_code < 500:
                    return url, None, problem
            finally:
                self._last = time.monotonic()
            if attempt + 1 < self.retries:
                time.sleep(self.backoff_s * (attempt + 1))
        return url, None, f"{problem} after {self.retries} attempts"


def _count(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _when(value) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        when = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _host(url) -> str | None:
    if not isinstance(url, str) or "@" in url:
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return normalize_domain(parts.hostname)


def hint(host: str) -> str | None:
    h = host.lower()
    return next((kind for kind, words in _HINTS if any(w in h for w in words)), None)


def _hosts(entries) -> list[dict]:
    tally: Counter = Counter()
    for e in entries if isinstance(entries, list) else []:
        if isinstance(e, dict) and (host := _host(e.get("url"))):
            tally[host] += _count(e.get("occurrence")) or 0
    return [{"host": h, "occurrence": n, "hint": hint(h)} for h, n in
            sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_HOSTS]]


def _strength(block) -> dict | None:
    if not isinstance(block, dict):
        return None
    out = {"total": _count(block.get("totalPass"))}
    for level in ("too_weak", "weak", "medium", "strong"):
        out[level] = _count((block.get(level) or {}).get("qty")) if isinstance(block.get(level), dict) else None
    return out if any(v is not None for v in out.values()) else None


def _families(block) -> dict | None:
    if not isinstance(block, dict):
        return None
    out = {str(k): v for k, v in sorted(block.items()) if k != "total" and _count(v) is not None and "@" not in str(k)}
    return out or None


def _third_parties(entries) -> list[dict] | None:
    out = []
    for e in entries if isinstance(entries, list) else []:
        raw = str(e.get("domain") or "") if isinstance(e, dict) else ""
        if raw and "@" not in raw and (d := normalize_domain(raw)):
            out.append({"domain": d, "occurrence": _count(e.get("occurrence"))})
    return out[:MAX_HOSTS] or None


def summarize(doc: dict) -> dict:
    """The redacted summary we keep (and store as evidence): counts, dates, tallies and host names."""
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
    return {
        "total": _count(doc.get("total")),
        "employees": _count(doc.get("employees")),
        "users": _count(doc.get("users")),
        "third_parties": _count(doc.get("third_parties")),
        "last_employee_compromised": doc.get("last_employee_compromised") if _when(doc.get("last_employee_compromised")) else None,
        "last_user_compromised": doc.get("last_user_compromised") if _when(doc.get("last_user_compromised")) else None,
        "stealer_families": _families(doc.get("stealerFamilies")),
        "employee_passwords": _strength(doc.get("employeePasswords")),
        "user_passwords": _strength(doc.get("userPasswords")),
        "employee_login_hosts": _hosts(data.get("employees_urls")) or None,
        "user_login_hosts": _hosts(data.get("clients_urls")) or None,
        "third_party_domains": _third_parties(doc.get("thirdPartyDomains")),
        "source_dataset_size": _count(doc.get("totalStealers")),
    }


def targets_csv(session) -> bytes:
    """company_key,domain for every current company domain."""
    from ..email_security.job import targets_csv as domains_csv

    return domains_csv(session)


class InfostealerJob(Job):
    name = "hudson_rock_infostealers"
    dataset_key = "infostealer_targets"
    media_type = "text/csv"
    source = SourceSpec(source_key="project_domain_targets", name="Project domain target list",
                        source_type="dataset", access_method="manual")
    rules = (
        Rule("company_key_required", lambda r: None if r.get("company_key") else "company_key is empty",
             field="company_key"),
        Rule("domain_valid", lambda r: None if normalize_domain(r.get("domain", ""))
             else f"{r.get('domain')!r} is not a domain name", field="domain"),
    )

    def __init__(self, store: ObjectStore, client: InfostealerClient | None = None):
        self.store = store
        self._client = client
        self.tally: Counter = Counter()

    @property
    def client(self) -> InfostealerClient:
        if self._client is None:
            self._client = InfostealerClient()
        return self._client

    def parse(self, content: bytes):
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        if not reader.fieldnames or not {"company_key", "domain"} <= set(reader.fieldnames):
            raise ValueError("target CSV needs company_key and domain columns")
        for number, raw in enumerate(reader, start=1):
            data = {k.strip(): (v or "").strip() for k, v in raw.items() if k}
            yield InputRow(number, f"{data.get('company_key')}|{normalize_domain(data.get('domain', ''))}", data)

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        company = s.scalar(select(Company).where(Company.company_key == r["company_key"]))
        if company is None:
            raise RowRejected("unknown_company", f"no company with key {r['company_key']!r}", "company_key")
        name = normalize_domain(r["domain"])
        domain = s.scalar(select(Domain).join(CompanyDomain, CompanyDomain.domain_id == Domain.id).where(
            Domain.name == name, CompanyDomain.company_id == company.id))
        if domain is None:
            raise RowRejected("domain_not_linked", f"{name} is not a known domain of {r['company_key']}; "
                                                   "import it with company-domains first", "domain")
        url, doc, problem = self.client.domain(name)
        now = datetime.now(UTC)
        base = {"company_id": company.id, "domain_id": domain.id, "provider": PROVIDER, "observed_at": now,
                "ingestion_run_id": ctx.run.id}
        if doc is None:
            self.tally["lookup_failed"] += 1
            s.add(AggregateExposureObservation(**base, outcome="lookup_failed", message=problem))
            return "updated"
        summary = summarize(doc)
        try:
            version = record_evidence(s, self.store, source=ensure_source(s, HUDSON_ROCK_SOURCE), source_url=url,
                                      content=json.dumps(summary, sort_keys=True, indent=1).encode(),
                                      media_type="application/json", http_status=200,
                                      title=f"Hudson Rock infostealer summary for {name} (redacted)")
        except SecretDetected as exc:
            raise RowRejected("withheld", f"Hudson Rock summary for {name} not stored: {exc}", "domain") from None
        found = any(summary[k] for k in ("total", "employees", "users", "third_parties"))
        outcome = "found" if found else "none_reported"
        self.tally[outcome] += 1
        previous = s.scalar(select(AggregateExposureObservation.evidence_version_id).where(
            AggregateExposureObservation.domain_id == domain.id, AggregateExposureObservation.provider == PROVIDER,
            AggregateExposureObservation.evidence_version_id.is_not(None))
            .order_by(AggregateExposureObservation.id.desc()).limit(1))
        s.add(AggregateExposureObservation(
            **base, outcome=outcome, total_infections=summary["total"], employees=summary["employees"],
            users=summary["users"], third_parties=summary["third_parties"],
            last_employee_infection_at=_when(summary["last_employee_compromised"]),
            last_user_infection_at=_when(summary["last_user_compromised"]),
            stealer_families=summary["stealer_families"], employee_password_strength=summary["employee_passwords"],
            user_password_strength=summary["user_passwords"], employee_login_hosts=summary["employee_login_hosts"],
            third_party_domains=summary["third_party_domains"], source_dataset_size=summary["source_dataset_size"],
            evidence_version_id=version.id))
        return "unchanged" if previous == version.id else "inserted"
