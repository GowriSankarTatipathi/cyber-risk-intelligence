"""Collect certificates and hostnames for company domains from Certificate Transparency (issue 10.1).

Input is a CSV ``company_key,domain`` (``python -m cyber_risk_intelligence.ct targets`` writes one
from ``company_domains``). For each row the job searches crt.sh once for the domain and its
subdomains (current certificates only), stores the answer as evidence, and records:

* the search in ``ct_lookups`` (a failed search is ``lookup_failed``, never "no certificates");
* each certificate once in ``certificates`` (issuer + serial number), however many log entries,
  searches or domains it turns up in, with every sighting in ``certificate_observations``;
* the names it covers in ``certificate_hostnames``. Wildcards are kept and flagged. A name is tied
  to a known domain only when it is that domain or a subdomain of it.

Passive only: no host named in a certificate is resolved, contacted or scanned.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from sqlalchemy import select, tuple_

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
from ..models.certificates import (
    Certificate,
    CertificateHostname,
    CertificateObservation,
    CtLookup,
)
from .crtsh import CrtShClient, CtEntry

CT_SOURCE = SourceSpec(
    source_key="crt_sh",
    name="crt.sh Certificate Transparency log search",
    source_type="other",
    access_method="api",
    base_url="https://crt.sh/",
    notes="Public index of Certificate Transparency logs (Sectigo). Free shared service; queries are spaced out.",
)
_CHUNK = 500


def _suffixes(name: str) -> list[str]:
    labels = name.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


class CtJob(Job):
    name = "certificate_transparency"
    dataset_key = "ct_domain_targets"
    media_type = "text/csv"
    source = SourceSpec(
        source_key="project_domain_targets",
        name="Project domain target list",
        source_type="dataset",
        access_method="manual",
    )
    rules = (
        Rule("company_key_required", lambda r: None if r.get("company_key") else "company_key is empty",
             field="company_key"),
        Rule("domain_valid", lambda r: None if normalize_domain(r.get("domain", ""))
             else f"{r.get('domain')!r} is not a domain name", field="domain"),
    )

    def __init__(self, store: ObjectStore, client: CrtShClient | None = None):
        self.store = store
        self._client = client

    @property
    def client(self) -> CrtShClient:
        if self._client is None:
            self._client = CrtShClient()
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

        result = self.client.search(name)
        now = datetime.now(UTC)
        lookup = CtLookup(domain_id=domain.id, query=name, source="crt.sh", request_url=result.request_url,
                          queried_at=now, outcome=result.outcome, http_status=result.http_status,
                          message=result.message, ingestion_run_id=ctx.run.id)
        if result.outcome == "lookup_failed":
            s.add(lookup)
            s.flush()
            return "updated"
        try:
            version = record_evidence(s, self.store, source=ensure_source(s, CT_SOURCE),
                                      source_url=result.request_url, content=result.content,
                                      media_type="application/json", http_status=result.http_status,
                                      title=f"crt.sh certificates for {name}")
        except SecretDetected as exc:
            raise RowRejected("withheld", f"crt.sh answer for {name} not stored: {exc}", "domain") from None
        lookup.evidence_version_id = version.id
        lookup.entry_count = len(result.entries)
        lookup.certificate_count = len({(e.issuer_name, e.serial_number) for e in result.entries})
        s.add(lookup)
        s.flush()
        new = self._store_entries(s, lookup, version.id, result.entries, now)
        return "inserted" if new else "unchanged"

    def _store_entries(self, s, lookup: CtLookup, version_id: int, entries: list[CtEntry], now: datetime) -> int:
        by_key: dict[tuple[str, str], list[CtEntry]] = {}
        for e in entries:
            by_key.setdefault((e.issuer_name, e.serial_number), []).append(e)
        keys = list(by_key)
        existing: dict[tuple[str, str], Certificate] = {}
        for i in range(0, len(keys), _CHUNK):
            chunk = keys[i:i + _CHUNK]
            for c in s.scalars(select(Certificate).where(
                    tuple_(Certificate.issuer_name, Certificate.serial_number).in_(chunk))):
                existing[(c.issuer_name, c.serial_number)] = c
        domains = self._domains_for(s, {n.removeprefix("*.") for e in entries for n in e.names})
        new = 0
        for key, group in by_key.items():
            cert = existing.get(key)
            if cert is None:
                first = group[0]
                cert = Certificate(issuer_name=first.issuer_name, issuer_ca_id=first.issuer_ca_id,
                                   serial_number=first.serial_number, common_name=first.common_name,
                                   not_before=first.not_before, not_after=first.not_after,
                                   first_observed_at=now, last_observed_at=now)
                s.add(cert)
                s.flush()
                names = list(dict.fromkeys(n for e in group for n in e.names))
                for n in names:
                    base = n.removeprefix("*.")
                    s.add(CertificateHostname(certificate_id=cert.id, hostname=n, is_wildcard=n.startswith("*."),
                                              base_name=base, domain_id=domains.get(base)))
                new += 1
            else:
                cert.last_observed_at = max(cert.last_observed_at, now)
            for e in group:
                s.add(CertificateObservation(certificate_id=cert.id, ct_lookup_id=lookup.id,
                                             log_entry_id=e.log_entry_id, evidence_version_id=version_id,
                                             observed_at=now, source_ref=f"https://crt.sh/?id={e.log_entry_id}"))
        s.flush()
        return new

    @staticmethod
    def _domains_for(s, names: set[str]) -> dict[str, int]:
        """name -> id of the longest known domain that is the name or a parent of it."""
        wanted = {suffix for n in names for suffix in _suffixes(n)}
        known: dict[str, int] = {}
        candidates = list(wanted)
        for i in range(0, len(candidates), _CHUNK):
            for d in s.execute(select(Domain.name, Domain.id).where(Domain.name.in_(candidates[i:i + _CHUNK]))):
                known[d.name] = d.id
        out = {}
        for n in names:
            match = next((sfx for sfx in _suffixes(n) if sfx in known), None)  # longest first
            if match:
                out[n] = known[match]
        return out


def targets_csv(s) -> bytes:
    """company_key,domain for every current company domain."""
    from ..email_security.job import targets_csv as domain_targets

    return domain_targets(s)
