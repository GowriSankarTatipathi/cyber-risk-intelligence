"""Collect certificates and hostnames for company domains from Certificate Transparency (issue 10.1).

Input is a CSV ``company_key,domain`` (``python -m cyber_risk_intelligence.ct targets`` writes one
from ``company_domains``). For each row the job searches Cert Spotter for the domain and its
subdomains (current certificates only, every page), falling back to crt.sh if Cert Spotter can't
answer, stores the answer as evidence, and records:

* the search in ``ct_lookups`` (a failed search is ``lookup_failed``, never "no certificates");
* each certificate once in ``certificates`` (TBS hash or issuer + serial number), however many entries,
  searches or domains it turns up in, with every sighting in ``certificate_observations``;
* the names it covers in ``certificate_hostnames``. Wildcards are kept and flagged. A name is tied
  to a known domain only when it is that domain or a subdomain of it.

Passive only: no host named in a certificate is resolved, contacted or scanned.
"""

from __future__ import annotations

import csv
import gzip
import io
from datetime import UTC, datetime

from sqlalchemy import insert, select, tuple_, update

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
from .certspotter import CertSpotterClient
from .crtsh import CrtShClient
from .entries import CtEntry, CtLookupResult

CT_SOURCES = {
    "certspotter": SourceSpec(
        source_key="certspotter",
        name="Cert Spotter (SSLMate) Certificate Transparency search API",
        source_type="other",
        access_method="api",
        base_url="https://api.certspotter.com/v1/issuances",
        notes="Public CT search API; current certificates, 100 per page. Optional API key from CERTSPOTTER_API_KEY.",
    ),
    "crt.sh": SourceSpec(
        source_key="crt_sh",
        name="crt.sh Certificate Transparency log search",
        source_type="other",
        access_method="api",
        base_url="https://crt.sh/",
        notes="Public index of Certificate Transparency logs (Sectigo). Free shared service; used as a fallback.",
    ),
}
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

    def __init__(self, store: ObjectStore, clients: list | None = None):
        """``clients`` are tried in order until one answers (default: Cert Spotter, then crt.sh)."""
        self.store = store
        self._clients = clients

    @property
    def clients(self) -> list:
        if self._clients is None:
            self._clients = [CertSpotterClient(), CrtShClient()]
        return self._clients

    def search(self, name: str) -> CtLookupResult:
        failures = []
        for client in self.clients:
            result = client.search(name)
            if result.outcome != "lookup_failed":
                if failures:
                    result.message = "; ".join([*failures, *([result.message] if result.message else [])])
                return result
            failures.append(f"{result.source}: {result.message}")
        result.message = "; ".join(failures)
        return result

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

        result = self.search(name)
        now = datetime.now(UTC)
        lookup = CtLookup(domain_id=domain.id, query=name, source=result.source, request_url=result.request_url,
                          queried_at=now, outcome=result.outcome, http_status=result.http_status,
                          message=result.message, pages=result.pages, complete=result.complete,
                          ingestion_run_id=ctx.run.id)
        if result.outcome == "lookup_failed":
            s.add(lookup)
            s.flush()
            return "updated"
        try:
            # Gzipped JSON: a big estate's answer is hundreds of MB as text and about a tenth compressed.
            # mtime=0 keeps the bytes identical for an identical answer, so repeat runs reuse the stored copy.
            version = record_evidence(s, self.store, source=ensure_source(s, CT_SOURCES[result.source]),
                                      source_url=result.request_url, content=gzip.compress(result.content, mtime=0),
                                      media_type="application/gzip", http_status=result.http_status,
                                      title=f"{result.source} certificates for {name} (gzipped JSON)")
        except SecretDetected as exc:
            raise RowRejected("withheld", f"{result.source} answer for {name} not stored: {exc}", "domain") from None
        lookup.evidence_version_id = version.id
        lookup.entry_count = len(result.entries)
        lookup.certificate_count = len({e.key for e in result.entries})
        s.add(lookup)
        s.flush()
        new = self._store_entries(s, lookup, version.id, result.entries, now)
        return "inserted" if new else "unchanged"

    @staticmethod
    def _existing(s, keys: list[tuple[str, str]]) -> dict[tuple[str, str], int]:
        """certificate key -> id for the keys already stored."""
        found: dict[tuple[str, str], int] = {}
        tbs = [v for k, v in keys if k == "tbs"]
        serials = [tuple(v.split("\x1f", 1)) for k, v in keys if k == "serial"]
        for i in range(0, len(tbs), _CHUNK):
            for cid, h in s.execute(select(Certificate.id, Certificate.tbs_sha256)
                                    .where(Certificate.tbs_sha256.in_(tbs[i:i + _CHUNK]))):
                found[("tbs", h)] = cid
        for i in range(0, len(serials), _CHUNK):
            for cid, issuer, serial in s.execute(select(Certificate.id, Certificate.issuer_name, Certificate.serial_number)
                                                 .where(tuple_(Certificate.issuer_name, Certificate.serial_number)
                                                        .in_(serials[i:i + _CHUNK]))):
                found[("serial", f"{issuer}\x1f{serial}")] = cid
        return found

    def _store_entries(self, s, lookup: CtLookup, version_id: int, entries: list[CtEntry], now: datetime) -> int:
        """Bulk writes: tens of thousands of certificates for one domain must not mean as many round trips."""
        by_key: dict[tuple[str, str], list[CtEntry]] = {}
        for e in entries:
            by_key.setdefault(e.key, []).append(e)
        ids = self._existing(s, list(by_key))
        new_keys = [k for k in by_key if k not in ids]
        for i in range(0, len(new_keys), _CHUNK):
            chunk = new_keys[i:i + _CHUNK]
            rows = []
            for k in chunk:
                e = by_key[k][0]
                rows.append({"issuer_name": e.issuer_name, "issuer_ca_id": e.issuer_ca_id,
                             "serial_number": e.serial_number, "tbs_sha256": e.tbs_sha256,
                             "cert_sha256": e.cert_sha256, "revoked": e.revoked, "common_name": e.common_name,
                             "not_before": e.not_before, "not_after": e.not_after,
                             "first_observed_at": now, "last_observed_at": now})
            created = s.execute(insert(Certificate).returning(Certificate.id, sort_by_parameter_order=True), rows)
            for k, cid in zip(chunk, created.scalars(), strict=True):
                ids[k] = cid
        fresh = set(new_keys)
        old = [ids[k] for k in by_key if k not in fresh]
        for i in range(0, len(old), _CHUNK):
            s.execute(update(Certificate).where(Certificate.id.in_(old[i:i + _CHUNK]))
                      .values(last_observed_at=now))

        domains = self._domains_for(s, {n.removeprefix("*.") for e in entries for n in e.names})
        names = []
        for k in new_keys:
            for n in dict.fromkeys(n for e in by_key[k] for n in e.names):
                base = n.removeprefix("*.")
                names.append({"certificate_id": ids[k], "hostname": n, "is_wildcard": n.startswith("*."),
                              "base_name": base, "domain_id": domains.get(base)})
        observations = [{"certificate_id": ids[k], "ct_lookup_id": lookup.id, "source_entry_id": e.entry_id,
                         "evidence_version_id": version_id, "observed_at": now, "source_ref": e.source_ref}
                        for k, group in by_key.items() for e in group]
        for model, rows in ((CertificateHostname, names), (CertificateObservation, observations)):
            for i in range(0, len(rows), 5000):
                s.execute(insert(model), rows[i:i + 5000])
        s.flush()
        return len(new_keys)

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
