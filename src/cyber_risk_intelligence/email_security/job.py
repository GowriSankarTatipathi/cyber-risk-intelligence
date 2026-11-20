"""Collect SPF (23.1), DMARC (23.2), DKIM (23.3) and MTA-STS / TLS reporting (23.4) for company domains.

Input is a CSV ``company_key,domain`` (``python -m cyber_risk_intelligence.email_security targets``
writes one from ``company_domains``). For each row the job asks a public resolver for TXT
records (``<domain>`` for SPF, ``_dmarc.<domain>`` for DMARC), stores each answer as evidence,
records each lookup in ``dns_security_records`` and what it shows in ``email_security_observations``.

Only TXT queries are made, plus (23.4) one HTTPS GET of the MTA-STS policy file when the domain's
DNS announces one. No mail or report is sent. A failed lookup is ``lookup_failed``: it is never read as "no record".
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

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
from ..models.email_security import (
    DkimEvidence,
    DnsSecurityRecord,
    EmailSecurityObservation,
    MtaStsObservation,
    TlsReportingObservation,
)
from .dkim import (
    KnownSelector,
    read_dkim,
    selectors_from_mail_records,
    selectors_from_spf,
)
from .dmarc import organizational_domain, read_dmarc
from .dns import DnsResolver, Resolver
from .mta_sts import (
    PolicyFetcher,
    policy_url,
    read_policy,
    read_sts_record,
    read_tlsrpt_record,
    report_addresses,
)
from .spf import read_spf, txt_value

DNS_SOURCE = SourceSpec(
    source_key="public_dns",
    name="Public DNS (TXT records)",
    source_type="other",
    access_method="api",
    notes="Read-only DNS queries through a recursive resolver; what a domain publishes for anyone to read.",
)


def answer_document(query_name: str, record_type: str, outcome: str, rcode: str | None,
                    answers: list[list[str]] | None) -> bytes:
    """The stored evidence: what DNS returned, without the time or resolver, so an unchanged
    answer is the same bytes (and the same evidence object) on every run."""
    return json.dumps({"query": query_name, "type": record_type, "outcome": outcome, "rcode": rcode,
                       "answers": sorted(answers or [])}, indent=1, ensure_ascii=False).encode()


class _TxtJob(Job):
    """Shared by the SPF and DMARC jobs: target parsing, the company/domain checks and one TXT lookup."""

    media_type = "text/csv"
    control = ""
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

    def __init__(self, store: ObjectStore, resolver: Resolver | None = None):
        self.store = store
        self._resolver = resolver

    @property
    def resolver(self) -> Resolver:
        if self._resolver is None:
            self._resolver = DnsResolver()
        return self._resolver

    def parse(self, content: bytes):
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig")))
        if not reader.fieldnames or not {"company_key", "domain"} <= set(reader.fieldnames):
            raise ValueError("target CSV needs company_key and domain columns")
        for number, raw in enumerate(reader, start=1):
            data = {k.strip(): (v or "").strip() for k, v in raw.items() if k}
            yield InputRow(number, f"{data.get('company_key')}|{normalize_domain(data.get('domain', ''))}", data)

    def _target(self, ctx: WriteContext) -> tuple[Company, Domain]:
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
        return company, domain

    def _lookup(self, ctx: WriteContext, domain: Domain, query_name: str) -> tuple[DnsSecurityRecord, bool]:
        """Query TXT at ``query_name``; store the answer. Returns the lookup row and whether the
        answer is the same as the previous lookup of that name (the stored copy was reused)."""
        s = ctx.session
        lookup = self.resolver.txt(query_name)
        row = DnsSecurityRecord(
            domain_id=domain.id, query_name=query_name, record_type="TXT", resolver=lookup.resolver,
            outcome=lookup.outcome, rcode=lookup.rcode, message=lookup.message,
            answers=lookup.answers if lookup.outcome == "answered" else None, ttl=lookup.ttl,
            ingestion_run_id=ctx.run.id)
        previous = s.scalar(select(DnsSecurityRecord.evidence_version_id).where(
            DnsSecurityRecord.query_name == query_name, DnsSecurityRecord.record_type == "TXT")
            .order_by(DnsSecurityRecord.id.desc()).limit(1))
        if lookup.outcome != "lookup_failed":
            try:
                version = record_evidence(
                    s, self.store, source=ensure_source(s, DNS_SOURCE), source_url=f"dns:{query_name}/TXT",
                    content=answer_document(query_name, "TXT", lookup.outcome, lookup.rcode, lookup.answers),
                    media_type="application/json", title=f"TXT records for {query_name}")
            except SecretDetected as exc:
                raise RowRejected("withheld", f"TXT answer for {query_name} not stored: {exc}", "domain") from None
            row.evidence_version_id = version.id
        s.add(row)
        s.flush()
        return row, row.evidence_version_id is not None and previous == row.evidence_version_id

    def _observation(self, company: Company, domain: Domain, row: DnsSecurityRecord) -> EmailSecurityObservation:
        return EmailSecurityObservation(
            company_id=company.id, domain_id=domain.id, dns_record_id=row.id, control=self.control,
            observed_at=row.queried_at, evidence_version_id=row.evidence_version_id,
            source_ref=f"dns:{row.query_name}/TXT via {row.resolver}")


def _failed(obs: EmailSecurityObservation, row: DnsSecurityRecord) -> None:
    obs.status, obs.evidence_version_id = "lookup_failed", None
    obs.problems = [row.message or row.rcode or "lookup failed"]


class SpfJob(_TxtJob):
    name = "spf"
    dataset_key = "spf_targets"
    control = "spf"

    def write(self, ctx: WriteContext) -> RowStatus:
        company, domain = self._target(ctx)
        row, same = self._lookup(ctx, domain, domain.name)
        obs = self._observation(company, domain, row)
        if row.outcome == "lookup_failed":
            _failed(obs, row)
        elif row.outcome == "nxdomain":
            obs.status = "no_domain"
        else:
            spf = read_spf(row.answers or [])
            obs.status = spf.status
            obs.record_count = len(spf.records)
            obs.record_text = "\n".join(spf.records) or None
            if spf.status == "multiple":
                obs.problems = [f"{len(spf.records)} SPF records published; receivers treat this as an error"]
            if spf.record is not None:
                rec = spf.record
                obs.all_qualifier, obs.redirect = rec.all_qualifier, rec.redirect
                obs.mechanisms, obs.modifiers = rec.mechanisms, rec.modifiers
                obs.dns_lookup_terms, obs.problems = rec.dns_lookup_terms, rec.problems or None
        ctx.session.add(obs)
        ctx.session.flush()
        # Every lookup is kept (it is an observation at a time); the answer itself is stored once.
        return "unchanged" if same else "inserted"


class DmarcJob(_TxtJob):
    """DMARC is looked up at ``_dmarc.<domain>``. When a subdomain (``corporate.acme.com``) has none,
    receivers use the organizational domain's record (``_dmarc.acme.com``), so we look there too and
    record which one applies (``policy_source``)."""

    name = "dmarc"
    dataset_key = "dmarc_targets"
    control = "dmarc"

    def write(self, ctx: WriteContext) -> RowStatus:
        company, domain = self._target(ctx)
        row, same = self._lookup(ctx, domain, f"_dmarc.{domain.name}")
        obs = self._observation(company, domain, row)
        if row.outcome == "lookup_failed":
            _failed(obs, row)
        else:
            result, policy_row = read_dmarc(row.answers or []), row
            org = organizational_domain(domain.name)
            if result.status == "missing" and org != domain.name:
                policy_row, same_org = self._lookup(ctx, domain, f"_dmarc.{org}")
                same = same and same_org
                if policy_row.outcome == "lookup_failed":
                    _failed(obs, policy_row)
                    obs.policy_dns_record_id = policy_row.id
                    ctx.session.add(obs)
                    ctx.session.flush()
                    return "unchanged" if same else "inserted"
                result = read_dmarc(policy_row.answers or [])
                obs.policy_dns_record_id = policy_row.id
                obs.evidence_version_id = policy_row.evidence_version_id if result.status != "missing" \
                    else row.evidence_version_id
            obs.status = result.status
            obs.record_count = len(result.records)
            obs.record_text = "\n".join(result.records) or None
            if result.status != "missing":
                obs.policy_source = "domain" if policy_row is row else "organizational_domain"
            if result.status == "multiple":
                obs.problems = [f"{len(result.records)} DMARC records published; receivers ignore them all"]
            if result.record is not None:
                rec = result.record
                obs.tags, obs.problems = rec.tags, rec.problems or None
                if result.status == "present":
                    obs.dmarc_policy, obs.dmarc_subdomain_policy = rec.policy, rec.subdomain_policy
                    obs.dmarc_pct = rec.pct
                    obs.dkim_alignment, obs.spf_alignment = rec.dkim_alignment, rec.spf_alignment
                    obs.aggregate_report_uris = rec.aggregate_reports or None
                    obs.failure_report_uris = rec.failure_reports or None
                    obs.defaults_used = rec.defaults_used or None
        ctx.session.add(obs)
        ctx.session.flush()
        return "unchanged" if same else "inserted"


class DkimJob(_TxtJob):
    """DKIM keys at selectors known from public evidence (issue 23.3; see ``dkim``). Selectors come from
    the providers the domain's SPF record authorizes or its MX / verification records show, plus any in ``published`` ((company_key, domain) ->
    [KnownSelector]). No selector is guessed."""

    name = "dkim"
    dataset_key = "dkim_targets"
    control = "dkim"

    def __init__(self, store: ObjectStore, resolver: Resolver | None = None,
                 published: dict[tuple[str, str], list[KnownSelector]] | None = None):
        super().__init__(store, resolver)
        self.published = published or {}

    def write(self, ctx: WriteContext) -> RowStatus:
        company, domain = self._target(ctx)
        s = ctx.session
        known = [*self.published.get((company.company_key, domain.name), []),
                 *selectors_from_spf(domain.name, self.resolver.txt),
                 *selectors_from_mail_records(domain.name, self.resolver.txt, getattr(self.resolver, "mx", None))]
        unique: dict[str, KnownSelector] = {}
        for k in known:
            unique.setdefault(k.selector.lower(), k)
        if not unique:
            s.add(DkimEvidence(company_id=company.id, domain_id=domain.id, outcome="no_known_selector",
                               observed_at=datetime.now(UTC), ingestion_run_id=ctx.run.id,
                               problem="no selector known from public evidence; DKIM status unknown"))
            s.flush()
            return "updated"
        all_same = True
        for k in unique.values():
            row, same = self._lookup(ctx, domain, f"{k.selector}._domainkey.{domain.name}")
            all_same = all_same and same
            ev = DkimEvidence(company_id=company.id, domain_id=domain.id, selector=k.selector,
                              selector_source=k.source, selector_evidence=k.evidence, selector_source_url=k.source_url,
                              dns_record_id=row.id, observed_at=row.queried_at, ingestion_run_id=ctx.run.id,
                              evidence_version_id=row.evidence_version_id)
            if row.outcome == "lookup_failed":
                ev.outcome, ev.problem, ev.evidence_version_id = "lookup_failed", row.message or row.rcode, None
            elif row.outcome in ("nxdomain", "no_records"):
                ev.outcome = "not_found"
            else:
                values = [txt_value(a) for a in row.answers or []]
                dkim = [v for v in values if "p=" in v.replace(" ", "") or v.strip().startswith("v=DKIM1")]
                if not dkim:  # e.g. a wildcard TXT (*._domainkey) answering every name: no key here
                    ev.outcome, ev.problem = "not_found", "only a non-DKIM TXT record answers here (often a wildcard)"
                    ev.record_text = "\n".join(values)[:500]
                elif len(dkim) > 1:
                    ev.outcome, ev.problem, ev.record_text = "invalid", f"{len(dkim)} DKIM records", "\n".join(dkim)
                else:
                    key = read_dkim(dkim[0])
                    ev.outcome, ev.key_type, ev.key_bits, ev.problem = key.status, key.key_type, key.key_bits, key.problem
                    ev.record_text = dkim[0]
            s.add(ev)
        s.flush()
        return "unchanged" if all_same else "inserted"


MTA_STS_POLICY_SOURCE = SourceSpec(
    source_key="mta_sts_policies",
    name="MTA-STS policy files",
    source_type="other",
    access_method="api",
    notes="GET of https://mta-sts.<domain>/.well-known/mta-sts.txt, only when the domain's DNS announces "
          "a policy (RFC 8461). No redirects followed; at most 64 KB.",
)


def _txt_values(row: DnsSecurityRecord) -> list[str]:
    return [txt_value(a) for a in row.answers or []] if row.outcome == "answered" else []


class MtaStsJob(_TxtJob):
    """MTA-STS (``_mta-sts.<domain>`` plus its policy file) and TLS reporting (``_smtp._tls.<domain>``),
    issue 23.4; see ``mta_sts``. The policy file is fetched only when DNS announces a policy."""

    name = "mta_sts"
    dataset_key = "mta_sts_targets"
    control = "mta_sts"

    def __init__(self, store: ObjectStore, resolver: Resolver | None = None, fetcher: PolicyFetcher | None = None):
        super().__init__(store, resolver)
        self._fetcher = fetcher

    @property
    def fetcher(self) -> PolicyFetcher:
        if self._fetcher is None:
            self._fetcher = PolicyFetcher()
        return self._fetcher

    def write(self, ctx: WriteContext) -> RowStatus:
        company, domain = self._target(ctx)
        s = ctx.session
        sts_row, same_sts = self._lookup(ctx, domain, f"_mta-sts.{domain.name}")
        obs = MtaStsObservation(company_id=company.id, domain_id=domain.id, dns_record_id=sts_row.id,
                                policy_url=policy_url(domain.name), policy_retrieval="not_attempted",
                                observed_at=sts_row.queried_at, ingestion_run_id=ctx.run.id)
        problems: list[str] = []
        if sts_row.outcome == "lookup_failed":
            obs.dns_status, obs.message = "lookup_failed", sts_row.message or sts_row.rcode or "lookup failed"
        else:
            rec = read_sts_record(_txt_values(sts_row))
            obs.dns_status, obs.record_text, obs.sts_id = rec.status, rec.record, rec.tags.get("id")
            problems += rec.problems
        same_policy = True
        if obs.dns_status in ("present", "invalid", "multiple"):
            previous = s.scalar(select(MtaStsObservation.policy_evidence_version_id)
                                .where(MtaStsObservation.domain_id == domain.id)
                                .order_by(MtaStsObservation.id.desc()).limit(1))
            fetched = self.fetcher.fetch(domain.name)
            obs.policy_retrieval, obs.policy_http_status, obs.message = fetched.outcome, fetched.http_status, \
                fetched.message
            if fetched.outcome == "retrieved":
                text = (fetched.body or b"").decode("utf-8", errors="replace")
                try:
                    version = record_evidence(
                        s, self.store, source=ensure_source(s, MTA_STS_POLICY_SOURCE), source_url=fetched.url,
                        content=fetched.body or b"", media_type="text/plain", http_status=fetched.http_status,
                        title=f"MTA-STS policy of {domain.name}")
                except SecretDetected as exc:
                    raise RowRejected("withheld", f"MTA-STS policy of {domain.name} not stored: {exc}",
                                      "domain") from None
                policy = read_policy(text)
                obs.policy_evidence_version_id = version.id
                obs.policy_status, obs.mode, obs.max_age = policy.status, policy.mode, policy.max_age
                obs.mx_patterns = policy.mx or None
                problems += policy.problems
                same_policy = previous == version.id
            else:
                same_policy = False
        obs.problems = problems or None
        s.add(obs)

        rpt_row, same_rpt = self._lookup(ctx, domain, f"_smtp._tls.{domain.name}")
        rpt = TlsReportingObservation(company_id=company.id, domain_id=domain.id, dns_record_id=rpt_row.id,
                                      observed_at=rpt_row.queried_at, evidence_version_id=rpt_row.evidence_version_id,
                                      ingestion_run_id=ctx.run.id)
        if rpt_row.outcome == "lookup_failed":
            rpt.status, rpt.problems = "lookup_failed", [rpt_row.message or rpt_row.rcode or "lookup failed"]
        else:
            r = read_tlsrpt_record(_txt_values(rpt_row))
            rpt.status, rpt.record_text, rpt.problems = r.status, r.record, r.problems or None
            rpt.report_uris = report_addresses(r) or None
        s.add(rpt)
        s.flush()
        # "updated" counts domains where something could not be read (as the website checks do).
        # A 404 or a bad certificate is a finding about the domain, not a failure to look.
        if "lookup_failed" in (sts_row.outcome, rpt_row.outcome) or obs.policy_retrieval == "request_failed":
            return "updated"
        return "unchanged" if same_sts and same_rpt and same_policy else "inserted"


def targets_csv(s) -> bytes:
    """company_key,domain for every current company domain."""
    rows = s.execute(select(Company.company_key, Domain.name).join(CompanyDomain, CompanyDomain.company_id == Company.id)
                     .join(Domain, Domain.id == CompanyDomain.domain_id).where(CompanyDomain.valid_to.is_(None))
                     .distinct().order_by(Company.company_key, Domain.name)).all()
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["company_key", "domain"])
    w.writerows(rows)
    return buf.getvalue().encode()
