"""Read the certificate a company's own website presents (issue 10.1 follow-up).

This is what a browser shows under Inspect > Security: one TLS handshake on port 443 with the
company's known domain and its ``www.`` host. The handshake is first made with normal browser-style
checking (trusted roots and host name). If that fails, it is made again without checking so the
certificate that was presented can still be read, and the reason it failed is kept.

Only those two hosts are contacted. No other port is tried, no page is requested, and none of the
names inside the certificate is followed. Certificate Transparency (``CtJob``) covers the rest of the estate.
"""

from __future__ import annotations

import csv
import hashlib
import io
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
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
from ..models.certificates import WebsiteCertificateCheck

WEBSITE_TLS_SOURCE = SourceSpec(
    source_key="website_tls",
    name="Company website TLS certificate",
    source_type="other",
    access_method="api",
    notes="One TLS handshake on port 443 with the company's known website (domain and www.), as a browser does.",
)


@dataclass
class TlsResult:
    host: str
    port: int
    outcome: str  # trusted / not_trusted / unreachable
    message: str | None = None
    tls_version: str | None = None
    der: bytes | None = None
    names: list[str] = field(default_factory=list)


def _handshake(host: str, port: int, timeout: float, context: ssl.SSLContext) -> tuple[bytes | None, str | None]:
    with (socket.create_connection((host, port), timeout=timeout) as raw,
          context.wrap_socket(raw, server_hostname=host) as tls):
        return tls.getpeercert(binary_form=True), tls.version()


def fetch_certificate(host: str, port: int = 443, timeout: float = 10.0, cafile: str | None = None) -> TlsResult:
    """The certificate ``host`` presents, and whether a browser would trust it."""
    checking = ssl.create_default_context(cafile=cafile)
    try:
        der, version = _handshake(host, port, timeout, checking)
        return TlsResult(host, port, "trusted", None, version, der)
    except ssl.SSLCertVerificationError as exc:
        reason = exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:  # no such host, refused, timeout, no TLS on the port
        return TlsResult(host, port, "unreachable", f"{type(exc).__name__}: {exc}")
    reading = ssl.create_default_context()
    reading.check_hostname = False
    reading.verify_mode = ssl.CERT_NONE
    try:
        der, version = _handshake(host, port, timeout, reading)
    except (OSError, ssl.SSLError) as exc:
        return TlsResult(host, port, "unreachable", f"not trusted ({reason}), then {type(exc).__name__}: {exc}")
    return TlsResult(host, port, "not_trusted", reason, version, der)


@dataclass
class CertificateFacts:
    sha256: str
    serial_number: str
    issuer_name: str
    subject_name: str
    common_name: str | None
    names: list[str]
    not_before: datetime
    not_after: datetime
    pem: bytes


def read_certificate(der: bytes) -> CertificateFacts:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = sorted({n.lower() for n in san.get_values_for_type(x509.DNSName)})
    except x509.ExtensionNotFound:
        names = []
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return CertificateFacts(
        sha256=hashlib.sha256(der).hexdigest(), serial_number=format(cert.serial_number, "x"),
        issuer_name=cert.issuer.rfc4514_string(), subject_name=cert.subject.rfc4514_string(),
        common_name=str(cn[0].value) if cn else None, names=names,
        not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc,
        pem=cert.public_bytes(Encoding.PEM))


def hosts_for(domain: str) -> list[str]:
    return [domain] if domain.startswith("www.") else [domain, f"www.{domain}"]


class WebsiteCertificateJob(Job):
    name = "website_certificates"
    dataset_key = "website_certificate_targets"
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

    def __init__(self, store: ObjectStore, fetch=fetch_certificate):
        self.store = store
        self.fetch = fetch

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
        statuses = []
        for host in hosts_for(name):
            result = self.fetch(host)
            check = WebsiteCertificateCheck(domain_id=domain.id, host=host, port=result.port,
                                            checked_at=datetime.now(UTC), outcome=result.outcome,
                                            message=result.message, tls_version=result.tls_version,
                                            ingestion_run_id=ctx.run.id)
            if result.der is None:
                statuses.append("updated")
            else:
                facts = read_certificate(result.der)
                previous = s.scalar(select(WebsiteCertificateCheck.cert_sha256).where(
                    WebsiteCertificateCheck.host == host, WebsiteCertificateCheck.cert_sha256.is_not(None))
                    .order_by(WebsiteCertificateCheck.id.desc()).limit(1))
                try:
                    version = record_evidence(
                        s, self.store, source=ensure_source(s, WEBSITE_TLS_SOURCE),
                        source_url=f"tls://{host}:{result.port}", content=facts.pem,
                        media_type="application/x-pem-file", title=f"TLS certificate presented by {host}")
                except SecretDetected as exc:
                    raise RowRejected("withheld", f"certificate from {host} not stored: {exc}", "domain") from None
                check.evidence_version_id = version.id
                check.cert_sha256, check.serial_number = facts.sha256, facts.serial_number
                check.issuer_name, check.subject_name = facts.issuer_name, facts.subject_name
                check.common_name, check.names = facts.common_name, facts.names
                check.not_before, check.not_after = facts.not_before, facts.not_after
                statuses.append("unchanged" if previous == facts.sha256 else "inserted")
            s.add(check)
        s.flush()
        if "inserted" in statuses:
            return "inserted"
        return "unchanged" if "unchanged" in statuses else "updated"
