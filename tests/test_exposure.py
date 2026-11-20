"""Indexed exposure from Shodan InternetDB (issue 10.3). Fake DNS and mocked InternetDB; nothing is contacted."""

import csv
import hashlib
import io

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.domains import CompanyDomainsJob
from cyber_risk_intelligence.evidence import LocalStore
from cyber_risk_intelligence.exposure import (
    IndexedExposureJob,
    InternetDbClient,
    attribution,
)
from cyber_risk_intelligence.exposure.__main__ import summary
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import IndexedHostLookup, IndexedServiceObservation

from . import factories as f

OWN = {"acme.example"}


def test_attribution():
    assert attribution({"tags": ["cdn"], "hostnames": ["www.acme.example"]}, OWN) == "cdn"
    assert attribution({"hostnames": ["vpn.acme.example", "acme.example"]}, OWN) == "company_only"
    assert attribution({"hostnames": ["vpn.acme.example", "other-company.example"]}, OWN) == "shared"
    assert attribution({"hostnames": []}, OWN) == "unknown"


def client(routes, calls=None):
    """routes: ip -> (status, json) or an exception."""
    def handler(request):
        ip = request.url.path.strip("/")
        if calls is not None:
            calls.append(ip)
        answer = routes.get(ip, (404, {"detail": "No information available"}))
        if isinstance(answer, Exception):
            raise answer
        return httpx.Response(answer[0], json=answer[1])
    return InternetDbClient(httpx.Client(transport=httpx.MockTransport(handler)), pause=0, retries=1)


def test_client_outcomes():
    c = client({"192.0.2.1": (200, {"ip": "192.0.2.1", "ports": [443]}), "192.0.2.3": (503, {}),
                "192.0.2.4": httpx.ConnectTimeout("timed out")})
    assert c.host("192.0.2.1").outcome == "found"
    assert c.host("192.0.2.2").outcome == "not_indexed"
    assert (c.host("192.0.2.3").outcome, c.host("192.0.2.3").http_status) == ("lookup_failed", 503)
    assert "ConnectTimeout" in c.host("192.0.2.4").message


class FakeResolver:
    name = "fake-resolver"

    def __init__(self, a, mx=None):
        self.a_records, self.mx_hosts, self.asked = a, mx or {}, []

    def a(self, name):
        self.asked.append(name)
        return self.a_records.get(name, [])

    def mx(self, name):
        return self.mx_hosts.get(name, [])

    def txt(self, name):  # pragma: no cover - not used by this job
        raise AssertionError


def csv_bytes(header, *rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue().encode()


@pytest.fixture
def store(tmp_path):
    return LocalStore(tmp_path)


@pytest.fixture
def acme(session_factory, store):
    with session_factory() as s:
        f.company(s, "acme", "Acme")
        s.commit()
    run = run_import(session_factory, store, CompanyDomainsJob(), csv_bytes(
        ["company_key", "domain", "role", "source_url"],
        ["acme", "acme.example", "primary_website", "https://www.wikidata.org/entity/Q1"]),
        source_url="file:///domains.csv")
    assert run.status == "succeeded"


DNS = {"acme.example": ["192.0.2.10"], "www.acme.example": ["198.51.100.1"], "mail.acme.example": ["192.0.2.25"]}
MX = {"acme.example": ["mail.acme.example", "acme-example.mail.protection.outlook.com"]}
DB = {"192.0.2.10": (200, {"ip": "192.0.2.10", "ports": [443, 3389, 22], "hostnames": ["acme.example"],
                           "cpes": ["cpe:/a:microsoft:internet_information_services:8.5"],
                           "vulns": ["CVE-2026-0001"], "tags": []}),
      "198.51.100.1": (200, {"ip": "198.51.100.1", "ports": [80, 443, 8443], "hostnames": ["edge.cdn.example"],
                             "cpes": [], "vulns": [], "tags": ["cdn"]}),
      "192.0.2.25": (200, {"ip": "192.0.2.25", "ports": [25], "hostnames": ["mail.acme.example", "other.example"],
                           "cpes": [], "vulns": [], "tags": []})}


def collect(sf, store, dns, db, mx=None, calls=None):
    resolver = FakeResolver(dns, mx)
    run = run_import(sf, store, IndexedExposureJob(store, resolver, client(db, calls)),
                     csv_bytes(["company_key", "domain"], ["acme", "acme.example"]), source_url="file:///t.csv")
    return run, resolver


def test_job_records_lookups_ports_and_attribution(session_factory, store, acme, capsys):
    calls = []
    run, resolver = collect(session_factory, store, DNS, DB, MX, calls)
    assert run.status == "succeeded" and run.rows_inserted == 1
    # the provider's mail host is not asked: its IPs serve other companies
    assert resolver.asked == ["acme.example", "www.acme.example", "mail.acme.example"]
    assert sorted(calls) == ["192.0.2.10", "192.0.2.25", "198.51.100.1"]
    with session_factory() as s:
        lookups = {r.host: r for r in s.scalars(select(IndexedHostLookup))}
        ports = s.scalars(select(IndexedServiceObservation).order_by(IndexedServiceObservation.port)).all()
    bare, www, mail = lookups["acme.example"], lookups["www.acme.example"], lookups["mail.acme.example"]
    assert (bare.attribution, www.attribution, mail.attribution) == ("company_only", "cdn", "shared")
    assert bare.potential_vulns == ["CVE-2026-0001"] and bare.source_scan_date is None  # InternetDB gives no date
    assert mail.host_role == "mail" and all(r.evidence_version_id for r in lookups.values())
    rdp = next(p for p in ports if p.port == 3389)
    assert (rdp.service_hint, rdp.sensitive, rdp.attribution) == ("rdp", True, "company_only")
    assert not next(p for p in ports if p.port == 8443).sensitive and not next(p for p in ports if p.port == 22).sensitive
    summary(session_factory)
    out = capsys.readouterr().out
    assert "acme.example:3389/rdp" in out and "22/ssh" not in out  # ssh is listed, but not as sensitive
    assert "8443" not in out.split("\n")[1]  # a CDN's ports are not listed as the company's

    run, _ = collect(session_factory, store, DNS, DB, MX)
    assert run.rows_unchanged == 1


def test_summary_counts_an_ip_behind_two_hosts_once(session_factory, store, acme, capsys):
    collect(session_factory, store, {"acme.example": ["198.51.100.1"], "www.acme.example": ["198.51.100.1"]}, DB)
    summary(session_factory)
    line = capsys.readouterr().out.split("\n")[1].split()
    assert line[:5] == ["acme", "0", "1", "1", "0"]  # no side host, 1 IP, 1 cdn (not 2), 0 shared


def test_not_indexed_and_failures_are_kept_apart(session_factory, store, acme):
    run, _ = collect(session_factory, store, {"acme.example": ["192.0.2.10"], "www.acme.example": None},
                     {"192.0.2.10": httpx.ConnectTimeout("timed out")})
    assert run.rows_updated == 1
    with session_factory() as s:
        rows = {r.host: r for r in s.scalars(select(IndexedHostLookup))}
    assert (rows["acme.example"].outcome, rows["acme.example"].evidence_version_id) == ("lookup_failed", None)
    assert (rows["www.acme.example"].outcome, rows["www.acme.example"].ip) == ("dns_failed", None)

    collect(session_factory, store, {"acme.example": ["192.0.2.99"]}, {})
    with session_factory() as s:
        last = s.scalars(select(IndexedHostLookup).order_by(IndexedHostLookup.id.desc())).all()
    assert {r.outcome for r in last[:2]} == {"not_indexed", "no_address"}


def test_database_refuses_found_without_evidence(session_factory, store, acme):
    collect(session_factory, store, DNS, DB, MX)
    with session_factory() as s:
        row = s.scalars(select(IndexedHostLookup).where(IndexedHostLookup.outcome == "found")).first()
        row.evidence_version_id = None
        with pytest.raises(IntegrityError):
            s.flush()


# --- side hosts from CT certificates ---------------------------------------------------------------------

def test_name_hint():
    from cyber_risk_intelligence.exposure.side_hosts import name_hint

    assert name_hint("vpn2.eu.acme.example", "acme.example") == "remote_access"
    assert name_hint("sftp-files.acme.example", "acme.example") == "file_transfer"
    assert name_hint("owa.acme.example", "acme.example") == "mail"
    assert name_hint("careers.acme.example", "acme.example") is None
    assert name_hint("acme-admin.acme.example", "acme.example") == "admin"


def add_certificate(s, domain_id, names, not_after):
    from datetime import UTC, datetime

    from cyber_risk_intelligence.models import Certificate, CertificateHostname

    now = datetime.now(UTC)
    c = Certificate(issuer_name="Test CA", tbs_sha256=hashlib.sha256(names[0].encode()).hexdigest(), not_after=not_after,
                    first_observed_at=now, last_observed_at=now)
    s.add(c)
    s.flush()
    for n in names:
        s.add(CertificateHostname(certificate_id=c.id, hostname=n, is_wildcard=n.startswith("*."),
                                  base_name=n.removeprefix("*."), domain_id=domain_id))


def test_side_hosts_come_from_recent_certificates(session_factory, store, acme, capsys):
    from datetime import UTC, datetime, timedelta

    from cyber_risk_intelligence.exposure.side_hosts import side_hosts
    from cyber_risk_intelligence.models import Domain

    now = datetime.now(UTC)
    with session_factory() as s:
        d = s.scalars(select(Domain).where(Domain.name == "acme.example")).one()
        add_certificate(s, d.id, ["careers.acme.example", "vpn.acme.example", "*.acme.example", "www.acme.example"],
                        now + timedelta(days=90))
        add_certificate(s, d.id, ["owa.acme.example"], now + timedelta(days=30))
        add_certificate(s, d.id, ["oldvpn.acme.example"], now - timedelta(days=500))  # long expired
        s.commit()
        picked = side_hosts(s, d.id, "acme.example", 10, {"acme.example", "www.acme.example"})
        assert picked == [("vpn.acme.example", "remote_access"), ("owa.acme.example", "mail"),
                          ("careers.acme.example", None)]
        assert side_hosts(s, d.id, "acme.example", 1, set()) == [("vpn.acme.example", "remote_access")]
        assert side_hosts(s, d.id, "acme.example", 0, set()) == []

    dns = {**DNS, "vpn.acme.example": ["192.0.2.30"]}
    db = {**DB, "192.0.2.30": (200, {"ip": "192.0.2.30", "ports": [443, 3389], "hostnames": ["vpn.acme.example"],
                                     "cpes": ["cpe:/o:fortinet:fortios"], "vulns": [], "tags": []})}
    resolver = FakeResolver(dns, MX)
    run_import(session_factory, store, IndexedExposureJob(store, resolver, client(db), side_hosts=1),
               csv_bytes(["company_key", "domain"], ["acme", "acme.example"]), source_url="file:///t.csv")
    assert resolver.asked == ["acme.example", "www.acme.example", "mail.acme.example", "vpn.acme.example"]
    with session_factory() as s:
        vpn = s.scalars(select(IndexedHostLookup).where(IndexedHostLookup.host == "vpn.acme.example")).one()
    assert (vpn.host_role, vpn.name_hint, vpn.attribution) == ("certificate_name", "remote_access", "company_only")
    summary(session_factory)
    out = capsys.readouterr().out
    assert "vpn.acme.example:3389/rdp" in out and "fortinet:fortios" in out
