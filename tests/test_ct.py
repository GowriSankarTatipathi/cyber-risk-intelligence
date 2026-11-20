"""Issue 10.1: certificates and hostnames from Certificate Transparency logs (no live calls)."""

import csv
import io
import json

import httpx
import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.ct import CtJob
from cyber_risk_intelligence.ct.certspotter import CertSpotterClient
from cyber_risk_intelligence.ct.crtsh import CrtShClient, clean_name, parse_entries
from cyber_risk_intelligence.domains import CompanyDomainsJob
from cyber_risk_intelligence.evidence import LocalStore
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import ValidationResult
from cyber_risk_intelligence.models.certificates import (
    Certificate,
    CertificateHostname,
    CertificateObservation,
    CtLookup,
)
from cyber_risk_intelligence.quality import run_validation

from . import factories as f

ISSUER = "C=US, O=Let's Encrypt, CN=R11"


def entry(id_, serial, names, cn=None, issuer=ISSUER, nb="2026-10-01T00:00:00", na="2027-01-01T00:00:00"):
    return {"issuer_ca_id": 1, "issuer_name": issuer, "common_name": cn or names.split("\n")[0],
            "name_value": names, "id": id_, "not_before": nb, "not_after": na, "serial_number": serial,
            "result_count": 2}


# A precertificate and its certificate (same issuer + serial, two log entries), a wildcard certificate,
# and a certificate that also names another company's domain and an outside one.
ACME = [
    entry(101, "0aBc01", "acme.example\nwww.acme.example"),
    entry(102, "0abc01", "acme.example\nwww.acme.example"),
    entry(103, "77", "*.dev.acme.example\ndev.acme.example"),
    entry(104, "88", "shop.acme.example\nglobex.example\nunrelated.example\nadmin@acme.example\n10.0.0.1",
          issuer="C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1"),
]


def csv_bytes(header, *rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue().encode()


def crtsh(responses):
    """A CrtShClient whose HTTP answers come from ``responses``: domain -> list of (status, body)."""
    calls = []

    def handler(request):
        q = request.url.params["q"]
        calls.append(q)
        status, body = responses[q].pop(0) if len(responses[q]) > 1 else responses[q][0]
        return httpx.Response(status, content=body if isinstance(body, bytes) else json.dumps(body).encode())

    client = CrtShClient(httpx.Client(transport=httpx.MockTransport(handler)), min_delay=0, retries=2, backoff=0)
    return client, calls


def spotter(pages_by_after, status_seq=None, max_pages=None, retry_after="0"):
    """A CertSpotterClient answering from ``pages_by_after``: after-id ('' for the first page) -> items.
    ``status_seq`` is a list of statuses to answer with first (e.g. [429])."""
    calls, statuses = [], list(status_seq or [])

    def handler(request):
        after = request.url.params.get("after", "")
        calls.append(after)
        if statuses:
            code = statuses.pop(0)
            return httpx.Response(code, headers={"Retry-After": retry_after}, content=b"{}")
        return httpx.Response(200, content=json.dumps(pages_by_after.get(after, [])).encode())

    client = CertSpotterClient(httpx.Client(transport=httpx.MockTransport(handler)), min_delay=0, retries=2,
                               backoff=0, max_pages=max_pages)
    return client, calls


def issuance(id_, tbs_char, names, issuer="C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"):
    return {"id": str(id_), "tbs_sha256": tbs_char * 64, "cert_sha256": "c" * 63 + tbs_char, "dns_names": names,
            "issuer": {"name": issuer}, "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-09-01T23:59:59Z",
            "revoked": False}


@pytest.fixture
def store(tmp_path):
    return LocalStore(tmp_path)


@pytest.fixture
def acme(session_factory, store):
    with session_factory() as s:
        f.company(s, "acme", "Acme")
        f.company(s, "globex", "Globex")
        s.commit()
    run = run_import(session_factory, store, CompanyDomainsJob(), csv_bytes(
        ["company_key", "domain", "role", "source_url"],
        ["acme", "acme.example", "primary_website", "https://www.wikidata.org/entity/Q1"],
        ["globex", "globex.example", "primary_website", "https://www.wikidata.org/entity/Q2"],
    ), source_url="file:///domains.csv")
    assert run.status == "succeeded"


def collect(sf, store, responses, *rows, clients=None):
    client, calls = crtsh(responses)
    rows = rows or (["acme", "acme.example"],)
    run = run_import(sf, store, CtJob(store, clients or [client]), csv_bytes(["company_key", "domain"], *rows),
                     source_url="file:///t.csv")
    return run, calls


def count(sf, model):
    with sf() as s:
        return s.scalar(select(func.count()).select_from(model))


# --- parsing --------------------------------------------------------------------------------------------

def test_names_are_cleaned():
    assert clean_name("WWW.Acme.Example.") == "www.acme.example"
    assert clean_name("*.dev.acme.example") == "*.dev.acme.example"
    assert clean_name("admin@acme.example") is None and clean_name("10.0.0.1") is None
    assert clean_name("acme") is None and clean_name("a b.example") is None


def test_entries_keep_issuer_serial_and_dates():
    e = parse_entries(json.dumps(ACME).encode())
    assert [x.serial_number for x in e[:2]] == ["0abc01", "0abc01"]  # same certificate, any case
    assert e[3].names == ["shop.acme.example", "globex.example", "unrelated.example"]
    assert e[0].not_after.isoformat() == "2027-01-01T00:00:00+00:00"


# --- collection -----------------------------------------------------------------------------------------

def test_certificates_collapse_and_keep_observations(session_factory, store, acme):
    run, calls = collect(session_factory, store, {"acme.example": [(200, ACME)]})
    assert run.status == "succeeded" and calls == ["acme.example"]
    with session_factory() as s:
        certs = s.scalars(select(Certificate).order_by(Certificate.id)).all()
        assert len(certs) == 3  # precertificate + certificate collapse to one
        obs = s.scalars(select(CertificateObservation)).all()
        assert sorted(o.source_entry_id for o in obs) == ["101", "102", "103", "104"]
        assert all(o.evidence_version_id and o.source_ref.startswith("https://crt.sh/?id=") for o in obs)
        lookup = s.scalars(select(CtLookup)).one()
        assert (lookup.outcome, lookup.entry_count, lookup.certificate_count) == ("answered", 4, 3)
        assert lookup.evidence_version_id is not None


def test_repeat_search_adds_observations_not_certificates(session_factory, store, acme):
    collect(session_factory, store, {"acme.example": [(200, ACME)]})
    run, _ = collect(session_factory, store, {"acme.example": [(200, ACME)]})
    assert run.rows_unchanged == 1
    assert count(session_factory, Certificate) == 3
    assert count(session_factory, CertificateObservation) == 8  # every sighting is kept
    assert count(session_factory, CtLookup) == 2


def test_wildcards_are_patterns_and_names_link_only_to_known_domains(session_factory, store, acme):
    collect(session_factory, store, {"acme.example": [(200, ACME)]})
    with session_factory() as s:
        names = {h.hostname: h for h in s.scalars(select(CertificateHostname))}
        domain_of = dict(s.execute(text("SELECT id, name FROM domains")).all())
        view = s.execute(text(
            "SELECT c.company_key, v.hostname, v.is_wildcard FROM company_certificate_hostnames v "
            "JOIN companies c ON c.id = v.company_id")).all()
    wild = names["*.dev.acme.example"]
    assert wild.is_wildcard and wild.base_name == "dev.acme.example"
    assert domain_of[names["shop.acme.example"].domain_id] == "acme.example"
    assert domain_of[names["globex.example"].domain_id] == "globex.example"  # another company's known domain
    assert names["unrelated.example"].domain_id is None  # no domain evidence: not tied to any company
    assert "admin@acme.example" not in names and "10.0.0.1" not in names
    assert ("globex", "globex.example", False) in view
    assert ("acme", "*.dev.acme.example", True) in view
    assert not any(h == "unrelated.example" for _, h, _ in view)


def test_failed_search_is_unknown_not_empty(session_factory, store, acme):
    run, calls = collect(session_factory, store, {"acme.example": [(502, b"Bad Gateway")]})
    assert run.status == "succeeded" and len(calls) == 3  # retried, then given up
    with session_factory() as s:
        lookup = s.scalars(select(CtLookup)).one()
    assert lookup.outcome == "lookup_failed" and lookup.entry_count is None and lookup.evidence_version_id is None
    assert "HTTP 502" in lookup.message
    run_validation(session_factory)
    with session_factory() as s:
        res = s.scalars(select(ValidationResult).where(ValidationResult.rule == "ct_lookup_failed")).one()
    assert res.rows_failed == 1


def test_rate_limit_then_answer_is_retried(session_factory, store, acme):
    _, calls = collect(session_factory, store, {"acme.example": [(429, b""), (200, ACME)]})
    assert len(calls) == 2 and count(session_factory, Certificate) == 3


def test_no_certificates_is_its_own_outcome(session_factory, store, acme):
    collect(session_factory, store, {"acme.example": [(200, [])]})
    with session_factory() as s:
        lookup = s.scalars(select(CtLookup)).one()
    assert (lookup.outcome, lookup.entry_count) == ("no_results", 0) and lookup.evidence_version_id


def test_unlinked_domain_is_rejected_without_a_search(session_factory, store, acme):
    run, calls = collect(session_factory, store, {}, ["acme", "globex.example"], ["nobody", "acme.example"])
    assert run.rows_rejected == 2 and calls == []


def test_database_refuses_inconsistent_rows(session_factory, store, acme):
    collect(session_factory, store, {"acme.example": [(200, ACME)]})
    bad = ["UPDATE certificate_hostnames SET is_wildcard = true WHERE hostname = 'shop.acme.example'",
           "UPDATE ct_lookups SET evidence_version_id = NULL",
           "UPDATE certificates SET serial_number = 'XYZ'"]
    for sql in bad:
        with session_factory() as s, pytest.raises(IntegrityError):
            s.execute(text(sql))
            s.flush()


# --- Cert Spotter (first choice; pages through big domains) ----------------------------------------------

PAGES = {"": [issuance(1, "a", ["acme.example", "www.acme.example"]), issuance(2, "b", ["*.cdn.acme.example"])],
         "2": [issuance(3, "d", ["api.acme.example", "globex.example"])], "3": []}


def test_certspotter_reads_every_page(session_factory, store, acme):
    client, calls = spotter(PAGES)
    run, _ = collect(session_factory, store, {}, clients=[client])
    assert run.status == "succeeded" and calls == ["", "2", "3"]
    with session_factory() as s:
        lookup = s.scalars(select(CtLookup)).one()
        certs = s.scalars(select(Certificate)).all()
        obs = s.scalars(select(CertificateObservation)).all()
    assert (lookup.source, lookup.pages, lookup.complete, lookup.certificate_count) == ("certspotter", 3, True, 3)
    assert {c.tbs_sha256[0] for c in certs} == {"a", "b", "d"} and all(c.serial_number is None for c in certs)
    assert all(o.source_ref.startswith("https://crt.sh/?sha256=") for o in obs)


def test_certspotter_repeat_collapses_by_tbs(session_factory, store, acme):
    for _ in range(2):
        client, _ = spotter(PAGES)
        collect(session_factory, store, {}, clients=[client])
    assert count(session_factory, Certificate) == 3 and count(session_factory, CertificateObservation) == 6


def test_certspotter_rate_limit_waits_and_continues(session_factory, store, acme):
    client, calls = spotter(PAGES, status_seq=[429])
    collect(session_factory, store, {}, clients=[client])
    assert calls == ["", "", "2", "3"] and count(session_factory, Certificate) == 3


def test_page_limit_keeps_what_was_read_and_says_so(session_factory, store, acme):
    client, _ = spotter(PAGES, max_pages=1)
    collect(session_factory, store, {}, clients=[client])
    with session_factory() as s:
        lookup = s.scalars(select(CtLookup)).one()
    assert (lookup.outcome, lookup.complete, lookup.certificate_count) == ("answered", False, 2)
    assert "more exist" in lookup.message


def test_falls_back_to_crtsh_when_certspotter_fails(session_factory, store, acme):
    failing, _ = spotter({}, status_seq=[503, 503, 503])
    fallback, calls = crtsh({"acme.example": [(200, ACME)]})
    collect(session_factory, store, {}, clients=[failing, fallback])
    with session_factory() as s:
        lookup = s.scalars(select(CtLookup)).one()
    assert lookup.source == "crt.sh" and calls == ["acme.example"] and "certspotter: HTTP 503" in lookup.message
    assert count(session_factory, Certificate) == 3


def test_long_rate_limit_moves_on_to_crtsh_and_stops_asking(session_factory, store, acme):
    limited, spotter_calls = spotter(PAGES, status_seq=[429], retry_after="3000")
    fallback, crtsh_calls = crtsh({"acme.example": [(200, ACME)], "globex.example": [(200, [])]})
    run, _ = collect(session_factory, store, {}, ["acme", "acme.example"], ["globex", "globex.example"],
                     clients=[limited, fallback])
    assert run.status == "succeeded"
    assert spotter_calls == [""]  # asked once; the second domain went straight to crt.sh
    assert crtsh_calls == ["acme.example", "globex.example"]
    with session_factory() as s:
        lookups = s.scalars(select(CtLookup).order_by(CtLookup.id)).all()
    assert [lk.source for lk in lookups] == ["crt.sh", "crt.sh"]
    assert "rate limited" in lookups[1].message


def test_waits_for_certspotter_when_crtsh_cannot_answer(session_factory, store, acme):
    limited, spotter_calls = spotter(PAGES, status_seq=[429], retry_after="3000")
    broken, _ = crtsh({"acme.example": [(504, b"")]})
    job = CtJob(store, [limited, broken])
    waited = []

    def fake_wait(seconds):
        waited.append(seconds)
        limited._blocked_until = 0.0

    job._wait = fake_wait
    run = run_import(session_factory, store, job, csv_bytes(["company_key", "domain"], ["acme", "acme.example"]),
                     source_url="file:///t.csv")
    assert run.status == "succeeded" and len(waited) == 1 and 2990 < waited[0] <= 3000
    assert spotter_calls == ["", "", "2", "3"]
    with session_factory() as s:
        lookup = s.scalars(select(CtLookup)).one()
    assert (lookup.source, lookup.complete) == ("certspotter", True) and count(session_factory, Certificate) == 3
