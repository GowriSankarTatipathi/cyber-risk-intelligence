"""DKIM keys at selectors known from public evidence (issue 23.3). Fake resolver only; no DNS queries."""

import base64
import csv
import io

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import select

from cyber_risk_intelligence.domains import CompanyDomainsJob
from cyber_risk_intelligence.email_security import (
    DkimJob,
    KnownSelector,
    TxtLookup,
    read_dkim,
    selectors_from_spf,
)
from cyber_risk_intelligence.email_security.__main__ import (
    dkim_summary,
    published_selectors,
)
from cyber_risk_intelligence.email_security.dkim import MAX_SPF_LOOKUPS, spf_includes
from cyber_risk_intelligence.evidence import LocalStore
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import DkimEvidence, DnsSecurityRecord

from . import factories as f

NX = TxtLookup("nxdomain", "fake-resolver", rcode="NXDOMAIN")


def rsa_key(bits=2048):
    der = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


KEY = rsa_key()


class FakeResolver:
    name = "fake-resolver"

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def txt(self, name):
        self.calls.append(name)
        a = self.answers.get(name, NX)
        if isinstance(a, TxtLookup):
            return a
        return TxtLookup("answered", self.name, rcode="NOERROR", answers=a, ttl=300)


# --- reading a key ---------------------------------------------------------------------------------------

def test_rsa_key_is_found_with_its_size():
    k = read_dkim(f"v=DKIM1; k=rsa; p={KEY}")
    assert (k.status, k.key_type, k.key_bits, k.problem) == ("key_found", "rsa", 2048, None)
    split = KEY[:100] + " " + KEY[100:]  # keys are often split across strings with spaces
    assert read_dkim(f"v=DKIM1; p={split}").key_bits == 2048


def test_damaged_key_is_invalid_and_1024_bits_is_not_flagged():
    k = read_dkim(f"p={rsa_key(1024)[:-4]}")  # damaged: not a readable key
    assert k.status == "invalid"
    small = base64.b64encode(rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
                             .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()
    assert read_dkim(f"p={small}").problem is None  # 1024 is the floor, not under it


def test_revoked_invalid_and_ed25519():
    assert read_dkim("v=DKIM1; p=").status == "revoked"
    assert read_dkim("v=DKIM1; k=rsa").status == "invalid"
    assert read_dkim("v=DKIM1; p=!!!notbase64").status == "invalid"
    assert read_dkim("v=spf1 -all; p=x").status == "invalid"
    raw = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    k = read_dkim(f"v=DKIM1; k=ed25519; p={base64.b64encode(raw).decode()}")
    assert (k.status, k.key_type) == ("key_found", "ed25519")


# --- which selectors are known ----------------------------------------------------------------------------

def test_providers_are_found_through_nested_spf_includes():
    r = FakeResolver({"acme.example": [["v=spf1 include:_spf.acme.example -all"]],
                      "_spf.acme.example": [["v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net ~all"]],
                      "spf.protection.outlook.com": [["v=spf1 ip4:192.0.2.0/24 -all"]],
                      "servers.mcsv.net": [["v=spf1 ip4:198.51.100.0/24 -all"]]})
    known = selectors_from_spf("acme.example", r.txt)
    assert [k.selector for k in known] == ["selector1", "selector2", "k2", "k3"]
    assert "acme.example -> _spf.acme.example -> spf.protection.outlook.com" in known[0].evidence
    assert known[0].source == "spf_provider" and known[0].source_url.startswith("https://learn.microsoft.com/")
    assert all("_domainkey" not in c for c in r.calls)  # finding selectors asks only SPF names


def test_spf_walk_stops_at_the_spf_lookup_limit():
    chain = {f"n{i}.example": [[f"v=spf1 include:n{i + 1}.example -all"]] for i in range(30)}
    r = FakeResolver({"acme.example": [["v=spf1 include:n0.example -all"]], **chain})
    _, lookups = spf_includes("acme.example", r.txt)
    assert lookups == MAX_SPF_LOOKUPS and len(r.calls) == MAX_SPF_LOOKUPS


def test_no_spf_or_unknown_provider_means_no_selector():
    assert selectors_from_spf("acme.example", FakeResolver({}).txt) == []
    r = FakeResolver({"acme.example": [["v=spf1 include:mail.unknown-vendor.example -all"]]})
    assert selectors_from_spf("acme.example", r.txt) == []


# --- the job ---------------------------------------------------------------------------------------------

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


def collect(sf, store, answers, published=None):
    resolver = FakeResolver(answers)
    run = run_import(sf, store, DkimJob(store, resolver, published=published),
                     csv_bytes(["company_key", "domain"], ["acme", "acme.example"]), source_url="file:///t.csv")
    return run, resolver


MICROSOFT = {"acme.example": [["v=spf1 include:spf.protection.outlook.com -all"]],
             "spf.protection.outlook.com": [["v=spf1 -all"]],
             "selector1._domainkey.acme.example": [["v=DKIM1; k=rsa; ", f"p={KEY}"]]}


def test_key_at_one_known_selector(session_factory, store, acme, capsys):
    run, resolver = collect(session_factory, store, MICROSOFT)
    assert run.status == "succeeded" and run.rows_inserted == 1
    assert [c for c in resolver.calls if "_domainkey" in c] == ["selector1._domainkey.acme.example",
                                                                 "selector2._domainkey.acme.example"]
    with session_factory() as s:
        rows = {e.selector: e for e in s.scalars(select(DkimEvidence))}
        lookups = s.scalars(select(DnsSecurityRecord)).all()
    one, two = rows["selector1"], rows["selector2"]
    assert (one.outcome, one.key_type, one.key_bits) == ("key_found", "rsa", 2048)
    assert one.evidence_version_id is not None and one.dns_record_id is not None
    assert "Microsoft 365" in one.selector_evidence and one.selector_source == "spf_provider"
    assert two.outcome == "not_found"  # says nothing about selectors we don't know
    assert len(lookups) == 2  # only the DKIM lookups are stored, not the SPF walk
    dkim_summary(session_factory)
    out = capsys.readouterr().out
    assert "key_found" in out and "Microsoft 365" in out and "key found: 1" in out

    run, _ = collect(session_factory, store, MICROSOFT)
    assert run.rows_unchanged == 1


def test_no_known_selector_is_unknown_not_absent(session_factory, store, acme, capsys):
    run, resolver = collect(session_factory, store, {"acme.example": [["v=spf1 ip4:192.0.2.1 -all"]]})
    assert run.rows_updated == 1 and not any("_domainkey" in c for c in resolver.calls)
    with session_factory() as s:
        e = s.scalars(select(DkimEvidence)).one()
    assert (e.outcome, e.selector, e.dns_record_id) == ("no_known_selector", None, None)
    assert "unknown" in e.problem
    dkim_summary(session_factory)
    assert "no known selector: 1" in capsys.readouterr().out


def test_failed_lookup_is_kept_apart(session_factory, store, acme):
    answers = {**MICROSOFT, "selector1._domainkey.acme.example": TxtLookup("lookup_failed", "fake-resolver",
                                                                           rcode="TIMEOUT", message="timed out")}
    collect(session_factory, store, answers)
    with session_factory() as s:
        e = s.scalars(select(DkimEvidence).where(DkimEvidence.selector == "selector1")).one()
    assert (e.outcome, e.evidence_version_id, e.problem) == ("lookup_failed", None, "timed out")


def test_wildcard_txt_at_a_selector_is_not_a_key(session_factory, store, acme):
    spf = [["v=spf1 include:servers.mcsv.net -all"]]
    collect(session_factory, store, {"acme.example": spf, "servers.mcsv.net": [["v=spf1 -all"]],
                                     "k2._domainkey.acme.example": spf, "k3._domainkey.acme.example": spf})
    with session_factory() as s:
        rows = s.scalars(select(DkimEvidence)).all()
    assert {e.outcome for e in rows} == {"not_found"} and all("wildcard" in e.problem for e in rows)
    assert rows[0].record_text.startswith("v=spf1")


def test_published_selector_is_used_with_its_source(session_factory, store, acme, tmp_path):
    path = tmp_path / "selectors.csv"
    path.write_text("company_key,domain,selector,source_url\n"
                    "acme,acme.example,mail2026,https://acme.example/press/email-header.txt\n"
                    "acme,acme.example,nosource,\n")
    published = published_selectors(str(path))
    assert [k.selector for k in published[("acme", "acme.example")]] == ["mail2026"]  # no source, not used
    collect(session_factory, store, {"mail2026._domainkey.acme.example": [[f"p={KEY}"]]}, published)
    with session_factory() as s:
        e = s.scalars(select(DkimEvidence)).one()
    assert (e.selector, e.selector_source, e.outcome) == ("mail2026", "published", "key_found")
    assert e.selector_source_url == "https://acme.example/press/email-header.txt"


def test_known_selector_type():
    assert KnownSelector("s1", "published", "x", "https://x").selector == "s1"
