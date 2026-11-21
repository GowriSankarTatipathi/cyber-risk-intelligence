"""HIBP public breach catalogue (issue 11.1). Synthetic catalogues and a mocked client; nothing is contacted."""
# ruff: noqa: F811 - pytest fixtures imported from test_exposure

import json

import httpx
import pytest
from sqlalchemy import func, select, text

from cyber_risk_intelligence.breaches import (
    HibpBreachesJob,
    HibpClient,
    HibpUnavailable,
    RestrictedEndpoint,
)
from cyber_risk_intelligence.breaches.__main__ import access, summary
from cyber_risk_intelligence.evidence import read_evidence
from cyber_risk_intelligence.ingest import run_import
from cyber_risk_intelligence.models import (
    BreachSourceAccessNote,
    EvidenceVersion,
    IngestionError,
    PublicBreachMetadata,
)

from .test_exposure import acme, store  # noqa: F401 - fixtures


def breach(name="Acme", **kw):
    b = {"Name": name, "Title": name, "Domain": "acme.example", "BreachDate": "2026-06-15",
         "AddedDate": "2026-07-01T10:00:00Z", "ModifiedDate": "2026-07-01T10:00:00Z", "PwnCount": 2691852,
         "Description": "In June 2026, Acme suffered a breach exposing customer records.",
         "LogoPath": "https://logos.haveibeenpwned.com/Acme.png", "Attribution": None, "DisclosureUrl": None,
         "DataClasses": ["Email addresses", "Names", "Passwords"], "IsVerified": True, "IsFabricated": False,
         "IsSensitive": False, "IsRetired": False, "IsSpamList": False, "IsMalware": False,
         "IsSubscriptionFree": False, "IsStealerLog": False}
    b.update(kw)
    return b


def catalogue(*breaches):
    return json.dumps(list(breaches)).encode()


def load(sf, store, content):
    return run_import(sf, store, HibpBreachesJob(), content, source_url="https://haveibeenpwned.com/api/v3/breaches")


def test_catalogue_is_stored_traceably_and_a_repeat_changes_nothing(session_factory, store):
    content = catalogue(breach(), breach("ShopX", Domain="shopx.example", PwnCount=None, BreachDate="",
                                         DataClasses=["Email addresses"]),
                        breach("Combo", Domain="", IsSpamList=True, IsVerified=False))
    run = load(session_factory, store, content)
    assert (run.status, run.rows_inserted) == ("succeeded", 3)
    with session_factory() as s:
        b = s.scalar(select(PublicBreachMetadata).where(PublicBreachMetadata.name == "Acme"))
        assert (b.domain, str(b.breach_date), b.pwn_count, b.is_verified) == ("acme.example", "2026-06-15", 2691852, True)
        assert b.data_classes == ["Email addresses", "Names", "Passwords"] and b.added_at.tzinfo is not None
        assert b.evidence_version_id == run.input_evidence_version_id  # the stored catalogue
        assert b.first_seen_run_id == b.last_seen_run_id == run.id
        shop = s.scalar(select(PublicBreachMetadata).where(PublicBreachMetadata.name == "ShopX"))
        assert shop.pwn_count is None and shop.breach_date is None  # not given = unknown, not zero
        combo = s.scalar(select(PublicBreachMetadata).where(PublicBreachMetadata.name == "Combo"))
        assert (combo.domain, combo.is_spam_list, combo.is_verified) == (None, True, False)
        notes = {n.capability: n for n in s.scalars(select(BreachSourceAccessNote))}
        assert notes["breach_catalogue"].used and notes["breach_catalogue"].access == "public"
        assert notes["domain_search"].access == "verified_domain" and not notes["domain_search"].used
        assert not any(n.used for n in notes.values() if n.access != "public")

    again = load(session_factory, store, content)
    assert (again.rows_unchanged, again.rows_inserted, again.rows_updated) == (3, 0, 0)
    assert again.data_version_id == run.data_version_id
    with session_factory() as s:
        assert s.scalar(select(func.count()).select_from(PublicBreachMetadata)) == 3
        assert s.scalar(select(func.count()).select_from(BreachSourceAccessNote)) == 7


def test_stored_records_hold_metadata_and_no_credentials(session_factory, store):
    run = load(session_factory, store, catalogue(breach()))
    with session_factory() as s:
        stored = read_evidence(s, store, s.get(EvidenceVersion, run.input_evidence_version_id))
        columns = {c.name for c in PublicBreachMetadata.__table__.columns}
    assert not {"email", "emails", "password", "passwords", "account", "accounts"} & columns
    assert json.loads(stored)[0]["Name"] == "Acme" and b"@" not in stored  # catalogue metadata only


def test_changes_update_with_new_evidence_and_removed_breaches_are_kept(session_factory, store):
    load(session_factory, store, catalogue(breach(), breach("Old", Domain="old.example")))
    second = load(session_factory, store, catalogue(breach(PwnCount=3000000, ModifiedDate="2026-08-01T00:00:00Z")))
    assert (second.rows_updated, second.rows_inserted) == (1, 0)
    with session_factory() as s:
        b = s.scalar(select(PublicBreachMetadata).where(PublicBreachMetadata.name == "Acme"))
        assert b.pwn_count == 3000000 and b.evidence_version_id == second.input_evidence_version_id
        old = s.scalar(select(PublicBreachMetadata).where(PublicBreachMetadata.name == "Old"))
        assert old.last_seen_run_id < second.id  # left the catalogue, kept for history


def test_bad_values_are_unknown_and_a_nameless_breach_is_rejected(session_factory, store):
    run = load(session_factory, store, catalogue(breach("Weird", Domain="not a domain", BreachDate="June",
                                                        PwnCount=-5), breach(Name="")))
    assert (run.status, run.rows_inserted, run.rows_rejected) == ("partial", 1, 1)
    with session_factory() as s:
        w = s.scalar(select(PublicBreachMetadata))
        assert (w.domain, w.breach_date, w.pwn_count) == (None, None, None)
        assert s.scalar(select(IngestionError.code).where(IngestionError.run_id == run.id)) == "name_required"


def test_company_link_needs_the_company_domain(session_factory, store, acme, capsys):
    load(session_factory, store, catalogue(
        breach(), breach("AcmeShop", Domain="shop.acme.example"), breach("NotAcme", Domain="acme.example.net"),
        breach("AcmeRewards", Title="Acme Rewards", Domain="acmerewards.example"),
        breach("Elsewhere", Domain="elsewhere.example")))
    with session_factory() as s:
        rows = {r.breach_name: r for r in s.execute(text("SELECT * FROM company_public_breaches"))}
    assert set(rows) == {"Acme", "AcmeShop"}
    assert (rows["Acme"].match_basis, rows["AcmeShop"].match_basis) == ("same_domain", "subdomain")
    assert rows["Acme"].passwords_exposed and rows["Acme"].in_latest_catalogue
    summary(session_factory)
    out = capsys.readouterr().out
    assert "2 breaches, 1 companies" in out and "NOT linked" in out and "AcmeRewards" in out
    access(session_factory)
    assert "domain_search (verified_domain, not used)" in capsys.readouterr().out


def client(handler, calls):
    def record(request):
        calls.append(request)
        return handler(request)
    return HibpClient(httpx.Client(transport=httpx.MockTransport(record)), backoff_s=0)


@pytest.mark.parametrize("path", ["breachedDomain/acme.example", "breacheddomain/acme.example",
                                  "breachedaccount/someone@acme.example", "pasteAccount/someone@acme.example",
                                  "stealerLogsByWebsiteDomain/acme.example", "subscribeddomains",
                                  "breaches/../breacheddomain/acme.example", "breach/../breacheddomain/acme.example"])
def test_restricted_searches_are_refused_before_any_request(path):
    calls = []
    hibp = client(lambda r: httpx.Response(200, json=[]), calls)
    with pytest.raises(RestrictedEndpoint):
        hibp.get(path)
    assert calls == []


def test_public_catalogue_download_retries_and_sends_no_key():
    calls = []
    answers = [httpx.Response(429, headers={"retry-after": "0"}), httpx.Response(503),
               httpx.Response(200, content=catalogue(breach()))]
    hibp = client(lambda r: answers.pop(0), calls)
    assert json.loads(hibp.catalogue())[0]["Name"] == "Acme"
    assert len(calls) == 3 and all("hibp-api-key" not in c.headers for c in calls)
    assert str(calls[0].url) == "https://haveibeenpwned.com/api/v3/breaches"

    calls.clear()
    with pytest.raises(HibpUnavailable):
        client(lambda r: httpx.Response(403), calls).catalogue()
    assert len(calls) == 1  # 403 is not retried
