"""Acceptance tests for issue 17.7 (evidence and historical storage).

All content here is synthetic; no network access.
"""

from datetime import UTC, date, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.evidence import (
    ChecksumMismatch,
    LocalStore,
    SecretDetected,
    find_secrets,
    link_evidence,
    read_evidence,
    record_evidence,
)
from cyber_risk_intelligence.evidence.store import sha256_hex
from cyber_risk_intelligence.models import (
    Company,
    EntityIdentifier,
    EvidenceLink,
    EvidenceObject,
    EvidenceVersion,
    LegalEntity,
    Source,
)

FILING = b"<html><body><h1>Example Corp 10-K</h1><p>Subsidiaries: Example Labs LLC</p></body></html>"
FILING_V2 = FILING.replace(b"10-K", b"10-K/A")


@pytest.fixture
def store(tmp_path):
    return LocalStore(tmp_path)


@pytest.fixture
def sec(session):
    s = Source(
        source_key="sec_edgar",
        name="SEC EDGAR",
        source_type="regulator",
        access_method="api",
        base_url="https://www.sec.gov/",
        terms_url="https://www.sec.gov/os/accessing-edgar-data",
        rate_limit_note="10 requests/second, declared User-Agent",
    )
    session.add(s)
    session.flush()
    return s


@pytest.fixture
def entity(session):
    c = Company(company_key="example", display_name="Example", normalized_name="example")
    e = LegalEntity(company=c, legal_name="Example Corp", normalized_name="example", jurisdiction_country="US")
    session.add(e)
    session.flush()
    return e


URL = "https://www.sec.gov/Archives/edgar/data/1234567/example-10k.htm"


def test_bytes_round_trip_with_same_checksum(session, store, sec):
    v = record_evidence(session, store, source=sec, source_url=URL, content=FILING, media_type="text/html")
    assert v.evidence_object.sha256 == sha256_hex(FILING)
    assert v.evidence_object.size_bytes == len(FILING)
    assert v.evidence_object.object_key == f"sha256/{sha256_hex(FILING)[:2]}/{sha256_hex(FILING)}"
    assert read_evidence(session, store, v) == FILING


def test_tampered_object_is_detected(session, store, sec):
    v = record_evidence(session, store, source=sec, source_url=URL, content=FILING, media_type="text/html")
    path = store.root / store.bucket / v.evidence_object.object_key
    path.write_bytes(FILING + b"tampered")
    with pytest.raises(ChecksumMismatch):
        read_evidence(session, store, v)


def test_missing_dates_stay_unknown(session, store, sec):
    v = record_evidence(session, store, source=sec, source_url=URL, content=FILING, media_type="text/html")
    session.refresh(v)
    assert v.published_at is None
    assert v.observed_at is None
    assert v.archive_captured_at is None
    assert v.collected_at is not None


def test_dates_are_kept_separately(session, store, sec):
    published = datetime(2025, 7, 30, tzinfo=UTC)
    captured = datetime(2025, 8, 2, 12, 0, tzinfo=UTC)
    v = record_evidence(
        session, store, source=sec, source_url=URL, content=FILING, media_type="text/html",
        published_at=published,
        archive_url="https://web.archive.org/web/20250802120000/" + URL,
        archive_captured_at=captured,
    )
    session.refresh(v)
    assert v.published_at == published
    assert v.archive_captured_at == captured
    assert v.collected_at.date() >= date(2026, 1, 1)


def test_repeat_capture_is_idempotent_and_changes_create_history(session, store, sec):
    v1 = record_evidence(session, store, source=sec, source_url=URL, content=FILING, media_type="text/html")
    again = record_evidence(session, store, source=sec, source_url=URL, content=FILING, media_type="text/html",
                            published_at=datetime(2025, 7, 30, tzinfo=UTC))
    assert again.id == v1.id
    assert again.published_at is not None  # a date learned later is filled in
    v2 = record_evidence(session, store, source=sec, source_url=URL, content=FILING_V2, media_type="text/html")
    assert v2.id != v1.id
    history = session.scalars(
        select(EvidenceVersion).where(EvidenceVersion.source_url == URL).order_by(EvidenceVersion.id)
    ).all()
    assert [h.evidence_object.sha256 for h in history] == [sha256_hex(FILING), sha256_hex(FILING_V2)]
    assert session.scalar(select(EvidenceObject).where(EvidenceObject.sha256 == sha256_hex(FILING))) is not None


def test_same_bytes_from_two_urls_share_one_object(session, store, sec):
    a = record_evidence(session, store, source=sec, source_url=URL, content=FILING, media_type="text/html")
    b = record_evidence(session, store, source=sec, source_url=URL + "?mirror=1", content=FILING, media_type="text/html")
    assert a.id != b.id
    assert a.evidence_object_id == b.evidence_object_id


def test_one_object_supports_several_records(session, store, sec, entity):
    cik = EntityIdentifier(legal_entity_id=entity.id, scheme="sec_cik", issuer_scope="US-SEC",
                           value="1234567", normalized_value="0001234567")
    session.add(cik)
    session.flush()
    v = record_evidence(session, store, source=sec, source_url=URL, content=FILING, media_type="text/html")
    link_evidence(session, v, entity, locator="cover page")
    link_evidence(session, v, cik, locator="dei:EntityCentralIndexKey")
    link_evidence(session, v, entity.company)
    assert len(v.links) == 3
    # A record can cite more than one capture, including one that contradicts it.
    other = record_evidence(session, store, source=sec, source_url=URL, content=FILING_V2, media_type="text/html")
    link_evidence(session, other, entity, relation="contradicts")
    rows = session.scalars(select(EvidenceLink).where(EvidenceLink.legal_entity_id == entity.id)).all()
    assert {r.relation for r in rows} == {"supports", "contradicts"}


def test_links_need_exactly_one_existing_target(session, store, sec, entity):
    v = record_evidence(session, store, source=sec, source_url=URL, content=FILING, media_type="text/html")
    for bad, constraint in [
        (EvidenceLink(evidence_version_id=v.id), "ck_evidence_links_exactly_one_target"),
        (EvidenceLink(evidence_version_id=v.id, legal_entity_id=entity.id, company_id=entity.company_id),
         "ck_evidence_links_exactly_one_target"),
        (EvidenceLink(evidence_version_id=v.id, legal_entity_id=999_999_999),
         "fk_evidence_links_legal_entity_id_legal_entities"),
    ]:
        with pytest.raises(IntegrityError) as err:
            with session.begin_nested():
                session.add(bad)
                session.flush()
        assert constraint in str(err.value)
    link_evidence(session, v, entity)
    with pytest.raises(IntegrityError, match="uq_evidence_links_link"):
        with session.begin_nested():
            link_evidence(session, v, entity)


def test_evidence_in_use_cannot_be_deleted(session, store, sec, entity):
    v = record_evidence(session, store, source=sec, source_url=URL, content=FILING, media_type="text/html")
    link_evidence(session, v, entity)
    with pytest.raises(IntegrityError):
        with session.begin_nested():
            session.execute(EvidenceVersion.__table__.delete().where(EvidenceVersion.id == v.id))
    with pytest.raises(IntegrityError):
        with session.begin_nested():
            session.execute(Source.__table__.delete().where(Source.id == sec.id))


@pytest.mark.parametrize(
    "leak, kind",
    [
        (b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "private_key"),
        (b"aws_key = AKIAABCDEFGHIJKLMNOP", "aws_access_key_id"),
        (b"token ghp_" + b"a" * 36, "github_token"),
        (b"postgres://admin:hunter2pass@db.example.com/prod", "url_with_password"),
        (b'config: {"password": "CorrectHorse99"}', "password_assignment"),
    ],
)
def test_content_with_secrets_is_rejected(session, store, sec, tmp_path, leak, kind):
    assert kind in find_secrets(leak)
    with pytest.raises(SecretDetected) as err:
        record_evidence(session, store, source=sec, source_url=URL, content=FILING + leak, media_type="text/html")
    assert leak.decode(errors="ignore")[-6:] not in str(err.value)
    assert not any(p.is_file() for p in tmp_path.rglob("*"))
    assert session.scalar(select(EvidenceObject)) is None


def test_ordinary_public_text_is_not_flagged():
    page = b"Reset your password at https://example.com/account. Our API key rotation policy is 90 days."
    assert find_secrets(page) == []


def test_unpermitted_source_is_refused(session, store, sec):
    sec.is_permitted = False
    with pytest.raises(PermissionError):
        record_evidence(session, store, source=sec, source_url=URL, content=FILING, media_type="text/html")


def test_source_and_object_checks(session):
    for bad, constraint in [
        (Source(source_key="Bad Key", name="x", source_type="regulator", access_method="api"), "ck_sources_source_key_format"),
        (Source(source_key="x", name="x", source_type="rumour", access_method="api"), "ck_sources_source_type"),
        (EvidenceObject(sha256="abc", size_bytes=1, media_type="text/plain", storage_backend="local", bucket="b", object_key="k"),
         "ck_evidence_objects_sha256_format"),
        (EvidenceObject(sha256="0" * 64, size_bytes=1, media_type="text/plain", storage_backend="s3", bucket="b", object_key="k"),
         "ck_evidence_objects_storage_backend"),
    ]:
        with pytest.raises(IntegrityError) as err:
            with session.begin_nested():
                session.add(bad)
                session.flush()
        assert constraint in str(err.value)
