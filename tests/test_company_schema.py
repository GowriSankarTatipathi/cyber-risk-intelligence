"""Acceptance tests for issue 17.1 (company and legal-entity schema)."""

from datetime import date

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from cyber_risk_intelligence.models import (
    Company,
    CompanyAlias,
    CompanyDomain,
    Domain,
    EntityIdentifier,
    EntityRelationship,
    IndexMembership,
    IndustryClassification,
    LegalEntity,
)
from cyber_risk_intelligence.normalize import normalize_domain, normalize_identifier, normalize_name


def make_company(session, key="microsoft", name="Microsoft"):
    c = Company(company_key=key, display_name=name, normalized_name=normalize_name(name))
    session.add(c)
    session.flush()
    return c


def make_entity(session, company, legal_name, country="US", **kw):
    e = LegalEntity(
        company=company,
        legal_name=legal_name,
        normalized_name=normalize_name(legal_name),
        jurisdiction_country=country,
        **kw,
    )
    session.add(e)
    session.flush()
    return e


def ident(entity, scheme, value, scope="", **kw):
    return EntityIdentifier(
        legal_entity_id=entity.id,
        scheme=scheme,
        issuer_scope=scope,
        value=value,
        normalized_value=normalize_identifier(scheme, value),
        **kw,
    )


def expect_violation(session, obj, constraint):
    """Insert ``obj`` inside a savepoint and assert the named constraint rejects it."""
    with pytest.raises(IntegrityError) as err:
        with session.begin_nested():
            session.add(obj)
            session.flush()
    assert constraint in str(err.value)


def test_company_with_legal_entity_and_identifiers(session):
    msft = make_company(session)
    corp = make_entity(session, msft, "Microsoft Corporation", jurisdiction_subdivision="US-WA")
    session.add_all(
        [
            ident(corp, "sec_cik", "789019", "US-SEC", verification_status="verified", source_ref="https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=0000789019"),
            ident(corp, "lei", "INR2EJN1ERAN0W5ZP974", "GLEIF"),
            ident(corp, "ticker", "MSFT", "NASDAQ"),
        ]
    )
    session.flush()
    found = session.scalar(
        select(LegalEntity)
        .join(EntityIdentifier)
        .where(EntityIdentifier.scheme == "sec_cik", EntityIdentifier.normalized_value == "0000789019")
    )
    assert found is corp
    assert found.company.company_key == "microsoft"
    assert {i.scheme for i in found.identifiers} == {"sec_cik", "lei", "ticker"}


def test_duplicate_normalized_identifier_is_rejected(session):
    msft = make_company(session)
    a = make_entity(session, msft, "Microsoft Corporation")
    b = make_entity(session, msft, "Microsoft Corp (duplicate record)")
    session.add(ident(a, "sec_cik", "789019", "US-SEC"))
    session.flush()
    # Same CIK, written differently, on another entity: must collide.
    expect_violation(session, ident(b, "sec_cik", "0000789019", "US-SEC"), "no_overlapping_identifier")


def test_identifier_can_be_reused_after_its_validity_ends(session):
    co = make_company(session, "acme", "Acme")
    old = make_entity(session, co, "Acme Holdings Inc.")
    new = make_entity(session, co, "Acme Technologies Inc.")
    session.add(ident(old, "ticker", "ACME", "NYSE", valid_from=date(2010, 1, 1), valid_to=date(2020, 1, 1)))
    session.add(ident(new, "ticker", "ACME", "NYSE", valid_from=date(2020, 1, 1)))
    session.flush()
    # The same ticker on another exchange is a different identifier.
    session.add(ident(old, "ticker", "ACME", "LSE"))
    session.flush()
    # But it may not overlap the current holder's period.
    expect_violation(
        session,
        ident(old, "ticker", "ACME", "NYSE", valid_from=date(2019, 6, 1), valid_to=date(2021, 1, 1)),
        "no_overlapping_identifier",
    )


def test_open_ended_identifiers_overlap(session):
    co = make_company(session, "acme", "Acme")
    a = make_entity(session, co, "Acme Inc.")
    b = make_entity(session, co, "Acme Labs Inc.")
    session.add(ident(a, "lei", "INR2EJN1ERAN0W5ZP974", "GLEIF"))
    session.flush()
    # Unknown dates are treated as "could be any time", so this conflicts.
    expect_violation(session, ident(b, "lei", "INR2EJN1ERAN0W5ZP974", "GLEIF"), "no_overlapping_identifier")


def test_identifier_formats_are_checked_by_the_database(session):
    co = make_company(session)
    e = make_entity(session, co, "Microsoft Corporation")
    bad_cik = EntityIdentifier(legal_entity_id=e.id, scheme="sec_cik", value="789019", normalized_value="789019")
    expect_violation(session, bad_cik, "ck_entity_identifiers_cik_format")
    bad_lei = EntityIdentifier(legal_entity_id=e.id, scheme="lei", value="x", normalized_value="SHORT")
    expect_violation(session, bad_lei, "ck_entity_identifiers_lei_format")
    bad_scheme = EntityIdentifier(legal_entity_id=e.id, scheme="isin", value="x", normalized_value="X")
    expect_violation(session, bad_scheme, "ck_entity_identifiers_scheme")


def test_orphan_records_are_rejected(session):
    expect_violation(
        session,
        EntityIdentifier(legal_entity_id=999_999_999, scheme="ticker", value="X", normalized_value="X"),
        "fk_entity_identifiers_legal_entity_id_legal_entities",
    )
    expect_violation(
        session,
        LegalEntity(company_id=999_999_999, legal_name="Ghost Inc.", normalized_name="ghost"),
        "fk_legal_entities_company_id_companies",
    )
    expect_violation(
        session,
        CompanyAlias(company_id=999_999_999, alias="Ghost", normalized_alias="ghost", alias_type="brand"),
        "fk_company_aliases_company_id_companies",
    )


def test_company_with_entities_cannot_be_deleted(session):
    co = make_company(session)
    make_entity(session, co, "Microsoft Corporation")
    with pytest.raises(IntegrityError):
        with session.begin_nested():
            session.execute(Company.__table__.delete().where(Company.id == co.id))


def test_similar_names_stay_separate_entities(session):
    apple = make_company(session, "apple", "Apple")
    reit = make_company(session, "apple-hospitality-reit", "Apple Hospitality REIT")
    a = make_entity(session, apple, "Apple Inc.")
    b = make_entity(session, reit, "Apple Hospitality REIT, Inc.")
    # Even an identical legal name in another jurisdiction is a separate entity.
    c = make_entity(session, apple, "Apple Inc.", country="IE")
    session.flush()
    assert len({a.id, b.id, c.id}) == 3
    rows = session.scalars(select(LegalEntity).where(LegalEntity.normalized_name == "apple")).all()
    assert {r.id for r in rows} == {a.id, c.id}


def test_time_bound_subsidiary_relationship(session):
    msft = make_company(session)
    parent = make_entity(session, msft, "Microsoft Corporation")
    linkedin = make_entity(session, msft, "LinkedIn Corporation")
    rel = EntityRelationship(
        child_entity_id=linkedin.id,
        parent_entity_id=parent.id,
        relationship_type="subsidiary_of",
        ownership_pct=100,
        valid_from=date(2016, 12, 8),
        verification_status="observed",
        source_ref="Microsoft 10-K FY2017, Exhibit 21",
    )
    session.add(rel)
    session.flush()

    def parents_on(day):
        return session.scalars(
            select(EntityRelationship.parent_entity_id).where(
                EntityRelationship.child_entity_id == linkedin.id,
                EntityRelationship.valid_from <= day,
                (EntityRelationship.valid_to.is_(None)) | (EntityRelationship.valid_to > day),
            )
        ).all()

    assert parents_on(date(2015, 1, 1)) == []
    assert parents_on(date(2026, 1, 1)) == [parent.id]

    overlapping = EntityRelationship(
        child_entity_id=linkedin.id,
        parent_entity_id=parent.id,
        relationship_type="subsidiary_of",
        valid_from=date(2020, 1, 1),
    )
    expect_violation(session, overlapping, "no_overlapping_relationship")


def test_relationship_checks(session):
    co = make_company(session)
    a = make_entity(session, co, "Microsoft Corporation")
    b = make_entity(session, co, "GitHub, Inc.")
    expect_violation(
        session,
        EntityRelationship(child_entity_id=a.id, parent_entity_id=a.id, relationship_type="subsidiary_of"),
        "ck_entity_relationships_not_self",
    )
    expect_violation(
        session,
        EntityRelationship(child_entity_id=b.id, parent_entity_id=a.id, relationship_type="owned_by"),
        "ck_entity_relationships_relationship_type",
    )
    expect_violation(
        session,
        EntityRelationship(child_entity_id=b.id, parent_entity_id=a.id, relationship_type="subsidiary_of", ownership_pct=150),
        "ck_entity_relationships_ownership_pct",
    )
    expect_violation(
        session,
        EntityRelationship(
            child_entity_id=b.id,
            parent_entity_id=a.id,
            relationship_type="acquired_by",
            valid_from=date(2018, 10, 26),
            valid_to=date(2018, 10, 26),
        ),
        "ck_entity_relationships_valid_period",
    )


def test_unknowns_are_stored_as_null_and_default_to_unknown_status(session):
    co = make_company(session, "mystery", "Mystery Co")
    e = LegalEntity(company_id=co.id, legal_name="Mystery Co LLC", normalized_name="mystery")
    session.add(e)
    session.flush()
    session.refresh(e)
    assert e.jurisdiction_country is None
    assert e.entity_status == "unknown"
    assert e.verification_status == "unknown"
    assert e.source_ref is None and e.observed_at is None
    assert e.collected_at is not None
    # An entity not yet linked to a company is allowed (unknown parent group).
    loose = LegalEntity(legal_name="Unlinked Ltd", normalized_name="unlinked")
    session.add(loose)
    session.flush()
    assert loose.company_id is None


def test_verification_status_and_country_are_checked(session):
    co = make_company(session)
    expect_violation(
        session,
        LegalEntity(company_id=co.id, legal_name="X Inc.", normalized_name="x", verification_status="trust_me"),
        "ck_legal_entities_verification_status",
    )
    expect_violation(
        session,
        LegalEntity(company_id=co.id, legal_name="X Inc.", normalized_name="x", jurisdiction_country="usa"),
        "ck_legal_entities_jurisdiction_country_iso",
    )
    expect_violation(
        session,
        LegalEntity(company_id=co.id, legal_name="   ", normalized_name=""),
        "ck_legal_entities_legal_name_not_blank",
    )
    expect_violation(
        session,
        Company(company_key="Bad Key", display_name="Bad", normalized_name="bad"),
        "ck_companies_company_key_format",
    )


def test_aliases_domains_classifications_and_index_membership(session):
    msft = make_company(session)
    corp = make_entity(session, msft, "Microsoft Corporation")
    session.add_all(
        [
            CompanyAlias(company_id=msft.id, legal_entity_id=corp.id, alias="Microsoft Corp.", normalized_alias=normalize_name("Microsoft Corp."), alias_type="abbreviation"),
            CompanyAlias(company_id=msft.id, alias="Xbox", normalized_alias="xbox", alias_type="brand"),
        ]
    )
    dom = Domain(name=normalize_domain("https://www.Microsoft.com/"))
    session.add(dom)
    session.flush()
    session.add(CompanyDomain(company_id=msft.id, legal_entity_id=corp.id, domain_id=dom.id, role="primary_website", verification_status="observed"))
    session.add(IndustryClassification(company_id=msft.id, system="GICS", code="451030", label="Software", level="industry"))
    session.add(IndexMembership(company_id=msft.id, index_name="Dow Jones Industrial Average", ticker="MSFT", observed_on=date(2026, 11, 16)))
    session.flush()

    expect_violation(
        session,
        CompanyAlias(company_id=msft.id, alias="XBOX", normalized_alias="xbox", alias_type="brand"),
        "uq_company_aliases_alias",
    )
    expect_violation(session, Domain(name="Microsoft.com"), "ck_domains_name_normalized")
    expect_violation(
        session,
        CompanyDomain(company_id=msft.id, domain_id=dom.id, role="primary_website"),
        "no_overlapping_company_domain",
    )
    # NULL code/level are treated as equal for duplicate detection.
    session.add(IndustryClassification(company_id=msft.id, system="project_group", label="Big Tech"))
    session.flush()
    expect_violation(
        session,
        IndustryClassification(company_id=msft.id, system="project_group", label="Big Tech"),
        "uq_industry_classifications_entry",
    )
    expect_violation(
        session,
        IndexMembership(company_id=msft.id, index_name="Dow Jones Industrial Average", observed_on=date(2026, 11, 16)),
        "uq_index_memberships_observation",
    )
