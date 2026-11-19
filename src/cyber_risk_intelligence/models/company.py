"""Issue 17.1: company and legal-entity schema.

Concepts
--------
* ``companies``: the research subject (a company group such as "Microsoft").
  Every collected fact is ultimately linked to one of these.
* ``legal_entities``: registered legal persons (an issuer, a subsidiary).
  Similar names are allowed; entities are never merged by name.
* ``entity_identifiers``: SEC CIK, LEI, tickers and similar, each with its
  issuing scope and validity period. The same normalized identifier cannot be
  active for two entities at the same time.
* ``entity_relationships``: time-bound links between legal entities
  (subsidiary, acquisition, merger, predecessor/successor).
* ``company_aliases``, ``domains`` + ``company_domains``,
  ``industry_classifications`` and ``index_memberships``: names, web domains,
  sector labels and market-index membership, all dated and sourced.
"""

from datetime import date
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Date,
    ForeignKey,
    Index,
    Numeric,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ExcludeConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import (
    Base,
    IdMixin,
    ProvenanceMixin,
    ValidityMixin,
    in_list,
    provenance_checks,
    validity_checks,
)

PERIOD = text("daterange(valid_from, valid_to, '[)')")

ENTITY_STATUSES = ("active", "inactive", "merged", "dissolved", "unknown")
IDENTIFIER_SCHEMES = ("sec_cik", "lei", "ticker", "opencorporates", "ein", "duns", "other")
ALIAS_TYPES = ("legal_name", "former_name", "trade_name", "brand", "abbreviation", "other")
RELATIONSHIP_TYPES = ("subsidiary_of", "acquired_by", "merged_into", "successor_of", "affiliate_of")
DOMAIN_ROLES = ("primary_website", "corporate", "product", "investor_relations", "trust_center", "email", "other")
CLASSIFICATION_SYSTEMS = ("GICS", "ICB", "NAICS", "SIC", "project_group")


class Company(IdMixin, Base):
    __tablename__ = "companies"

    company_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)

    legal_entities: Mapped[list["LegalEntity"]] = relationship(back_populates="company")
    aliases: Mapped[list["CompanyAlias"]] = relationship(back_populates="company")

    __table_args__ = (
        CheckConstraint("company_key ~ '^[a-z0-9][a-z0-9-]*$'", name="company_key_format"),
        CheckConstraint("length(trim(display_name)) > 0", name="display_name_not_blank"),
    )


class LegalEntity(IdMixin, ProvenanceMixin, Base):
    __tablename__ = "legal_entities"

    company_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="RESTRICT"), index=True
    )
    legal_name: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_name: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    jurisdiction_country: Mapped[str | None] = mapped_column(Text)
    jurisdiction_subdivision: Mapped[str | None] = mapped_column(Text)
    entity_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="unknown")

    company: Mapped[Company | None] = relationship(back_populates="legal_entities")
    identifiers: Mapped[list["EntityIdentifier"]] = relationship(back_populates="legal_entity")

    __table_args__ = (
        CheckConstraint("length(trim(legal_name)) > 0", name="legal_name_not_blank"),
        CheckConstraint("jurisdiction_country ~ '^[A-Z]{2}$'", name="jurisdiction_country_iso"),
        CheckConstraint(in_list("entity_status", ENTITY_STATUSES), name="entity_status"),
        *provenance_checks(),
    )


class EntityIdentifier(IdMixin, ProvenanceMixin, ValidityMixin, Base):
    __tablename__ = "entity_identifiers"

    legal_entity_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("legal_entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scheme: Mapped[str] = mapped_column(Text, nullable=False)
    # Who issued it or where it applies: "US-SEC", "GLEIF", an exchange such as "NASDAQ".
    issuer_scope: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    value: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_value: Mapped[str] = mapped_column(Text, nullable=False)

    legal_entity: Mapped[LegalEntity] = relationship(back_populates="identifiers")

    __table_args__ = (
        CheckConstraint(in_list("scheme", IDENTIFIER_SCHEMES), name="scheme"),
        CheckConstraint("scheme <> 'sec_cik' OR normalized_value ~ '^[0-9]{10}$'", name="cik_format"),
        CheckConstraint("scheme <> 'lei' OR normalized_value ~ '^[A-Z0-9]{18}[0-9]{2}$'", name="lei_format"),
        ExcludeConstraint(
            ("scheme", "="),
            ("issuer_scope", "="),
            ("normalized_value", "="),
            (PERIOD, "&&"),
            name="no_overlapping_identifier",
            using="gist",
        ),
        Index("ix_entity_identifiers_lookup", "scheme", "normalized_value"),
        *provenance_checks(),
        *validity_checks(),
    )


class EntityRelationship(IdMixin, ProvenanceMixin, ValidityMixin, Base):
    """``child`` <relationship_type> ``parent``, e.g. LinkedIn subsidiary_of Microsoft."""

    __tablename__ = "entity_relationships"

    child_entity_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("legal_entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    parent_entity_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("legal_entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relationship_type: Mapped[str] = mapped_column(Text, nullable=False)
    ownership_pct: Mapped[Decimal | None] = mapped_column(Numeric(7, 4))

    child: Mapped[LegalEntity] = relationship(foreign_keys=[child_entity_id])
    parent: Mapped[LegalEntity] = relationship(foreign_keys=[parent_entity_id])

    __table_args__ = (
        CheckConstraint("child_entity_id <> parent_entity_id", name="not_self"),
        CheckConstraint(in_list("relationship_type", RELATIONSHIP_TYPES), name="relationship_type"),
        CheckConstraint("ownership_pct IS NULL OR (ownership_pct > 0 AND ownership_pct <= 100)", name="ownership_pct"),
        ExcludeConstraint(
            ("child_entity_id", "="),
            ("parent_entity_id", "="),
            ("relationship_type", "="),
            (PERIOD, "&&"),
            name="no_overlapping_relationship",
            using="gist",
        ),
        *provenance_checks(),
        *validity_checks(),
    )


class CompanyAlias(IdMixin, ProvenanceMixin, ValidityMixin, Base):
    __tablename__ = "company_aliases"

    company_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    legal_entity_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("legal_entities.id", ondelete="SET NULL"), index=True
    )
    alias: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_alias: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    alias_type: Mapped[str] = mapped_column(Text, nullable=False)

    company: Mapped[Company] = relationship(back_populates="aliases")

    __table_args__ = (
        CheckConstraint(in_list("alias_type", ALIAS_TYPES), name="alias_type"),
        CheckConstraint("length(trim(alias)) > 0", name="alias_not_blank"),
        UniqueConstraint("company_id", "normalized_alias", "alias_type", name="uq_company_aliases_alias"),
        *provenance_checks(),
        *validity_checks(),
    )


class Domain(IdMixin, Base):
    __tablename__ = "domains"

    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)

    __table_args__ = (
        CheckConstraint("name = lower(name) AND name !~ '[/:@ ]' AND position('.' in name) > 1", name="name_normalized"),
    )


class CompanyDomain(IdMixin, ProvenanceMixin, ValidityMixin, Base):
    """A dated, sourced claim that a domain belongs to a company (or one of its entities)."""

    __tablename__ = "company_domains"

    company_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    legal_entity_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("legal_entities.id", ondelete="SET NULL"), index=True
    )
    domain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(Text, nullable=False, server_default="other")

    domain: Mapped[Domain] = relationship()

    __table_args__ = (
        CheckConstraint(in_list("role", DOMAIN_ROLES), name="role"),
        ExcludeConstraint(
            ("company_id", "="),
            ("domain_id", "="),
            ("role", "="),
            (PERIOD, "&&"),
            name="no_overlapping_company_domain",
            using="gist",
        ),
        *provenance_checks(),
        *validity_checks(),
    )


class IndustryClassification(IdMixin, ProvenanceMixin, ValidityMixin, Base):
    __tablename__ = "industry_classifications"

    company_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    system: Mapped[str] = mapped_column(Text, nullable=False)
    code: Mapped[str | None] = mapped_column(Text)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    level: Mapped[str | None] = mapped_column(Text)  # e.g. "sector", "sub-industry"

    __table_args__ = (
        CheckConstraint(in_list("system", CLASSIFICATION_SYSTEMS), name="system"),
        UniqueConstraint(
            "company_id", "system", "level", "label", "valid_from",
            name="uq_industry_classifications_entry",
            postgresql_nulls_not_distinct=True,
        ),
        *provenance_checks(),
        *validity_checks(),
    )


class IndexMembership(IdMixin, ProvenanceMixin, Base):
    """Membership observed on a date, e.g. 'MSFT in the Dow Jones IA on 2026-11-16'."""

    __tablename__ = "index_memberships"

    company_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    index_name: Mapped[str] = mapped_column(Text, nullable=False)
    ticker: Mapped[str | None] = mapped_column(Text)  # share class the membership applies to
    observed_on: Mapped[date] = mapped_column(Date, nullable=False)

    __table_args__ = (
        UniqueConstraint("company_id", "index_name", "observed_on", name="uq_index_memberships_observation"),
        *provenance_checks(),
    )
