"""Import the project's 200-company seed list (CSV export of the research workbook).

Creates or updates, per row: the company, its SEC issuer as a legal entity, the
CIK and ticker identifiers, sector/sub-industry and project-group labels, index
memberships observed on the check date, and the issuer name as an alias. Each
record is linked to the stored CSV as evidence.

Everything is marked ``unverified``: the list was compiled from public sources
but these values have not been re-checked against SEC or the index providers.
Columns not modelled yet (filing dates, research notes) stay in the stored CSV.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import date, datetime

from sqlalchemy import select

from ..models import (
    Company,
    CompanyAlias,
    EntityIdentifier,
    IndexMembership,
    IndustryClassification,
    LegalEntity,
)
from ..normalize import normalize_cik, normalize_name, normalize_ticker
from .framework import InputRow, Job, RowRejected, RowStatus, Rule, SourceSpec, WriteContext

SOURCE_REF = "Project 200-company seed list (research workbook, membership check 2026-11-18)"
STATUS = "unverified"

INDEX_COLUMNS = {
    "S&P 500": "S&P 500",
    "Nasdaq-100": "Nasdaq-100",
    "Dow Jones IA": "Dow Jones Industrial Average",
}
EXCHANGES = {"nasdaq": "NASDAQ", "nyse": "NYSE"}
_CLASSIFICATION = re.compile(r"^(?P<label>.+?)\s*\((?P<system>GICS|ICB|NAICS|SIC)\)$")


def company_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", normalize_name(name)).strip("-")


def _parse_date(value: str) -> date:
    return datetime.fromisoformat(value.strip()).date()


def _required(column: str):
    return lambda r: None if (r.get(column) or "").strip() else f"{column} is empty"


def _valid(fn, column: str):
    def check(r):
        try:
            fn(r[column])
        except (ValueError, KeyError) as exc:
            return f"{column}: {exc}"
        return None
    return check


def _yes_no(r):
    bad = [c for c in INDEX_COLUMNS if (r.get(c) or "").strip() not in ("Yes", "No")]
    return f"expected Yes/No in {', '.join(bad)}" if bad else None


def _membership_consistent(r):
    listed = {x.strip() for x in (r.get("Index memberships") or "").split(";") if x.strip()}
    flagged = {name for col, name in INDEX_COLUMNS.items() if (r.get(col) or "").strip() == "Yes"}
    return None if listed == flagged else f"Index memberships {sorted(listed)} disagree with Yes/No columns {sorted(flagged)}"


class SeedCompaniesJob(Job):
    name = "seed_companies"
    dataset_key = "project_seed_companies"
    media_type = "text/csv"
    source = SourceSpec(
        source_key="project_seed_list",
        name="Project 200-company seed list",
        source_type="dataset",
        access_method="manual",
        notes="Compiled for this project from SEC metadata, index constituent lists and company sites.",
    )
    rules = (
        Rule("company_name_required", _required("Company name"), field="Company name"),
        Rule("ticker_required", _required("Ticker"), field="Ticker"),
        Rule("cik_valid", _valid(normalize_cik, "Current issuer CIK"), field="Current issuer CIK"),
        Rule("ticker_valid", _valid(normalize_ticker, "Ticker"), field="Ticker"),
        Rule("issuer_name_required", _required("SEC issuer name"), field="SEC issuer name"),
        Rule("exchange_known",
             lambda r: None if (r.get("Stock exchange (SEC metadata)") or "").strip().lower() in EXCHANGES
             else f"unknown exchange {r.get('Stock exchange (SEC metadata)')!r}",
             field="Stock exchange (SEC metadata)"),
        Rule("index_flags_yes_no", _yes_no),
        Rule("membership_date_valid", _valid(_parse_date, "Membership check date"), field="Membership check date"),
        Rule("classification_parsable",
             lambda r: None if _CLASSIFICATION.match((r.get("Source sector / industry classification") or "").strip())
             else "expected 'Label (GICS|ICB|NAICS|SIC)'",
             severity="warning", field="Source sector / industry classification"),
        Rule("index_columns_consistent", _membership_consistent, severity="warning"),
    )

    def parse(self, content: bytes):
        text = content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "Company name" not in reader.fieldnames:
            raise ValueError("CSV has no 'Company name' header")
        for number, raw in enumerate(reader, start=1):
            data = {k.strip(): (v or "").strip() for k, v in raw.items() if k}
            try:
                key = normalize_cik(data.get("Current issuer CIK", ""))
            except ValueError:
                key = f"row-{number}"
            yield InputRow(number, key, data)

    def write(self, ctx: WriteContext) -> RowStatus:
        s, r = ctx.session, ctx.row.data
        changed = created = False

        cik = normalize_cik(r["Current issuer CIK"])
        ticker = normalize_ticker(r["Ticker"])
        exchange = EXCHANGES[r["Stock exchange (SEC metadata)"].lower()]
        issuer = r["SEC issuer name"]

        # Company: matched by the issuer's CIK first (names change), then by key.
        entity = s.scalar(
            select(LegalEntity).join(EntityIdentifier).where(
                EntityIdentifier.scheme == "sec_cik", EntityIdentifier.normalized_value == cik
            )
        )
        key = company_key(r["Company name"])
        company = entity.company if entity is not None and entity.company is not None else \
            s.scalar(select(Company).where(Company.company_key == key))
        if company is None:
            company = Company(company_key=key, display_name=r["Company name"],
                              normalized_name=normalize_name(r["Company name"]))
            s.add(company)
            created = True
        for attr, value in (("display_name", r["Company name"]),
                            ("description", r.get("Why we chose this company for the cyber-risk project") or None)):
            if getattr(company, attr) != value:
                setattr(company, attr, value)
                changed = True
        s.flush()

        if entity is None:
            entity = LegalEntity(company_id=company.id, legal_name=issuer, normalized_name=normalize_name(issuer),
                                 entity_status="active", source_ref=SOURCE_REF, verification_status=STATUS)
            s.add(entity)
            s.flush()
            s.add(EntityIdentifier(legal_entity_id=entity.id, scheme="sec_cik", issuer_scope="US-SEC", value=r["Current issuer CIK"],
                                   normalized_value=cik, source_ref=SOURCE_REF, verification_status=STATUS))
            created = True
        elif entity.legal_name != issuer:
            # Keep the old name as a former name; record the current one.
            self._alias(s, company, entity, entity.legal_name, "former_name")
            entity.legal_name, entity.normalized_name = issuer, normalize_name(issuer)
            changed = True

        holder = s.scalar(select(EntityIdentifier).where(
            EntityIdentifier.scheme == "ticker", EntityIdentifier.issuer_scope == exchange,
            EntityIdentifier.normalized_value == ticker))
        if holder is None:
            s.add(EntityIdentifier(legal_entity_id=entity.id, scheme="ticker", issuer_scope=exchange, value=r["Ticker"],
                                   normalized_value=ticker, source_ref=SOURCE_REF, verification_status=STATUS))
            changed = True
        elif holder.legal_entity_id != entity.id:
            raise RowRejected("identifier_conflict",
                              f"Ticker {ticker} on {exchange} already belongs to legal entity {holder.legal_entity_id}",
                              "Ticker")

        changed |= self._alias(s, company, entity, issuer, "legal_name")

        m = _CLASSIFICATION.match(r.get("Source sector / industry classification", ""))
        if m:
            changed |= self._classify(s, company, m["system"], "sector", m["label"])
            if r.get("Business sub-industry"):
                changed |= self._classify(s, company, m["system"], "sub-industry", r["Business sub-industry"])
        if r.get("Project sector group (sheet)"):
            changed |= self._classify(s, company, "project_group", "sector_group", r["Project sector group (sheet)"])

        observed = _parse_date(r["Membership check date"])
        for col, index_name in INDEX_COLUMNS.items():
            if r.get(col) == "Yes":
                exists = s.scalar(select(IndexMembership.id).where(
                    IndexMembership.company_id == company.id, IndexMembership.index_name == index_name,
                    IndexMembership.observed_on == observed))
                if exists is None:
                    s.add(IndexMembership(company_id=company.id, index_name=index_name, ticker=ticker,
                                          observed_on=observed, source_ref=SOURCE_REF, verification_status=STATUS))
                    changed = True
            # "No" is not stored: absence from one check is not proof of non-membership over time.
        s.flush()

        ctx.cite(company)
        ctx.cite(entity)
        if created:
            return "inserted"
        return "updated" if changed else "unchanged"

    @staticmethod
    def _alias(s, company, entity, alias, alias_type) -> bool:
        norm = normalize_name(alias)
        if s.scalar(select(CompanyAlias.id).where(CompanyAlias.company_id == company.id,
                                                  CompanyAlias.normalized_alias == norm,
                                                  CompanyAlias.alias_type == alias_type)):
            return False
        s.add(CompanyAlias(company_id=company.id, legal_entity_id=entity.id, alias=alias, normalized_alias=norm,
                           alias_type=alias_type, source_ref=SOURCE_REF, verification_status=STATUS))
        return True

    @staticmethod
    def _classify(s, company, system, level, label) -> bool:
        if s.scalar(select(IndustryClassification.id).where(
                IndustryClassification.company_id == company.id, IndustryClassification.system == system,
                IndustryClassification.level == level, IndustryClassification.label == label,
                IndustryClassification.valid_from.is_(None))):
            return False
        s.add(IndustryClassification(company_id=company.id, system=system, level=level, label=label,
                                     source_ref=SOURCE_REF, verification_status=STATUS))
        return True
