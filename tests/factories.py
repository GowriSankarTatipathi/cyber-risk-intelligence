"""Small builders for synthetic records shared by the data-quality tests."""

from datetime import date

from cyber_risk_intelligence.models import Company, EntityIdentifier, LegalEntity, Source
from cyber_risk_intelligence.normalize import normalize_identifier, normalize_name


def company(s, key="acme", name="Acme"):
    c = Company(company_key=key, display_name=name, normalized_name=normalize_name(name))
    s.add(c)
    s.flush()
    return c


def entity(s, comp=None, legal_name="Acme Corp", **kw):
    kw.setdefault("source_ref", "synthetic fixture")
    e = LegalEntity(company_id=comp.id if comp else None, legal_name=legal_name,
                    normalized_name=normalize_name(legal_name), **kw)
    s.add(e)
    s.flush()
    return e


def identifier(s, ent, scheme="sec_cik", value="1234567", scope="US-SEC",
               valid_from: date | None = None, valid_to: date | None = None, **kw):
    kw.setdefault("source_ref", "synthetic fixture")
    i = EntityIdentifier(legal_entity_id=ent.id, scheme=scheme, issuer_scope=scope, value=value,
                         normalized_value=normalize_identifier(scheme, value),
                         valid_from=valid_from, valid_to=valid_to, **kw)
    s.add(i)
    s.flush()
    return i


def source(s, key="fixture"):
    src = Source(source_key=key, name="Synthetic fixture", source_type="other", access_method="manual")
    s.add(src)
    s.flush()
    return src
