"""crt.sh database as a CT source (no live calls: the connection is a stand-in)."""
# ruff: noqa: F811  (the acme and store fixtures come from test_ct)

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from cyber_risk_intelligence.ct import CtJob
from cyber_risk_intelligence.ct.crtsh_db import CrtShDbClient, _like
from cyber_risk_intelligence.models.certificates import (
    Certificate,
    CertificateHostname,
    CtLookup,
)

from .test_ct import (  # noqa: F401
    ACME,
    ISSUER,
    acme,
    collect,
    count,
    crtsh,
    issuance,
    spotter,
    store,
)

COLUMNS = ("id", "issuer_name", "issuer_ca_id", "serial_number", "common_name", "not_before", "not_after",
           "tbs_sha256", "names")


def row(id_, serial, names, tbs=None, issuer=ISSUER):
    return (id_, issuer, 1, serial, names[0], datetime(2026, 10, 1, tzinfo=UTC), datetime(2027, 1, 1, tzinfo=UTC), tbs, names)


class FakeCursor:
    def __init__(self, rows, columns=COLUMNS):
        self.description = [(c,) for c in columns]
        self._rows = rows

    def fetchall(self):
        return self._rows


class FakeConnection:
    """Answers each domain from ``answers``; an Exception in the list is raised instead."""

    def __init__(self, answers, log, columns=COLUMNS):
        self.answers, self.log, self.closed, self.sql, self.columns = answers, log, False, [], columns

    def execute(self, sql, params=None):
        if params is None:  # SET statement_timeout
            return FakeCursor([])
        self.log.append((params["domain"], "x509_tbscert_strip_ct_ext" in sql))
        self.sql.append(sql)
        answer = self.answers[params["domain"]]
        result = answer.pop(0) if isinstance(answer, list) and answer and isinstance(answer[0], Exception) else answer
        if isinstance(result, Exception):
            raise result
        return FakeCursor(result, self.columns)

    def close(self):
        self.closed = True


def db(answers, fail_connect=None, columns=COLUMNS, **kw):
    log, connects = [], []

    def connect():
        if fail_connect:
            connects.append(1)
            raise fail_connect
        conn = FakeConnection(answers, log, columns)
        connects.append(conn)
        return conn

    return CrtShDbClient(connect=connect, **kw), log, connects


def test_like_pattern_escapes():
    assert _like("acme.example") == "%.acme.example"
    assert _like("a_b.example") == "%.a!_b.example"


def test_database_answer_is_stored(session_factory, store, acme):
    client, log, _ = db({"acme.example": [
        row(201, "0abc01", ["acme.example", "www.acme.example"], tbs="a" * 64),
        row(202, "77", ["*.dev.acme.example", "dev.acme.example", "admin@acme.example"]),
    ]})
    run, _ = collect(session_factory, store, {}, clients=[client])
    assert run.status == "succeeded" and log == [("acme.example", True)]
    with session_factory() as s:
        lookup = s.scalars(select(CtLookup)).one()
        certs = s.scalars(select(Certificate).order_by(Certificate.id)).all()
        names = set(s.scalars(select(CertificateHostname.hostname)))
    assert lookup.source == "crt.sh" and lookup.request_url.startswith("postgresql://guest@crt.sh:5432/certwatch?q=")
    assert (lookup.outcome, lookup.complete, lookup.entry_count) == ("answered", True, 2)
    assert [(c.serial_number, c.tbs_sha256) for c in certs] == [("0abc01", "a" * 64), ("77", None)]
    assert names == {"acme.example", "www.acme.example", "*.dev.acme.example", "dev.acme.example"}


def test_same_certificate_from_other_sources_is_one_row(session_factory, store, acme):
    # crt.sh web search first (issuer + serial), Cert Spotter next (TBS hash), then the database (both).
    collect(session_factory, store, {"acme.example": [(200, ACME)]})
    spot, _ = spotter({"": [issuance(1, "d", ["acme.example"], issuer=ISSUER)]})
    collect(session_factory, store, {}, clients=[spot])
    before = count(session_factory, Certificate)
    client, _, _ = db({"acme.example": [
        row(301, "0abc01", ["acme.example", "www.acme.example"], tbs="e" * 64),  # matches the crt.sh web row
        row(302, "99", ["acme.example"], tbs="d" * 64),  # matches the Cert Spotter row
    ]})
    run, _ = collect(session_factory, store, {}, clients=[client])
    assert run.status == "succeeded"
    assert count(session_factory, Certificate) == before


def test_unreachable_database_waits_before_trying_again(session_factory, store, acme):
    client, _, connects = db({}, fail_connect=OSError("connection refused"), backoff_s=0)
    fallback, calls = crtsh({"acme.example": [(200, ACME)], "globex.example": [(200, [])]})
    run, _ = collect(session_factory, store, {}, ["acme", "acme.example"], ["globex", "globex.example"],
                     clients=[client, fallback])
    assert run.status == "succeeded" and len(connects) == 3  # 3 attempts for the first domain, none for the next
    assert calls == ["acme.example", "globex.example"]
    with session_factory() as s:
        lookups = s.scalars(select(CtLookup).order_by(CtLookup.id)).all()
    assert "connection refused" in lookups[0].message and "trying again in" in lookups[1].message


def test_database_given_up_after_repeated_outages(session_factory, store, acme):
    client, _, connects = db({}, fail_connect=OSError("connection refused"), backoff_s=0, connect_attempts=2,
                             retry_after_s=0, max_outages=2)
    fallback, _ = crtsh({"acme.example": [(200, ACME)], "globex.example": [(200, [])]})
    collect(session_factory, store, {}, ["acme", "acme.example"], ["globex", "globex.example"],
            clients=[client, fallback])
    assert len(connects) == 4 and client._down and "not tried again" in client._down
    assert client.search("acme.example").message == client._down and len(connects) == 4


def test_connection_prefers_ipv4_and_reports_every_attempt(monkeypatch):
    import psycopg

    from cyber_risk_intelligence.ct import crtsh_db

    tried = []

    def fake_connect(**kw):
        tried.append(kw.get("hostaddr"))
        raise psycopg.OperationalError(f"refused at {kw.get('hostaddr') or 'any'}")

    monkeypatch.setattr(crtsh_db.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("91.199.212.73", 5432)), (2, 1, 6, "", ("91.199.212.73", 5432))])
    monkeypatch.setattr(psycopg, "connect", fake_connect)
    with pytest.raises(ConnectionError) as err:
        CrtShDbClient()._psycopg_connect()
    assert tried == ["91.199.212.73", None]
    assert "91.199.212.73: refused at 91.199.212.73" in str(err.value) and "crt.sh: refused at any" in str(err.value)


def test_failed_query_falls_through_and_reconnects(session_factory, store, acme):
    client, _, connects = db({"acme.example": [RuntimeError("canceling statement due to statement timeout")],
                              "globex.example": []})
    fallback, calls = crtsh({"acme.example": [(200, ACME)]})
    run, _ = collect(session_factory, store, {}, ["acme", "acme.example"], ["globex", "globex.example"],
                     clients=[client, fallback])
    assert run.status == "succeeded" and calls == ["acme.example"] and len(connects) == 2
    with session_factory() as s:
        lookups = s.scalars(select(CtLookup).order_by(CtLookup.id)).all()
    assert "statement timeout" in lookups[0].message and lookups[0].source == "crt.sh"
    assert (lookups[1].outcome, lookups[1].entry_count) == ("no_results", 0)  # answered by the database


class SchemaError(Exception):
    sqlstate = "42703"  # undefined column


def test_query_crt_sh_rejects_stops_the_database_for_the_run(session_factory, store, acme):
    client, log, connects = db({"acme.example": [SchemaError("column cai.name_value does not exist")]})
    client._with_tbs = False
    fallback, calls = crtsh({"acme.example": [(200, ACME)], "globex.example": [(200, [])]})
    run, _ = collect(session_factory, store, {}, ["acme", "acme.example"], ["globex", "globex.example"],
                     clients=[client, fallback])
    assert run.status == "succeeded" and len(log) == 1 and len(connects) == 1
    assert calls == ["acme.example", "globex.example"]


def test_missing_hash_function_falls_back_to_serial_only(session_factory, store, acme):
    client, log, _ = db({"acme.example": [RuntimeError("function digest(bytea, unknown) does not exist"),
                                          row(401, "55", ["shop.acme.example"])]})
    run, _ = collect(session_factory, store, {}, clients=[client])
    assert run.status == "succeeded"
    assert log == [("acme.example", True), ("acme.example", False)]
    assert count(session_factory, Certificate) == 1


def test_answer_at_the_cap_is_incomplete(session_factory, store, acme):
    client, _, _ = db({"acme.example": [row(i, f"{i:x}", [f"h{i}.acme.example"]) for i in range(1, 4)]},
                      max_certs=3)
    collect(session_factory, store, {}, clients=[client])
    with session_factory() as s:
        lookup = s.scalars(select(CtLookup)).one()
    assert (lookup.outcome, lookup.complete) == ("answered", False) and "more exist" in lookup.message


def test_newest_certificate_per_name_by_default(session_factory, store, acme):
    # The narrowing is done by crt.sh (the WITH query); the common name of the kept certificate is not
    # added back, since that name's own newest certificate may be another one.
    client, _, connects = db({"acme.example": [row(501, "5a", ["www.acme.example"], tbs="f" * 64)]})
    collect(session_factory, store, {}, clients=[client])
    sql = connects[0].sql[-1]
    assert "DISTINCT ON (name)" in sql and "count(*) FROM hits" in sql
    with session_factory() as s:
        assert set(s.scalars(select(CertificateHostname.hostname))) == {"www.acme.example"}


def test_all_certificates_on_request(session_factory, store, acme):
    client, _, connects = db({"acme.example": [row(601, "6a", ["www.acme.example"], tbs="f" * 64)]},
                             latest_per_name=False)
    collect(session_factory, store, {}, clients=[client])
    assert "DISTINCT ON" not in connects[0].sql[-1]


def test_cap_counts_matches_read_not_rows_returned(session_factory, store, acme):
    # one certificate kept, but crt.sh read 5 (certificate, name) matches: the cap of 5 was reached
    client, _, _ = db({"acme.example": [(*row(701, "7a", ["a.acme.example"]), 5)]}, max_certs=5,
                      columns=(*COLUMNS, "hits"))
    collect(session_factory, store, {}, clients=[client])
    with session_factory() as s:
        assert s.scalars(select(CtLookup)).one().complete is False


def test_default_clients_ask_the_database_first(store):
    names = [type(c).__name__ for c in CtJob(store).clients]
    assert names == ["CrtShDbClient", "CertSpotterClient", "CrtShClient"]


@pytest.fixture(autouse=True)
def _no_env(monkeypatch):
    monkeypatch.delenv("CT_DB_MAX_CERTS", raising=False)
