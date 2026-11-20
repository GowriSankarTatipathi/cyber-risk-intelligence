"""Search crt.sh's public, read-only certificate database directly (SQL instead of the web page).

crt.sh lets anyone query its database: ``psql -h crt.sh -p 5432 -U guest certwatch`` (no password).
One query per domain returns every current certificate naming the domain or a subdomain, so even a
domain with thousands of certificates answers in seconds, with no paging and no hourly allowance.

* Same answer as the crt.sh web search with ``exclude=expired``: the certificates' issuer, serial number,
  validity and the names that match the domain. Each certificate also gets ``tbs_sha256``, the
  SHA-256 of its to-be-signed part with the CT extensions removed (``x509_tbscert_strip_ct_ext``), which
  is how Cert Spotter identifies a certificate, so one seen by both indexes is stored once.
* The guest database is shared and sometimes refuses connections or cancels long queries. A failed
  query is ``lookup_failed`` (the job then asks Cert Spotter), never "no certificates". If the
  database can't be reached at all (port 5432 blocked, server down), the client stops trying for the
  rest of the run instead of waiting on every domain. So does a query the server rejects as not
  fitting its schema (SQLSTATE class 42), which would fail the same way for every domain.
* By default only the **newest certificate for each host name** is kept (``latest_per_name``): every
  name the domain has a current certificate for is still found, but a name renewed every 90 days, or
  covered by hundreds of near-identical certificates, gives one certificate, not hundreds. The
  narrowing happens inside crt.sh, so only that much is sent and stored. ``latest_per_name=False``
  (``ct collect --all-certificates``) keeps every certificate.
* ``max_certs`` (``CT_DB_MAX_CERTS``, default 300,000) caps the (certificate, name) matches read; a
  search that reaches it is marked incomplete.

Only the crt.sh database is contacted; none of the hosts named in a certificate is.
"""

from __future__ import annotations

import json
import logging
import os
from urllib.parse import urlencode

from .entries import CtEntry, CtLookupResult, names_of, when

HOST, PORT, USER, DBNAME = "crt.sh", 5432, "guest", "certwatch"
BASE_URL = f"postgresql://{USER}@{HOST}:{PORT}/{DBNAME}"
log = logging.getLogger(__name__)

_COLUMNS = """
SELECT c.id, ca.name AS issuer_name, c.issuer_ca_id,
       encode(x509_serialNumber(c.certificate), 'hex') AS serial_number,
       x509_commonName(c.certificate) AS common_name,
       x509_notBefore(c.certificate) AS not_before,
       x509_notAfter(c.certificate) AS not_after,
       {tbs} AS tbs_sha256,
       m.names"""
_MATCH = """
    FROM certificate_and_identities cai
    WHERE plainto_tsquery('certwatch', %(domain)s) @@ identities(cai.certificate)
      AND (lower(cai.name_value) = %(domain)s OR lower(cai.name_value) LIKE %(like)s ESCAPE '!')
      AND coalesce(x509_notAfter(cai.certificate), 'infinity') >= (now() AT TIME ZONE 'UTC')"""
_TBS = "encode(digest(x509_tbscert_strip_ct_ext(c.certificate), 'sha256'), 'hex')"
# Every certificate, with the names that match the domain.
_QUERY = _COLUMNS + """
FROM (
    SELECT cai.certificate_id, array_agg(DISTINCT lower(cai.name_value)) AS names""" + _MATCH + """
    GROUP BY cai.certificate_id
    LIMIT %(limit)s
) m
JOIN certificate c ON c.id = m.certificate_id
JOIN ca ON ca.id = c.issuer_ca_id
"""
# Newest certificate per name: the matches, then one certificate per name (latest not_before), then
# that certificate's names gathered again. ``hits`` = matches read, to tell whether the cap was reached.
_LATEST_QUERY = """
WITH hits AS (
    SELECT DISTINCT lower(cai.name_value) AS name, cai.certificate_id,
           x509_notBefore(cai.certificate) AS not_before""" + _MATCH + """
    LIMIT %(limit)s
), latest AS (
    SELECT DISTINCT ON (name) name, certificate_id FROM hits
    ORDER BY name, not_before DESC NULLS LAST, certificate_id DESC
), m AS (
    SELECT certificate_id, array_agg(name ORDER BY name) AS names FROM latest GROUP BY certificate_id
)""" + _COLUMNS + """,
       (SELECT count(*) FROM hits) AS hits
FROM m
JOIN certificate c ON c.id = m.certificate_id
JOIN ca ON ca.id = c.issuer_ca_id
"""


def request_url(domain: str) -> str:
    return BASE_URL + "?" + urlencode({"q": domain, "exclude": "expired"})


def _like(domain: str) -> str:
    return "%." + domain.replace("!", "!!").replace("%", "!%").replace("_", "!_")


def to_entry(row: dict, with_common_name: bool = True) -> CtEntry | None:
    issuer = (row.get("issuer_name") or "").strip()
    serial = "".join(ch for ch in str(row.get("serial_number") or "").lower() if ch in "0123456789abcdef")
    tbs = (row.get("tbs_sha256") or "").lower() or None
    if not issuer or row.get("id") is None or not (serial or tbs):
        return None
    common = (row.get("common_name") or "").strip() or None
    return CtEntry(
        entry_id=str(row["id"]), source_ref=f"https://crt.sh/?id={row['id']}", issuer_name=issuer,
        names=names_of([*(row.get("names") or []), (common or "") if with_common_name else ""]),
        serial_number=serial or None,
        tbs_sha256=tbs if tbs and len(tbs) == 64 else None, issuer_ca_id=row.get("issuer_ca_id"),
        common_name=common, not_before=when(row.get("not_before")), not_after=when(row.get("not_after")))


class CrtShDbClient:
    source = "crt.sh"  # the same index as the web search; request_url says it was asked through SQL

    def __init__(self, connect=None, max_certs: int | None = None, statement_timeout_s: int = 300,
                 connect_timeout_s: int = 15, latest_per_name: bool = True):
        self._connect = connect or self._psycopg_connect
        self.max_certs = max_certs or int(os.environ.get("CT_DB_MAX_CERTS") or 300_000)
        self.statement_timeout_s, self.connect_timeout_s = statement_timeout_s, connect_timeout_s
        self._conn = None
        self._down: str | None = None  # why the database can't be reached; set once, then not retried
        self._with_tbs = True
        self.latest_per_name = latest_per_name

    def _psycopg_connect(self):
        import psycopg

        return psycopg.connect(host=HOST, port=PORT, user=USER, dbname=DBNAME, autocommit=True,
                               connect_timeout=self.connect_timeout_s, application_name="cyber-risk-intelligence")

    def _connection(self):
        if self._conn is None or getattr(self._conn, "closed", False):
            self._conn = self._connect()
            try:
                self._conn.execute(f"SET statement_timeout = '{int(self.statement_timeout_s)}s'")
            except Exception as exc:  # noqa: BLE001 - the server's own limit applies then
                log.debug("crt.sh database: statement_timeout not set: %s", exc)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def _rows(self, domain: str) -> list[dict]:
        params = {"domain": domain, "like": _like(domain), "limit": self.max_certs}
        conn = self._connection()
        query = _LATEST_QUERY if self.latest_per_name else _QUERY
        try:
            cur = conn.execute(query.format(tbs=_TBS if self._with_tbs else "NULL"), params)
        except Exception as exc:
            if self._with_tbs and "does not exist" in str(exc):  # digest() or the strip function missing
                log.warning("crt.sh database: no TBS hash available (%s); using issuer and serial only", exc)
                self._with_tbs = False
                cur = conn.execute(query.format(tbs="NULL"), params)
            else:
                raise
        names = [d[0] for d in cur.description]
        return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]

    def search(self, domain: str) -> CtLookupResult:
        url = request_url(domain)
        if self._down:
            return CtLookupResult(self.source, "lookup_failed", url, None, f"database not reachable: {self._down}")
        try:
            self._connection()
        except Exception as exc:  # noqa: BLE001 - any connection failure means the same thing
            self._down = f"{type(exc).__name__}: {exc}".strip()[:300]
            log.warning("crt.sh database not reachable (%s); using the other CT sources for this run", self._down)
            return CtLookupResult(self.source, "lookup_failed", url, None, f"database not reachable: {self._down}")
        try:
            rows = self._rows(domain)
        except Exception as exc:  # noqa: BLE001 - cancelled query, dropped connection, server busy
            self.close()
            if str(getattr(exc, "sqlstate", "") or "").startswith("42"):
                # the query itself doesn't fit crt.sh's schema any more: no point asking for every domain
                self._down = f"query not accepted: {str(exc).strip()[:300]}"
                log.warning("crt.sh database: %s; using the other CT sources for this run", self._down)
            return CtLookupResult(self.source, "lookup_failed", url, None,
                                  f"database query failed: {type(exc).__name__}: {str(exc).strip()[:300]}")
        entries = [e for e in (to_entry(r, not self.latest_per_name) for r in rows) if e]
        read = max((r.get("hits") or 0 for r in rows), default=0) or len(rows)
        complete = read < self.max_certs
        content = json.dumps({"query": domain, "source": "crt.sh database", "exclude": "expired",
                              "kept": "newest certificate per name" if self.latest_per_name else "all",
                              "complete": complete, "certificates": rows},
                             default=lambda v: v.isoformat() if hasattr(v, "isoformat") else str(v),
                             ensure_ascii=False).encode()
        return CtLookupResult(self.source, "answered" if entries else "no_results", url, None,
                              None if complete else f"stopped at {self.max_certs} matches; more exist",
                              content, entries, pages=1, complete=complete)
