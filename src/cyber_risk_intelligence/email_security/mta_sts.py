"""MTA-STS (RFC 8461) and SMTP TLS reporting (RFC 8460) for a domain (issue 23.4).

MTA-STS tells sending mail servers to deliver to the domain only over verified TLS. It has two parts,
recorded separately:

* a DNS TXT record at ``_mta-sts.<domain>`` (``v=STSv1; id=...``) that announces a policy;
* the policy file at ``https://mta-sts.<domain>/.well-known/mta-sts.txt`` (``version``, ``mode``,
  ``mx`` patterns, ``max_age``). It is fetched only when the DNS record exists: one HTTPS request,
  no redirects (the RFC forbids following them), a valid certificate required, at most 64 KB.

TLS reporting is a TXT record at ``_smtp._tls.<domain>`` (``v=TLSRPTv1; rua=...``) naming where
senders should send reports. The addresses are recorded, never contacted.

A failed lookup or fetch is never read as "no MTA-STS".
"""

from __future__ import annotations

import os
import re
import ssl
from dataclasses import dataclass, field

import httpx

STS_MAX_BYTES = 64 * 1024
MAX_AGE_LIMIT = 31557600  # RFC 8461: up to one year
_STS_ID = re.compile(r"^[A-Za-z0-9]{1,32}$")
DEFAULT_USER_AGENT = "cyber-risk-intelligence-research/0.1 (MTA-STS policy check)"


@dataclass
class TxtRecordResult:
    status: str  # present / missing / invalid / multiple
    record: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


def _tags(value: str) -> dict[str, str]:
    out = {}
    for part in value.split(";"):
        name, sep, arg = part.strip().partition("=")
        if sep:
            out.setdefault(name.strip(), arg.strip())
    return out


def _read_txt(values: list[str], version: str) -> TxtRecordResult:
    mine = [v for v in values if re.match(rf"^\s*v\s*=\s*{re.escape(version)}\s*(;|$)", v)]
    if not mine:
        return TxtRecordResult("missing")
    if len(mine) > 1:
        return TxtRecordResult("multiple", "\n".join(mine), problems=[f"{len(mine)} {version} records"])
    return TxtRecordResult("present", mine[0], _tags(mine[0]))


def read_sts_record(values: list[str]) -> TxtRecordResult:
    r = _read_txt(values, "STSv1")
    if r.status == "present" and not _STS_ID.match(r.tags.get("id", "")):
        r.status, r.problems = "invalid", ["id must be 1-32 letters or digits"]
    return r


def read_tlsrpt_record(values: list[str]) -> TxtRecordResult:
    r = _read_txt(values, "TLSRPTv1")
    if r.status != "present":
        return r
    uris = [u.strip() for u in r.tags.get("rua", "").split(",") if u.strip()]
    bad = [u for u in uris if not u.lower().startswith(("mailto:", "https:"))]
    if not uris:
        r.status, r.problems = "invalid", ["no rua= reporting address"]
    elif bad:
        r.status, r.problems = "invalid", [f"rua must be mailto: or https: ({', '.join(bad)})"]
    return r


def report_addresses(r: TxtRecordResult) -> list[str]:
    return [u.strip() for u in r.tags.get("rua", "").split(",") if u.strip()]


@dataclass
class StsPolicy:
    status: str  # valid / invalid
    version: str | None = None
    mode: str | None = None
    mx: list[str] = field(default_factory=list)
    max_age: int | None = None
    problems: list[str] = field(default_factory=list)


def read_policy(text: str) -> StsPolicy:
    fields: dict[str, list[str]] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep:
            return StsPolicy("invalid", problems=[f"line {line.strip()[:40]!r} is not key: value"])
        fields.setdefault(key.strip().lower(), []).append(value.strip())
    p = StsPolicy("valid", (fields.get("version") or [None])[0], (fields.get("mode") or [None])[0],
                  fields.get("mx", []))
    if p.version != "STSv1":
        p.problems.append("version must be STSv1")
    if p.mode not in ("enforce", "testing", "none"):
        p.problems.append(f"mode {p.mode!r} is not enforce, testing or none")
    if p.mode in ("enforce", "testing") and not p.mx:
        p.problems.append("no mx patterns")
    age = (fields.get("max_age") or [""])[0]
    if age.isdigit():
        p.max_age = int(age)
        if p.max_age > MAX_AGE_LIMIT:
            p.problems.append(f"max_age over {MAX_AGE_LIMIT} seconds")
    else:
        p.problems.append("max_age missing or not a number")
    if p.problems:
        p.status = "invalid"
    return p


@dataclass
class PolicyFetch:
    outcome: str  # retrieved / not_found / certificate_invalid / request_failed
    url: str
    http_status: int | None = None
    body: bytes | None = None
    message: str | None = None


def policy_url(domain: str) -> str:
    return f"https://mta-sts.{domain}/.well-known/mta-sts.txt"


class PolicyFetcher:
    def __init__(self, client: httpx.Client | None = None, timeout: float = 15.0):
        agent = os.environ.get("COLLECTOR_USER_AGENT") or DEFAULT_USER_AGENT
        self.client = client or httpx.Client(timeout=timeout, headers={"User-Agent": agent})

    def fetch(self, domain: str) -> PolicyFetch:
        url = policy_url(domain)
        try:
            with self.client.stream("GET", url, follow_redirects=False) as r:
                if r.status_code != 200:
                    kind = "not_found" if r.status_code == 404 else "request_failed"
                    return PolicyFetch(kind, url, r.status_code, message=f"HTTP {r.status_code}")
                body = bytearray()
                for chunk in r.iter_bytes():
                    body += chunk
                    if len(body) > STS_MAX_BYTES:
                        return PolicyFetch("request_failed", url, 200, message="policy larger than 64 KB")
                return PolicyFetch("retrieved", url, 200, bytes(body))
        except httpx.ConnectError as exc:
            cause = exc.__cause__ or exc.__context__
            if isinstance(cause, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(exc):
                return PolicyFetch("certificate_invalid", url, message=str(exc)[:300])
            return PolicyFetch("request_failed", url, message=f"ConnectError: {exc}"[:300])
        except httpx.HTTPError as exc:
            return PolicyFetch("request_failed", url, message=f"{type(exc).__name__}: {exc}"[:300])
