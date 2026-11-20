"""Search crt.sh, a public index of Certificate Transparency logs, and read its answer.

One HTTPS request per domain to ``https://crt.sh/?q=<domain>&output=json&exclude=expired``.
crt.sh is a free, shared service that is often overloaded: requests are spaced
out, a 429/5xx or timeout is retried a few times with a growing pause, and if it
still fails the lookup is recorded as ``lookup_failed`` (unknown), never as
"no certificates". Only the index is contacted; none of the hosts named in a
certificate is.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlencode

import httpx

BASE_URL = "https://crt.sh/"
MAX_BYTES = 64 * 1024 * 1024
DEFAULT_USER_AGENT = "cyber-risk-intelligence/0.1 (passive CT lookup)"
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


@dataclass
class CtEntry:
    """One log entry as the index reports it (a precertificate and its certificate are two entries)."""

    log_entry_id: int
    issuer_name: str
    issuer_ca_id: int | None
    serial_number: str
    common_name: str | None
    not_before: datetime | None
    not_after: datetime | None
    names: list[str]  # valid DNS names (lower-case), wildcards included


@dataclass
class CtLookupResult:
    outcome: str  # answered / no_results / lookup_failed
    request_url: str
    http_status: int | None = None
    message: str | None = None
    content: bytes | None = None
    entries: list[CtEntry] = field(default_factory=list)


def request_url(domain: str) -> str:
    return BASE_URL + "?" + urlencode({"q": domain, "output": "json", "exclude": "expired"})


def _when(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)  # crt.sh gives UTC without an offset


def clean_name(value: str) -> str | None:
    """A DNS name from a certificate, lower-case, or None for e-mail addresses, IPs and junk."""
    v = (value or "").strip().lower().rstrip(".")
    if not v or "@" in v or " " in v or "/" in v or ":" in v:
        return None
    labels = v.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return None
    first = 1 if labels[0] == "*" else 0
    if not all(_HOST_LABEL.match(x) for x in labels[first:]):
        return None
    return v


def parse_entries(content: bytes) -> list[CtEntry]:
    """crt.sh JSON (a list of objects) into entries. Raises ValueError/TypeError if it isn't that."""
    data = json.loads(content.decode("utf-8"))
    if not isinstance(data, list):
        raise TypeError("expected a JSON list")
    entries = []
    for row in data:
        serial = re.sub(r"[^0-9a-f]", "", str(row.get("serial_number") or "").lower())
        issuer = (row.get("issuer_name") or "").strip()
        if not serial or not issuer or row.get("id") is None:
            continue
        raw = [*str(row.get("name_value") or "").split("\n"), str(row.get("common_name") or "")]
        names = list(dict.fromkeys(n for n in (clean_name(x) for x in raw) if n))
        cn = (row.get("common_name") or "").strip() or None
        entries.append(CtEntry(int(row["id"]), issuer, row.get("issuer_ca_id"), serial, cn,
                               _when(row.get("not_before")), _when(row.get("not_after")), names))
    return entries


class CrtShClient:
    def __init__(self, client: httpx.Client | None = None, min_delay: float = 5.0, retries: int = 3,
                 backoff: float = 10.0, timeout: float = 180.0):
        agent = os.environ.get("COLLECTOR_USER_AGENT") or DEFAULT_USER_AGENT
        self.client = client or httpx.Client(timeout=timeout, headers={"User-Agent": agent,
                                                                       "Accept": "application/json"})
        self.min_delay, self.retries, self.backoff = min_delay, retries, backoff
        self._last = 0.0

    def _wait(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def search(self, domain: str) -> CtLookupResult:
        url = request_url(domain)
        last_status, last_message = None, None
        for attempt in range(self.retries + 1):
            self._wait(self.min_delay - (time.monotonic() - self._last))
            self._last = time.monotonic()
            try:
                body = b""
                with self.client.stream("GET", url) as r:
                    last_status = r.status_code
                    if r.status_code == 200:
                        for chunk in r.iter_bytes():
                            body += chunk
                            if len(body) > MAX_BYTES:
                                return CtLookupResult("lookup_failed", url, 200,
                                                      f"answer larger than {MAX_BYTES // (1024 * 1024)} MB; "
                                                      "too many certificates to read in one search")
                    retry_after = r.headers.get("Retry-After")
                if r.status_code == 200:
                    try:
                        entries = parse_entries(body)
                    except (ValueError, TypeError) as exc:
                        last_message = f"unreadable answer: {exc}"
                    else:
                        return CtLookupResult("answered" if entries else "no_results", url, 200, None, body, entries)
                elif r.status_code in (429, 500, 502, 503, 504):
                    last_message = f"HTTP {r.status_code}"
                    if attempt < self.retries:
                        pause = float(retry_after) if (retry_after or "").isdigit() else self.backoff * (attempt + 1)
                        self._wait(pause)
                    continue
                else:
                    return CtLookupResult("lookup_failed", url, r.status_code, f"HTTP {r.status_code}")
            except httpx.HTTPError as exc:
                last_message = f"{type(exc).__name__}: {exc}"
            if attempt < self.retries:
                self._wait(self.backoff * (attempt + 1))
        return CtLookupResult("lookup_failed", url, last_status,
                              f"{last_message} (after {self.retries + 1} attempts)")
