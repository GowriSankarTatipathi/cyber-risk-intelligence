"""Search Cert Spotter (SSLMate), a public Certificate Transparency search API, for a domain.

``GET https://api.certspotter.com/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names&expand=issuer``
returns current (unexpired) certificates 100 at a time; the next page is asked for with
``after=<last id>``. Pages come back in well under a second, so even domains with tens of
thousands of certificates (where crt.sh times out) can be read in full.

* An API key is optional (``CERTSPOTTER_API_KEY`` in the environment, never in the code or the
  database); without one the free hourly allowance applies.
* A 429 asking for a short pause (``patience`` seconds or less) is waited out. A longer one before any
  page was read gives up on this domain at once (``lookup_failed``, so the job can ask crt.sh) and
  every search until the allowance is back is skipped without a request; ``ready_in()`` says how
  long that is. Mid-way through a big domain the pause is waited out, since crt.sh can't answer
  those. 5xx and timeouts are retried a few times. If a page still fails, what was read so far is kept and the lookup is marked
  incomplete; if nothing was read the lookup is ``lookup_failed``.
* ``max_pages`` (``CT_MAX_PAGES``, default 3000 = 300,000 certificates) stops runaway searches; a
  search that hits it is marked incomplete too.

Only the API is contacted; none of the hosts named in a certificate is.
"""

from __future__ import annotations

import json
import logging
import os
import time
from urllib.parse import urlencode

import httpx

from .entries import DEFAULT_USER_AGENT, CtEntry, CtLookupResult, names_of, when

BASE_URL = "https://api.certspotter.com/v1/issuances"
MAX_RETRY_AFTER = 300.0
log = logging.getLogger(__name__)


def request_url(domain: str, after: str | None = None) -> str:
    params = [("domain", domain), ("include_subdomains", "true"), ("expand", "dns_names"), ("expand", "issuer")]
    if after:
        params.append(("after", after))
    return BASE_URL + "?" + urlencode(params)


def to_entry(item: dict) -> CtEntry | None:
    issuer = ((item.get("issuer") or {}).get("name") or "").strip()
    tbs = (item.get("tbs_sha256") or "").lower()
    if not issuer or not tbs or item.get("id") is None:
        return None
    cert = (item.get("cert_sha256") or "").lower() or None
    names = names_of(item.get("dns_names") or [])
    return CtEntry(
        entry_id=str(item["id"]),
        source_ref=f"https://crt.sh/?sha256={cert}" if cert else f"{BASE_URL}?after={item['id']}",
        issuer_name=issuer, names=names, tbs_sha256=tbs, cert_sha256=cert,
        not_before=when(item.get("not_before")), not_after=when(item.get("not_after")),
        revoked=item.get("revoked"))


class CertSpotterClient:
    source = "certspotter"

    def __init__(self, client: httpx.Client | None = None, min_delay: float = 0.2, retries: int = 3,
                 backoff: float = 5.0, max_pages: int | None = None, timeout: float = 60.0,
                 patience: float = 10.0):
        agent = os.environ.get("COLLECTOR_USER_AGENT") or DEFAULT_USER_AGENT
        headers = {"User-Agent": agent, "Accept": "application/json"}
        key = os.environ.get("CERTSPOTTER_API_KEY")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        self.client = client or httpx.Client(timeout=timeout, headers=headers)
        self.min_delay, self.retries, self.backoff = min_delay, retries, backoff
        self.max_pages = max_pages or int(os.environ.get("CT_MAX_PAGES") or 3000)
        self.patience = patience
        self._last = 0.0
        self._blocked_until = 0.0
        # When True, a long rate limit part-way through a domain returns at once (``deferred``) instead of
        # waiting; the pages read so far are kept here and the next search of that domain carries on.
        self.defer_on_limit = False
        self._partial: dict[str, tuple[list, str | None, int]] = {}

    def ready_in(self) -> float:
        """Seconds until the rate-limit allowance is back (0 when requests can be made now)."""
        return max(0.0, self._blocked_until - time.monotonic())

    def _wait(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def _page(self, url: str, give_up_on_long_limit: bool = False) -> tuple[list | None, int | None, str | None]:
        """One page: (items, status, error message). Retries 429/5xx/timeouts."""
        status, message = None, None
        for attempt in range(self.retries + 1):
            self._wait(self.min_delay - (time.monotonic() - self._last))
            self._last = time.monotonic()
            try:
                r = self.client.get(url)
            except httpx.HTTPError as exc:
                status, message = None, f"{type(exc).__name__}: {exc}"
            else:
                status = r.status_code
                if status == 200:
                    try:
                        data = r.json()
                    except ValueError as exc:
                        message = f"unreadable answer: {exc}"
                    else:
                        if isinstance(data, list):
                            return data, 200, None
                        message = "unreadable answer: expected a JSON list"
                elif status == 429:
                    message = "HTTP 429 (rate limited)"
                    ra = r.headers.get("Retry-After") or ""
                    asked = float(ra) if ra.replace(".", "", 1).isdigit() else 60.0
                    if asked > self.patience:
                        self._blocked_until = time.monotonic() + asked
                        if give_up_on_long_limit:
                            return None, 429, f"HTTP 429 (rate limited for {asked:.0f} s)"
                    if attempt < self.retries:
                        pause = min(asked, MAX_RETRY_AFTER)
                        log.warning("Cert Spotter rate limit; waiting %.0f s", pause)
                        self._wait(pause)
                    continue
                elif status >= 500:
                    message = f"HTTP {status}"
                else:
                    return None, status, f"HTTP {status}"
            if attempt < self.retries:
                self._wait(self.backoff * (attempt + 1))
        return None, status, f"{message} (after {self.retries + 1} attempts)"

    def search(self, domain: str) -> CtLookupResult:
        first = request_url(domain)
        if domain in self._partial and not self.defer_on_limit and self.ready_in():
            # a big domain left part-way: nothing else can answer it, so wait here and carry on
            log.warning("%s: waiting %.0f s for the Cert Spotter rate limit", domain, self.ready_in())
            self._wait(self.ready_in())
            self._blocked_until = 0.0
        if self.ready_in():
            return CtLookupResult(self.source, "lookup_failed", first, 429,
                                  f"rate limited for another {self.ready_in():.0f} s; not asked")
        items, after, pages = self._partial.pop(domain, ([], None, 0))
        status = None
        while True:
            if pages >= self.max_pages:
                return self._result(domain, first, items, pages, 200, False,
                                    f"stopped after {pages} pages ({len(items)} certificates); more exist")
            page, status, error = self._page(request_url(domain, after),
                                             give_up_on_long_limit=self.defer_on_limit or not items)
            if page is None:
                if items and self.defer_on_limit and status == 429:
                    self._partial[domain] = (items, after, pages)
                    return CtLookupResult(self.source, "lookup_failed", first, 429,
                                          f"{error} after {pages} pages; left for later", deferred=True)
                if not items:
                    return CtLookupResult(self.source, "lookup_failed", first, status, error)
                return self._result(domain, first, items, pages, status, False,
                                    f"stopped at page {pages + 1}: {error}")
            pages += 1
            if not page:
                break
            items.extend(page)
            after = str(page[-1].get("id"))
            if pages % 100 == 0:
                log.info("%s: %d pages, %d certificates so far", domain, pages, len(items))
        return self._result(domain, first, items, pages, 200, True, None)

    def _result(self, domain, url, items, pages, status, complete, message) -> CtLookupResult:
        entries = [e for e in (to_entry(i) for i in items) if e]
        content = json.dumps({"query": domain, "source": self.source, "pages": pages, "complete": complete,
                              "issuances": items}, ensure_ascii=False).encode()
        return CtLookupResult(self.source, "answered" if entries else "no_results", url, status, message,
                              content, entries, pages=pages, complete=complete)
