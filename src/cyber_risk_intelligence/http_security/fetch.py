"""Request a company home page the way a browser would and keep its response headers (issue 1.2).

Two requests per host, both to the home page (``/``):

* ``https://<host>/``, following up to ``MAX_REDIRECTS`` redirects, like a visitor typing the
  address. The headers of the final answer are what get graded.
* ``http://<host>/`` without following, to see whether plain HTTP is sent on to HTTPS.

Only response headers are read; the page body is not downloaded. No other path, port or host is
asked, and nothing found in the answer is followed beyond the home page's own redirects.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

DEFAULT_USER_AGENT = "cyber-risk-intelligence-research/0.1 (public website header check)"
MAX_REDIRECTS = 5
_REDIRECT = (301, 302, 303, 307, 308)


@dataclass
class PageResponse:
    requested_url: str
    outcome: str  # answered / request_failed
    message: str | None = None
    final_url: str | None = None
    http_status: int | None = None
    redirects: list[list] = field(default_factory=list)  # [status, location] for each hop
    headers: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class HttpRedirect:
    outcome: str  # redirects_to_https / no_redirect (served over plain HTTP) / redirects_elsewhere / request_failed
    http_status: int | None = None
    location: str | None = None
    message: str | None = None


class HeaderFetcher:
    def __init__(self, client: httpx.Client | None = None, timeout: float = 15.0):
        agent = os.environ.get("COLLECTOR_USER_AGENT") or DEFAULT_USER_AGENT
        self.client = client or httpx.Client(timeout=timeout, headers={"User-Agent": agent})

    def _get(self, url: str) -> httpx.Response:
        with self.client.stream("GET", url, follow_redirects=False) as r:
            return r  # headers only: the body is never read

    def page(self, host: str) -> PageResponse:
        url = start = f"https://{host}/"
        redirects: list[list] = []
        try:
            for _ in range(MAX_REDIRECTS + 1):
                r = self._get(url)
                location = r.headers.get("location")
                if r.status_code in _REDIRECT and location:
                    nxt = urljoin(url, location)
                    redirects.append([r.status_code, nxt])
                    if urlsplit(nxt).scheme not in ("http", "https"):
                        return PageResponse(start, "request_failed", f"redirect to {nxt!r} is not a web address",
                                            redirects=redirects)
                    url = nxt
                    continue
                if r.status_code >= 400:
                    # An error page (often a bot filter's 403) is not the website: its headers say
                    # nothing about the site's own, so they are not graded.
                    return PageResponse(start, "request_failed", f"HTTP {r.status_code} from {url}; "
                                        "headers of an error page are not graded", url, redirects=redirects)
                return PageResponse(start, "answered", None, url, r.status_code, redirects,
                                    [(k.decode("latin-1"), v.decode("latin-1")) for k, v in r.headers.raw])
            return PageResponse(start, "request_failed", f"more than {MAX_REDIRECTS} redirects", redirects=redirects)
        except httpx.HTTPError as exc:
            return PageResponse(start, "request_failed", f"{type(exc).__name__}: {exc}", redirects=redirects)

    def http_redirect(self, host: str) -> HttpRedirect:
        """Whether ``http://<host>/`` sends the visitor on to HTTPS (following plain-HTTP hops only)."""
        url = f"http://{host}/"
        try:
            for _ in range(MAX_REDIRECTS + 1):
                r = self._get(url)
                location = r.headers.get("location")
                if r.status_code not in _REDIRECT or not location:
                    return HttpRedirect("no_redirect", r.status_code, None if url.endswith(f"//{host}/") else url)
                url = urljoin(url, location)
                if urlsplit(url).scheme == "https":
                    return HttpRedirect("redirects_to_https", r.status_code, url)
                if urlsplit(url).scheme != "http":
                    return HttpRedirect("redirects_elsewhere", r.status_code, url)
            return HttpRedirect("request_failed", message=f"more than {MAX_REDIRECTS} redirects")
        except httpx.HTTPError as exc:
            return HttpRedirect("request_failed", message=f"{type(exc).__name__}: {exc}")
