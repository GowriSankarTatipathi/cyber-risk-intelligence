"""Polite HTTP fetching for public pages.

* Identifies itself with a declared User-Agent (``COLLECTOR_USER_AGENT``).
* Obeys robots.txt; a disallowed page is reported, not fetched.
* Waits between requests to the same host, and stops calling a host for the
  rest of the run after it answers 429.
* Only fetches http(s). Reads web pages and PDFs; gives up on pages over 5 MB
  and PDFs over 30 MB.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

import httpx

DEFAULT_USER_AGENT = "cyber-risk-intelligence-research/0.1 (public trust-center collector)"
MAX_BYTES = 5 * 1024 * 1024
MAX_PDF_BYTES = 30 * 1024 * 1024
LOGIN_HINTS = ("login", "signin", "sign-in", "sign_in", "auth", "sso", "account")


@dataclass(frozen=True)
class FetchResult:
    outcome: str  # captured (web page or PDF) | unavailable | login_required | blocked_by_robots | rate_limited | not_html
    url: str
    final_url: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    content: bytes | None = None
    message: str | None = None


class Fetcher(Protocol):
    def fetch(self, url: str) -> FetchResult: ...


def classify(url: str, status: int, final_url: str, content_type: str, content: bytes) -> FetchResult:
    path = urlsplit(final_url).path.lower() + "?" + urlsplit(final_url).query.lower()
    if status == 429:
        return FetchResult("rate_limited", url, final_url, status, message="HTTP 429 Too Many Requests")
    if status == 401 or (final_url != url and any(h in path for h in LOGIN_HINTS)):
        return FetchResult("login_required", url, final_url, status,
                           message="page requires sign-in; nothing is known about the controls it describes")
    if status >= 400:
        return FetchResult("unavailable", url, final_url, status, message=f"HTTP {status}")
    ctype = (content_type or "").split(";")[0].strip().lower()
    if ctype == "application/pdf" or content.lstrip()[:5] == b"%PDF-":
        return FetchResult("captured", url, final_url, status, "application/pdf", content)
    if ctype not in ("text/html", "application/xhtml+xml"):
        return FetchResult("not_html", url, final_url, status, ctype, content,
                           message=f"{ctype or 'unknown type'} is stored but not parsed yet")
    return FetchResult("captured", url, final_url, status, ctype, content)


class HttpFetcher:
    def __init__(self, user_agent: str | None = None, min_delay: float = 2.0, timeout: float = 20.0,
                 transport: httpx.BaseTransport | None = None):
        self.user_agent = user_agent or os.environ.get("COLLECTOR_USER_AGENT") or DEFAULT_USER_AGENT
        self.min_delay = min_delay
        self.client = httpx.Client(headers={"User-Agent": self.user_agent}, timeout=timeout,
                                   follow_redirects=True, transport=transport)
        self._robots: dict[str, RobotFileParser | None] = {}
        self._last: dict[str, float] = {}
        self._backoff: set[str] = set()

    def _wait(self, host: str) -> None:
        elapsed = time.monotonic() - self._last.get(host, 0.0)
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)
        self._last[host] = time.monotonic()

    def _allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in self._robots:
            rp = RobotFileParser()
            try:
                self._wait(parts.netloc)
                r = self.client.get(origin + "/robots.txt")
                if r.status_code in (401, 403):
                    rp.disallow_all = True
                elif r.status_code >= 400:
                    rp.allow_all = True
                else:
                    rp.parse(r.text.splitlines())
            except httpx.HTTPError:
                rp.allow_all = True  # robots.txt unreachable: treat as no rules, per RFC 9309
            self._robots[origin] = rp
        return self._robots[origin].can_fetch(self.user_agent, url)

    def fetch(self, url: str) -> FetchResult:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return FetchResult("unavailable", url, message="only http(s) URLs are collected")
        if parts.netloc in self._backoff:
            return FetchResult("rate_limited", url, message="host asked us to slow down earlier in this run")
        if not self._allowed(url):
            return FetchResult("blocked_by_robots", url, message="robots.txt disallows this page")
        self._wait(parts.netloc)
        try:
            with self.client.stream("GET", url) as r:
                is_pdf = "pdf" in r.headers.get("content-type", "").lower() or url.lower().split("?")[0].endswith(".pdf")
                limit = MAX_PDF_BYTES if is_pdf else MAX_BYTES
                body = b""
                for chunk in r.iter_bytes():
                    body += chunk
                    if len(body) > limit:
                        return FetchResult("unavailable", url, str(r.url), r.status_code,
                                           message=f"{'PDF' if is_pdf else 'page'} larger than "
                                                   f"{limit // (1024 * 1024)} MB; skipped")
                result = classify(url, r.status_code, str(r.url), r.headers.get("content-type", ""), body)
        except httpx.HTTPError as exc:
            return FetchResult("unavailable", url, message=f"{type(exc).__name__}: {exc}")
        if result.outcome == "rate_limited":
            self._backoff.add(parts.netloc)
        return result
