"""Grade the security headers a website sends (issue 1.2).

The rules follow the MDN HTTP Observatory's published guidance, simplified and versioned here
(``ASSESSMENT_VERSION``) so a result can always be reproduced from the stored headers. Each header
gets one result:

* ``pass``: present with a protective value;
* ``weak``: present but with a value that leaves the protection partly open;
* ``missing``: the site answered and the header was not sent;
* ``invalid``: present but unusable (malformed, or sent more than once with different values,
  which browsers treat as an error or ignore);
* ``info``: recorded for context only, not graded.

A request that failed (timeout, refused, TLS error) never produces header results: it is recorded on
the check as ``request_failed``, so a site we could not reach is never counted as missing headers.
"""

from __future__ import annotations

from dataclasses import dataclass

ASSESSMENT_VERSION = "cri-headers-1"
RESULTS = ("pass", "weak", "missing", "invalid", "info")
HSTS_MIN_AGE = 15552000  # 180 days, the Observatory's threshold

GRADED = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
          "referrer-policy")
CONTEXT = ("content-security-policy-report-only", "permissions-policy", "cross-origin-opener-policy")
KEPT = (*GRADED, *CONTEXT)

_SAFE_REFERRER = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
_UNSAFE_REFERRER = {"unsafe-url", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin"}


@dataclass
class HeaderResult:
    header: str
    value: str | None  # every value sent, joined with "\n" when there were several
    value_count: int
    result: str
    note: str | None = None


def _hsts(v: str) -> tuple[str, str | None]:
    directives = {}
    for part in v.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, arg = part.partition("=")
        directives[name.strip().lower()] = arg.strip().strip('"')
    age = directives.get("max-age")
    if age is None or not age.isdigit():
        return "invalid", "no valid max-age"
    flags = [f for f in ("includesubdomains", "preload") if f in directives]
    note = f"max-age={age}" + (f"; {', '.join(flags)}" if flags else "")
    if int(age) == 0:
        return "weak", note + " (turns HSTS off)"
    if int(age) < HSTS_MIN_AGE:
        return "weak", note + f" (under {HSTS_MIN_AGE // 86400} days)"
    return "pass", note


def _csp_directives(v: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in v.split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


def _csp(v: str) -> tuple[str, str | None]:
    d = _csp_directives(v)
    if not d:
        return "invalid", "empty policy"
    scripts = d.get("script-src", d.get("default-src"))
    problems = []
    if scripts is None:
        problems.append("no script-src or default-src")
    else:
        has_nonce = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'"
                        for t in scripts)
        if "'unsafe-inline'" in scripts and not has_nonce:
            problems.append("scripts allow 'unsafe-inline'")
        if "'unsafe-eval'" in scripts:
            problems.append("scripts allow 'unsafe-eval'")
        if "*" in scripts or "https:" in scripts or "http:" in scripts:
            problems.append("scripts allowed from any host")
    note = "; ".join(problems) or None
    return ("weak", note) if problems else ("pass", None)


def _xfo(v: str) -> tuple[str, str | None]:
    low = v.strip().lower()
    if low in ("deny", "sameorigin"):
        return "pass", None
    return "invalid", f"{v.strip()!r} is not DENY or SAMEORIGIN (ALLOW-FROM is ignored by browsers)"


def _xcto(v: str) -> tuple[str, str | None]:
    return ("pass", None) if v.strip().lower() == "nosniff" else ("invalid", "only 'nosniff' is valid")


def _referrer(v: str) -> tuple[str, str | None]:
    # A comma-separated list is allowed: the last value the browser understands wins.
    values = [p.strip().lower() for p in v.split(",") if p.strip()]
    known = [p for p in values if p in _SAFE_REFERRER | _UNSAFE_REFERRER]
    if not known:
        return "invalid", "no recognised policy"
    return ("pass", None) if known[-1] in _SAFE_REFERRER else ("weak", f"{known[-1]} sends the full URL to other sites")


_GRADERS = {"strict-transport-security": _hsts, "content-security-policy": _csp, "x-frame-options": _xfo,
            "x-content-type-options": _xcto, "referrer-policy": _referrer}


def assess(headers: list[tuple[str, str]], https: bool = True) -> list[HeaderResult]:
    """Results for every graded and context header, from the raw (name, value) pairs of one response."""
    by_name: dict[str, list[str]] = {}
    for name, value in headers:
        by_name.setdefault(name.strip().lower(), []).append(value)
    out = []
    csp = by_name.get("content-security-policy")
    for header in GRADED:
        values = by_name.get(header)
        if not values:
            if header == "x-frame-options" and csp and any("frame-ancestors" in _csp_directives(c) for c in csp):
                out.append(HeaderResult(header, None, 0, "pass", "covered by CSP frame-ancestors"))
            elif header == "strict-transport-security" and not https:
                out.append(HeaderResult(header, None, 0, "missing", "page not served over HTTPS"))
            else:
                out.append(HeaderResult(header, None, 0, "missing"))
            continue
        joined = "\n".join(values)
        distinct = list(dict.fromkeys(v.strip() for v in values))
        if header != "content-security-policy" and len(distinct) > 1:
            # Several CSP headers all apply (the strictest wins); for the others browsers reject or pick one.
            out.append(HeaderResult(header, joined, len(values), "invalid", f"sent {len(values)} times with different values"))
            continue
        if header == "content-security-policy":
            graded = [_csp(v) for v in values]
            result = "pass" if any(r == "pass" for r, _ in graded) else graded[0][0]
            note = next((n for r, n in graded if r == result), None)
        else:
            result, note = _GRADERS[header](distinct[0])
            if len(values) > 1:
                note = "; ".join(filter(None, [note, f"sent {len(values)} times"]))
        out.append(HeaderResult(header, joined, len(values), result, note))
    for header in CONTEXT:
        values = by_name.get(header)
        if values:
            out.append(HeaderResult(header, "\n".join(values), len(values), "info"))
    return out


def summarize(results: list[HeaderResult]) -> dict[str, int]:
    counts = dict.fromkeys(RESULTS, 0)
    for r in results:
        counts[r.result] += 1
    return counts


__all__ = ["ASSESSMENT_VERSION", "GRADED", "KEPT", "RESULTS", "HeaderResult", "assess", "summarize"]