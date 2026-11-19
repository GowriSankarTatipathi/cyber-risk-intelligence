"""Find security-control statements in a PDF (security policy, SOC 3 report, ESG report...).

Uses the same claim matching as web pages. PDFs have no reliable paragraphs or
headings, so each claim's context is its sentence plus the sentences on either
side, and its heading is the page it appears on ("page 12"). Dates come from
the PDF's own metadata (creation date = published, modification date =
updated) or a "Last updated" line in the text. Scanned PDFs without a text
layer yield no claims; they are stored and can be read again later.
"""

from __future__ import annotations

import io
import logging
import re
from datetime import UTC, datetime

from pypdf import PdfReader

from .extract import _UPDATED, PageExtract, _parse_date, _squash, add_claims_from_sections

MAX_PAGES = 400

logging.getLogger("pypdf").setLevel(logging.ERROR)  # malformed-but-readable PDFs are common


def is_pdf(content: bytes) -> bool:
    return content.lstrip()[:5] == b"%PDF-"


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def pdf_pages(content: bytes) -> list[str]:
    """Text of each page (empty strings for pages without a text layer)."""
    reader = PdfReader(io.BytesIO(content))
    pages = []
    for page in reader.pages[:MAX_PAGES]:
        try:
            pages.append(page.extract_text() or "")
        except Exception:  # one unreadable page shouldn't lose the rest
            pages.append("")
    return pages


def _chunks(text: str) -> list[str]:
    """Join wrapped lines into running text, but keep short title-like lines apart.

    A line that is short, has no closing punctuation and is followed by a capitalised
    line is a heading or a table cell, not the start of the next sentence.
    """
    text = re.sub(r"(\w)-\n(\w)", r"\1\2", text)  # undo hyphenation at line ends
    lines = [ln.strip() for ln in text.splitlines()]
    chunks: list[list[str]] = [[]]
    for i, line in enumerate(lines):
        if not line:
            chunks.append([])
            continue
        chunks[-1].append(line)
        nxt = next((ln for ln in lines[i + 1:] if ln), "")
        if len(line) < 70 and not re.search(r"[.,;:!?)\-]$", line) and nxt[:1].isupper():
            chunks.append([])
    return [_squash(" ".join(c)) for c in chunks if c]


def extract_pdf(content: bytes) -> PageExtract:
    try:
        reader = PdfReader(io.BytesIO(content))
        meta = reader.metadata
        pages = pdf_pages(content)
    except Exception:
        return PageExtract()
    page = PageExtract(title=_squash(meta.title) if meta and meta.title else None)
    if meta:
        try:
            page.published_at = _aware(meta.creation_date)
            modified = _aware(meta.modification_date)
            page.updated_on = modified.date() if modified else None
        except Exception:
            pass
    full = "\n".join(pages)
    if not page.updated_on and (m := _UPDATED.search(_squash(full))):
        page.updated_on = _parse_date(m.group(1))

    add_claims_from_sections(page, [(f"page {n}", chunk) for n, text in enumerate(pages, start=1)
                                    for chunk in _chunks(text)])
    return page
