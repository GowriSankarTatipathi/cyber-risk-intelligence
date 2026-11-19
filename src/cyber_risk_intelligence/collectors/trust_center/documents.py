"""Recognise a fetched document's format and read the security claims in it.

Companies publish security information in many formats. Besides web pages and
PDFs (``pdf.py``) this reads:

* Word (.docx), PowerPoint (.pptx) and Excel (.xlsx), e.g. security
  whitepapers, overview decks and filled-in security questionnaires (CAIQ,
  SIG). Each row of a spreadsheet is read as one line: "question | answer".
* Plain text (.txt, including security.txt) and Markdown (.md).
* JSON, e.g. a bug-bounty platform's published policy.

Office files are zip archives of XML; they are read with the standard library
and with size limits, so a malicious archive can't exhaust memory. Older
binary formats (.doc, .xls, .ppt), images and scanned documents without text
are stored but not parsed (``not_html``).

Each claim's ``section_heading`` says where it is: the document heading,
"slide 3", "Sheet1 row 12" or "page 4".
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from xml.etree import ElementTree as ET

from .extract import _UPDATED, PageExtract, _parse_date, _parse_datetime, _squash, add_claims_from_sections, extract
from .pdf import extract_pdf, is_pdf, pdf_pages

KINDS = ("html", "pdf", "docx", "pptx", "xlsx", "text", "markdown", "json")
MEDIA_TYPES = {
    "html": "text/html",
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text": "text/plain",
    "markdown": "text/markdown",
    "json": "application/json",
}
_BY_MEDIA = {v: k for k, v in MEDIA_TYPES.items()} | {
    "application/xhtml+xml": "html", "text/x-markdown": "markdown", "application/ld+json": "json"}
_BY_EXTENSION = {".pdf": "pdf", ".docx": "docx", ".pptx": "pptx", ".xlsx": "xlsx", ".txt": "text",
                 ".md": "markdown", ".markdown": "markdown", ".json": "json", ".htm": "html", ".html": "html"}

MAX_UNZIPPED = 100 * 1024 * 1024  # total uncompressed size we will read from an office file
MAX_ROWS = 20000

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def detect_kind(content: bytes, content_type: str | None = None, url: str | None = None) -> str | None:
    """The document's format (one of ``KINDS``), or None if we don't read it."""
    head = content.lstrip()[:512]
    if is_pdf(content):
        return "pdf"
    if head[:4] == b"PK\x03\x04":
        return _office_kind(content)
    ctype = (content_type or "").split(";")[0].strip().lower()
    kind = _BY_MEDIA.get(ctype)
    if kind in ("docx", "pptx", "xlsx", "pdf"):
        return None  # says it's a document but isn't one
    if kind is None and ctype in ("", "application/octet-stream", "text/plain", "binary/octet-stream") and url:
        path = url.split("?")[0].split("#")[0].lower()
        ext = path[path.rfind("."):] if "." in path.rsplit("/", 1)[-1] else ""
        kind = _BY_EXTENSION.get(ext, kind)
    if kind is None and ctype == "text/plain":
        kind = "text"
    if kind in ("text", "markdown", "json") and b"\x00" in content[:4096]:
        return None  # binary data
    if kind is None and head.lower().startswith((b"<!doctype html", b"<html")):
        kind = "html"
    return kind


def _office_kind(content: bytes) -> str | None:
    try:
        names = zipfile.ZipFile(io.BytesIO(content)).namelist()
    except zipfile.BadZipFile:
        return None
    if "word/document.xml" in names:
        return "docx"
    if any(n.startswith("ppt/slides/slide") for n in names):
        return "pptx"
    if "xl/workbook.xml" in names:
        return "xlsx"
    return None


def extract_document(content: bytes, kind: str) -> PageExtract:
    """Claims in a document of the given kind. Unreadable files give no claims rather than an error."""
    if kind == "html":
        return extract(content)
    if kind == "pdf":
        return extract_pdf(content)
    try:
        title, published, updated, sections = _read(content, kind)
    except Exception:
        return PageExtract()
    page = PageExtract(title=title, published_at=published, updated_on=updated)
    if not page.updated_on and (m := _UPDATED.search(_squash(" ".join(t for _, t in sections)))):
        page.updated_on = _parse_date(m.group(1))
    add_claims_from_sections(page, sections)
    return page


def document_text(content: bytes, kind: str) -> str:
    """All readable text, used for the secret check on formats whose raw bytes are compressed."""
    if kind == "pdf":
        return "\n".join(pdf_pages(content))
    try:
        return "\n".join(t for _, t in _read(content, kind)[3])
    except Exception:
        return ""


# --- readers: each returns (title, published_at, updated_on, [(heading, text)]) -----------------------

def _read(content: bytes, kind: str):
    if kind in ("docx", "pptx", "xlsx"):
        z = _open_zip(content)
        title, published, updated = _core_properties(z)
        reader = {"docx": _docx, "pptx": _pptx, "xlsx": _xlsx}[kind]
        return title, published, updated, reader(z)
    text = content.decode("utf-8-sig", errors="replace")
    if kind == "json":
        return None, None, None, _json_sections(json.loads(text))
    return _text_sections(text, markdown=(kind == "markdown"))


def _open_zip(content: bytes) -> zipfile.ZipFile:
    z = zipfile.ZipFile(io.BytesIO(content))
    if sum(i.file_size for i in z.infolist()) > MAX_UNZIPPED:
        raise ValueError("archive expands to more than the size limit")
    return z


def _xml(z: zipfile.ZipFile, name: str) -> ET.Element | None:
    try:
        return ET.fromstring(z.read(name))
    except KeyError:
        return None


def _core_properties(z: zipfile.ZipFile):
    root = _xml(z, "docProps/core.xml")
    if root is None:
        return None, None, None
    def find(local: str) -> str | None:
        el = next((e for e in root if e.tag.rsplit("}", 1)[-1] == local), None)
        return el.text.strip() if el is not None and el.text and el.text.strip() else None
    created, modified = find("created"), find("modified")
    published = _parse_datetime(created) if created else None
    updated_dt = _parse_datetime(modified) if modified else None
    return find("title"), published, updated_dt.date() if updated_dt else None


def _docx(z: zipfile.ZipFile) -> list[tuple[str | None, str]]:
    root = _xml(z, "word/document.xml")
    sections, heading = [], None
    for p in root.iter(f"{_W}p"):
        text = _squash("".join(t.text or "" for t in p.iter(f"{_W}t")))
        if not text:
            continue
        style = p.find(f"{_W}pPr/{_W}pStyle")
        style_name = (style.get(f"{_W}val") or "").lower() if style is not None else ""
        if style_name.startswith(("heading", "title")):
            heading = text
            continue
        sections.append((heading, text))
    return sections


def _pptx(z: zipfile.ZipFile) -> list[tuple[str | None, str]]:
    slides = sorted((n for n in z.namelist() if re.fullmatch(r"ppt/slides/slide\d+\.xml", n)),
                    key=lambda n: int(re.search(r"(\d+)\.xml$", n).group(1)))
    sections = []
    for number, name in enumerate(slides, start=1):
        for p in _xml(z, name).iter(f"{_A}p"):
            text = _squash("".join(t.text or "" for t in p.iter(f"{_A}t")))
            if text:
                sections.append((f"slide {number}", text))
    return sections


def _xlsx(z: zipfile.ZipFile) -> list[tuple[str | None, str]]:
    shared = []
    root = _xml(z, "xl/sharedStrings.xml")
    if root is not None:
        shared = ["".join(t.text or "" for t in si.iter(f"{_S}t")) for si in root.iter(f"{_S}si")]
    names = [s.get("name") for s in _xml(z, "xl/workbook.xml").iter(f"{_S}sheet")]
    sheets = sorted((n for n in z.namelist() if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n)),
                    key=lambda n: int(re.search(r"(\d+)\.xml$", n).group(1)))
    sections, rows = [], 0
    for i, name in enumerate(sheets):
        label = names[i] if i < len(names) and names[i] else f"sheet {i + 1}"
        for row in _xml(z, name).iter(f"{_S}row"):
            cells = []
            for c in row.iter(f"{_S}c"):
                if c.get("t") == "s":
                    v = c.find(f"{_S}v")
                    idx = int(v.text) if v is not None and v.text and v.text.isdigit() else -1
                    value = shared[idx] if 0 <= idx < len(shared) else ""
                elif c.get("t") == "inlineStr":
                    value = "".join(t.text or "" for t in c.iter(f"{_S}t"))
                else:
                    v = c.find(f"{_S}v")
                    value = v.text if v is not None and v.text else ""
                if value.strip():
                    cells.append(_squash(value))
            if cells:
                # One line per row, so a claim keeps the question and its answer together.
                sections.append((f"{label} row {row.get('r') or '?'}", " | ".join(cells)))
            rows += 1
            if rows >= MAX_ROWS:
                return sections
    return sections


def _text_sections(text: str, markdown: bool):
    title, heading, sections, para = None, None, [], []
    def flush():
        if para:
            sections.append((heading, " ".join(para)))
            para.clear()
    for raw in text.splitlines():
        line = raw.strip()
        if markdown and (m := re.match(r"#{1,6}\s+(.*)", line)):
            flush()
            heading = _squash(m.group(1).strip("# "))
            title = title or heading
            continue
        if not line:
            flush()
            continue
        if markdown:
            line = re.sub(r"^[-*+]\s+|^\d+[.)]\s+", "", line)  # list markers
            line = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", line)  # [text](link) -> text
            line = line.replace("**", "").replace("__", "").replace("`", "")
        if re.match(r"^[A-Za-z-]+:\s", line) and not markdown:
            flush()  # "Field: value" lines (security.txt) stand alone
            sections.append((heading, line))
            continue
        para.append(line)
    flush()
    return title, None, None, sections


def _json_sections(data, path: str = "") -> list[tuple[str | None, str]]:
    out: list[tuple[str | None, str]] = []
    if isinstance(data, dict):
        for k, v in data.items():
            out += _json_sections(v, f"{path}.{k}" if path else str(k))
    elif isinstance(data, list):
        for v in data[:MAX_ROWS]:
            out += _json_sections(v, path)
    elif isinstance(data, str) and len(data.strip()) >= 12:
        text = data
        if "<" in text and ">" in text:  # HTML stored inside JSON, common for published policies
            from bs4 import BeautifulSoup
            text = BeautifulSoup(text, "html.parser").get_text(" ")
        out.append((path or None, _squash(text)))
    return out
