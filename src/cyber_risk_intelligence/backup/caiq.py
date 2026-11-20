"""Read the backup answers in a CSA STAR CAIQ self-assessment (issue 2.1, second source).

The Cloud Security Alliance's STAR Registry publishes each cloud provider's
answers to the Consensus Assessments Initiative Questionnaire (CAIQ), an Excel
file. It is still the provider describing itself (a self-assessment), so rows
read from it are claims, like the provider's own web pages.

Only business-continuity (BCR) questions about backups are read (in CAIQ v4: BCR-08.1 to BCR-08.3). For
each one we keep the question, the answer (Yes / No / NA), who owns the control
under the shared-responsibility model, and the provider's implementation
description, where a schedule may be stated ("backed up daily"). Both CAIQ v4
(one answer column) and v3.1 (Yes / No / Not Applicable columns marked with an
X) are read.
"""

from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass

_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
MAX_UNZIPPED = 100 * 1024 * 1024
_QUESTION_ID = re.compile(r"^[A-Z]{2,4}-\d{2}(?:\.\d+)?$")
ANSWERS = ("yes", "no", "na")
# Backup questions sit in the business-continuity (BCR) domain; other domains mention "backed up" or
# "replicating" in passing (data locations, test data) and are not about backup practice.
_BACKUP_QUESTION = re.compile(r"\bback(?:ed|ing|s)?[\s-]?ups?\b", re.IGNORECASE)


@dataclass
class CaiqAnswer:
    question_id: str
    question: str
    answer: str | None  # yes / no / na, or None when left blank
    ownership: str | None  # e.g. "CSP-owned", "Shared CSP and CSC", "CSC-owned"
    description: str | None  # the provider's implementation description / notes
    customer_part: str | None  # what CAIQ v4 says the customer (CSC) must do


def _squash(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def _col(ref: str) -> int:
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group(0):
        n = n * 26 + ord(ch) - 64
    return n - 1


def sheet_rows(content: bytes):
    """Yield (sheet name, [cell text by column]) for every row of every sheet."""
    z = zipfile.ZipFile(io.BytesIO(content))
    if sum(i.file_size for i in z.infolist()) > MAX_UNZIPPED:
        raise ValueError("workbook expands to more than the size limit")
    shared: list[str] = []
    if "xl/sharedStrings.xml" in z.namelist():
        root = ET.fromstring(z.read("xl/sharedStrings.xml"))
        shared = ["".join(t.text or "" for t in si.iter(f"{_S}t")) for si in root.iter(f"{_S}si")]
    names = [s.get("name") for s in ET.fromstring(z.read("xl/workbook.xml")).iter(f"{_S}sheet")]
    sheets = sorted((n for n in z.namelist() if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n)),
                    key=lambda n: int(re.search(r"(\d+)\.xml$", n).group(1)))
    for i, name in enumerate(sheets):
        label = names[i] if i < len(names) else f"sheet {i + 1}"
        for row in ET.fromstring(z.read(name)).iter(f"{_S}row"):
            cells: dict[int, str] = {}
            for pos, c in enumerate(row.iter(f"{_S}c")):
                if c.get("t") == "s":
                    v = c.find(f"{_S}v")
                    idx = int(v.text) if v is not None and v.text and v.text.isdigit() else -1
                    value = shared[idx] if 0 <= idx < len(shared) else ""
                elif c.get("t") == "inlineStr":
                    value = "".join(t.text or "" for t in c.iter(f"{_S}t"))
                else:
                    v = c.find(f"{_S}v")
                    value = v.text if v is not None and v.text else ""
                cells[_col(c.get("r")) if c.get("r") else pos] = _squash(value)
            width = max(cells, default=-1) + 1
            yield label, [cells.get(j, "") for j in range(width)]


def _find(header: list[str], *needles: str, avoid: tuple[str, ...] = ()) -> int | None:
    for j, h in enumerate(header):
        low = h.lower()
        if any(n in low for n in needles) and not any(a in low for a in avoid):
            return j
    return None


def _cell(cells: list[str], cols: dict[str, int | None], name: str) -> str:
    j = cols.get(name)
    return cells[j] if j is not None and j < len(cells) else ""


def _answer(text: str) -> str | None:
    low = text.strip().lower().rstrip(".")
    if low in ("yes", "y"):
        return "yes"
    if low in ("no", "n"):
        return "no"
    if low in ("na", "n/a", "not applicable"):
        return "na"
    return None


def read_caiq(content: bytes) -> list[CaiqAnswer]:
    """The backup questions of a CAIQ workbook with their answers. Empty if the file is not a CAIQ."""
    found: list[CaiqAnswer] = []
    seen: set[str] = set()
    header: list[str] | None = None
    cols: dict[str, int | None] = {}
    marks: dict[str, int] = {}  # v3.1: answer -> column with an X
    for _, cells in sheet_rows(content):
        if any(c.lower() == "question id" for c in cells):
            header = cells
            cols = {
                "id": _find(header, "question id"),
                "question": _find(header, "question", avoid=("question id", "answer")),
                "answer": _find(header, "caiq answer", "assessment answer", "answer"),
                "ownership": _find(header, "ssrm", "ownership"),
                "description": _find(header, "implementation description", "notes", "comment"),
                "customer": _find(header, "csc responsibilit"),
            }
            marks = {}
            continue
        if header is None:
            continue
        lowered = [c.lower() for c in cells]
        if {"yes", "no"} <= set(lowered):  # v3.1 sub-header under "Consensus Assessment Answers"
            marks = {"yes": lowered.index("yes"), "no": lowered.index("no")}
            for j, c in enumerate(lowered):
                if c in ("not applicable", "n/a", "na"):
                    marks["na"] = j
            continue
        qid, question = _cell(cells, cols, "id"), _cell(cells, cols, "question")
        if (not _QUESTION_ID.match(qid) or not qid.startswith("BCR") or not _BACKUP_QUESTION.search(question)
                or qid in seen):
            continue
        seen.add(qid)
        if marks:
            answer = next((a for a, j in marks.items() if j < len(cells) and cells[j].strip()), None)
        else:
            answer = _answer(_cell(cells, cols, "answer"))
        found.append(CaiqAnswer(qid, question, answer, _cell(cells, cols, "ownership") or None,
                                _cell(cells, cols, "description") or None, _cell(cells, cols, "customer") or None))
    return found
