"""Read certification details out of text: which framework, who issued it, dates, scope.

Conservative on purpose: a value is filled in only when the text states it next
to a recognisable label ("Certificate number:", "Valid until", "for the period
... to ..."). Anything not stated stays None (unknown), never guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime

from ..models.assurance import FRAMEWORKS

I = re.IGNORECASE

# 1.1 claim qualifiers -> (framework, report_type, level). Self-declared alignment (GDPR, HIPAA, NIST) maps to None.
_QUALIFIER_MAP: dict[str, tuple[str, str | None, str | None]] = {
    "SOC 2 Type II": ("SOC 2", "Type II", None),
    "SOC 2 Type I": ("SOC 2", "Type I", None),
    "FedRAMP High": ("FedRAMP", None, "High"),
    "FedRAMP Moderate": ("FedRAMP", None, "Moderate"),
    **{f: (f, None, None) for f in FRAMEWORKS},
}


def framework_from_qualifier(qualifier: str | None) -> tuple[str, str | None, str | None] | None:
    return _QUALIFIER_MAP.get(qualifier or "")


# Frameworks as they appear in documents, most specific first.
_DOC_FRAMEWORKS: list[tuple[re.Pattern[str], tuple[str, str | None, str | None]]] = [
    (re.compile(r"SOC\s?2\s*(?:®)?\s*Type\s*(?:II|2)\b", I), ("SOC 2", "Type II", None)),
    (re.compile(r"SOC\s?2\s*(?:®)?\s*Type\s*(?:I|1)\b", I), ("SOC 2", "Type I", None)),
    (re.compile(r"SOC\s?1\s*(?:®)?\s*Type\s*(?:II|2)\b", I), ("SOC 1", "Type II", None)),
    (re.compile(r"\bSOC\s?3\b", I), ("SOC 3", None, None)),
    (re.compile(r"\bSOC\s?2\b", I), ("SOC 2", None, None)),
    (re.compile(r"\bSOC\s?1\b", I), ("SOC 1", None, None)),
    (re.compile(r"ISO(?:/IEC)?\s?27001\b", I), ("ISO/IEC 27001", None, None)),
    (re.compile(r"ISO(?:/IEC)?\s?27017\b", I), ("ISO/IEC 27017", None, None)),
    (re.compile(r"ISO(?:/IEC)?\s?27018\b", I), ("ISO/IEC 27018", None, None)),
    (re.compile(r"ISO(?:/IEC)?\s?27701\b", I), ("ISO/IEC 27701", None, None)),
    (re.compile(r"ISO\s?22301\b", I), ("ISO 22301", None, None)),
    (re.compile(r"ISO\s?9001\b", I), ("ISO 9001", None, None)),
    (re.compile(r"\bHITRUST\b", I), ("HITRUST", None, None)),
    (re.compile(r"PCI[- ]?DSS\b", I), ("PCI DSS", None, None)),
    (re.compile(r"FedRAMP\s+High\b", I), ("FedRAMP", None, "High")),
    (re.compile(r"FedRAMP\s+Moderate\b", I), ("FedRAMP", None, "Moderate")),
    (re.compile(r"\bFedRAMP\b", I), ("FedRAMP", None, None)),
    (re.compile(r"\bStateRAMP\b", I), ("StateRAMP", None, None)),
    (re.compile(r"CSA\s+STAR\b", I), ("CSA STAR", None, None)),
    (re.compile(r"\bTISAX\b", I), ("TISAX", None, None)),
    (re.compile(r"Cyber Essentials Plus", I), ("Cyber Essentials Plus", None, None)),
    (re.compile(r"Cyber Essentials\b", I), ("Cyber Essentials", None, None)),
]

# Well-known certification bodies and audit firms. Free-text "issued by X" is also read.
ISSUERS = (
    "BSI", "Schellman", "A-LIGN", "Coalfire", "Deloitte", "Ernst & Young", "EY", "KPMG", "PwC",
    "PricewaterhouseCoopers", "TÜV SÜD", "TÜV Rheinland", "TÜV NORD", "TÜV", "DNV", "Bureau Veritas", "LRQA",
    "SGS", "Intertek", "NQA", "Prescient", "Grant Thornton", "BDO", "Moss Adams", "Crowe", "Ellucian",
    "Johanson Group", "Insight Assurance", "Sensiba", "Advantage Partners", "Strike Graph", "Certification Europe",
    "DQS", "Perry Johnson Registrars", "QMS International", "IAS", "Mazars", "CertiProf",
)
ACCREDITATION_BODIES = ("UKAS", "ANAB", "DAkkS", "COFRAC", "ACCREDIA", "ENAC", "JAS-ANZ", "SCC", "RvA", "IAS")

_MONTHS = ("January|February|March|April|May|June|July|August|September|October|November|December|"
           "Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec")
DATE = (rf"(?:(?:{_MONTHS})\.?\s+\d{{1,2}},?\s+\d{{4}}|\d{{1,2}}(?:st|nd|rd|th)?\s+(?:{_MONTHS})\.?,?\s+\d{{4}}"
        rf"|\d{{4}}-\d{{2}}-\d{{2}}|\d{{1,2}}/\d{{1,2}}/\d{{4}})")

_VALID_UNTIL = re.compile(
    rf"(?:valid\s+(?:until|through|to)|expir(?:y|ation|es)(?:\s+date)?(?:\s+on)?|date\s+of\s+expiry|"
    rf"certificate\s+expiry)\s*[:\-]?\s*({DATE})", I)
_VALID_FROM = re.compile(rf"(?:valid\s+from|effective\s+(?:date|from)|validity\s+from)\s*[:\-]?\s*({DATE})", I)
_ISSUED = re.compile(
    rf"(?:(?:latest\s+)?issue\s+date|date\s+of\s+issue|issued\s+on|date\s+issued|certificate\s+date)"
    rf"\s*[:\-]?\s*({DATE})", I)
_ORIGINAL = re.compile(
    rf"(?:original\s+(?:certification|approval|registration)|initial\s+certification)\s+date\s*[:\-]?\s*({DATE})", I)
_PERIOD = re.compile(
    rf"(?:for\s+the\s+period|period\s+(?:of|from)|period)\s*(?:from\s+)?({DATE})\s*(?:to|through|-|–)\s*({DATE})", I)
_AS_OF = re.compile(rf"\bas\s+of\s+({DATE})", I)
_CERT_NO = re.compile(
    r"(?:certificate|cert\.?|registration)\s*(?:no\.?|number|#|id)\s*[:.\-]?\s*([A-Z0-9][A-Z0-9/\-. ]{2,30}[A-Z0-9])", I)
_SCOPE = re.compile(r"\bscope(?:\s+of\s+(?:certification|registration|the\s+report))?\s*[:\-]\s*(.{10,600}?)"
                    r"(?=(?:\s{2,}|\n|certificate|valid|issue|expir|$))", I | re.DOTALL)
_ISSUED_BY = re.compile(r"(?:issued|audited|certified|assessed|examined|registered)\s+by\s+([A-Z][\w&.,'\- ]{2,60}?)"
                        r"(?=[.,;\n]|\s+(?:on|in|for|under|and)\b|$)")
_GATED = re.compile(r"\b(?:NDA|non-disclosure|upon\s+request|on\s+request|request\s+(?:a\s+copy|access)|"
                    r"available\s+to\s+(?:customers|prospects)|under\s+confidentiality|sign\s+in\s+to\s+(?:view|download))\b", I)


@dataclass
class AssuranceDetails:
    issuer: str | None = None
    accreditation_body: str | None = None
    certificate_number: str | None = None
    scope_text: str | None = None
    issued_on: date | None = None
    valid_from: date | None = None
    valid_until: date | None = None
    period_start: date | None = None
    period_end: date | None = None
    gated: bool = False
    frameworks: list[tuple[str, str | None, str | None]] = field(default_factory=list)


def parse_date(value: str) -> date | None:
    v = re.sub(r"(\d)(st|nd|rd|th)\b", r"\1", value.strip().replace(",", "").replace(".", ""))
    v = re.sub(r"\s+", " ", v).replace("Sept ", "Sep ")
    for fmt in ("%B %d %Y", "%b %d %Y", "%d %B %Y", "%d %b %Y", "%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(v, fmt).date()  # noqa: DTZ007 - a calendar date, no time zone
        except ValueError:
            pass
    return None


def frameworks_in(text: str) -> list[tuple[str, str | None, str | None]]:
    """Frameworks named in ``text``; "SOC 2" is not repeated when "SOC 2 Type II" was found."""
    found: list[tuple[str, str | None, str | None]] = []
    for rx, fw in _DOC_FRAMEWORKS:
        if not rx.search(text) or fw in found:
            continue
        generic = fw[1] is None and fw[2] is None
        if generic and any(f[0] == fw[0] for f in found):
            continue  # a more specific form (Type II, High) is already listed
        found.append(fw)
    return found


def details(text: str) -> AssuranceDetails:
    d = AssuranceDetails(frameworks=frameworks_in(text))
    flat = re.sub(r"[ \t]+", " ", text)
    if m := _VALID_UNTIL.search(flat):
        d.valid_until = parse_date(m.group(1))
    if m := _VALID_FROM.search(flat):
        d.valid_from = parse_date(m.group(1))
    if m := (_ISSUED.search(flat) or _ORIGINAL.search(flat)):
        d.issued_on = parse_date(m.group(1))
    if m := _PERIOD.search(flat):
        d.period_start, d.period_end = parse_date(m.group(1)), parse_date(m.group(2))
    elif m := _AS_OF.search(flat):  # Type I reports describe a point in time
        d.period_end = parse_date(m.group(1))
    if m := _CERT_NO.search(flat):
        d.certificate_number = m.group(1).strip()
    if m := _SCOPE.search(text):
        scope = re.sub(r"^(?:scope\s*[:\-]\s*)+", "", re.sub(r"\s+", " ", m.group(1)).strip(), flags=I)
        d.scope_text = scope.strip(" .;:") or None
    for name in ISSUERS:
        if re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", flat):
            d.issuer = name
            break
    if d.issuer is None and (m := _ISSUED_BY.search(flat)):
        d.issuer = m.group(1).strip()
    for name in ACCREDITATION_BODIES:
        if re.search(rf"\b{re.escape(name)}\b", flat) and name != d.issuer:
            d.accreditation_body = name
            break
    d.gated = bool(_GATED.search(flat))
    # Reversed dates mean we misread something: keep neither rather than store nonsense.
    if d.valid_from and d.valid_until and d.valid_until < d.valid_from:
        d.valid_from = d.valid_until = None
    if d.period_start and d.period_end and d.period_end < d.period_start:
        d.period_start = d.period_end = None
    return d


_DOCUMENT_MARKERS = re.compile(
    r"this\s+is\s+to\s+certify|certificate\s+of\s+(?:registration|approval|conformity|compliance)|"
    r"certificate\s+(?:no|number|#)|independent\s+service\s+auditor|report\s+on\s+(?:management'?s\s+)?description|"
    r"(?:SOC\s?[23])\s*(?:®)?\s*(?:Type\s*(?:I|II|1|2)\s*)?report|attestation\s+of\s+compliance|"
    r"(?:has\s+been|is)\s+(?:certified|registered|assessed)\s+(?:as\s+)?(?:to\s+be\s+)?(?:in\s+)?(?:compliance|conform)", I)


def looks_like_assurance_document(text: str) -> bool:
    """A certificate or audit report, as opposed to a page that merely mentions a framework."""
    head = text[:6000]
    return bool(frameworks_in(head)) and bool(_DOCUMENT_MARKERS.search(head))
