"""Find security-control statements in a trust-center or security page.

Every claim keeps the exact sentence as published, the paragraph around it and
the nearest heading, so a reviewer can check it against the stored page.
Matching is deliberately conservative and keyword based: it finds candidate
statements, it does not judge whether they are true. Statements that deny a
control ("we do not support SSO") are kept and marked ``negated``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime

from bs4 import BeautifulSoup, Tag

I = re.IGNORECASE

# category -> (pattern, optional function returning a qualifier from the match/sentence)
_P = {
    "encryption_at_rest": re.compile(
        r"encrypt\w*\b[^.;]{0,80}\bat[- ]rest\b|\bat[- ]rest\b[^.;]{0,60}\bencrypt\w*|\bAES[- ]?(?:128|192|256)\b", I),
    "encryption_in_transit": re.compile(
        r"encrypt\w*\b[^.;]{0,80}\bin[- ]transit\b|\bin[- ]transit\b[^.;]{0,60}\bencrypt\w*|\bTLS\b|\bHTTPS\b|\bHSTS\b", I),
    "key_management": re.compile(
        r"\bkey management\b|\bKMS\b|\bHSMs?\b|hardware security modules?|customer[- ]managed (?:encryption )?keys|\bBYOK\b|bring your own key", I),
    "mfa": re.compile(
        r"multi[- ]factor|two[- ]factor|\b2FA\b|\bMFA\b|(?:2|two)[- ]step verification|phishing[- ]resistant|\bFIDO2?\b|\bpasskeys?\b|hardware security keys?", I),
    "sso": re.compile(r"single sign[- ]on|\bSSO\b|\bSAML\b|OpenID Connect|\bOIDC\b|\bSCIM\b", I),
    "access_control": re.compile(
        r"least[- ]privilege|role[- ]based access|\bRBAC\b|access reviews?|privileged access|just[- ]in[- ]time access|need[- ]to[- ]know|zero[- ]trust", I),
    "security_policy": re.compile(
        r"information security (?:policy|policies|program|programme|management system)|security polic(?:y|ies)\b|\bISMS\b|acceptable use polic", I),
    "vulnerability_management": re.compile(
        r"vulnerability (?:scanning|scans|management|assessments?)|patch(?:ing| management)\b|\bCVEs?\b", I),
    "penetration_testing": re.compile(r"penetration test\w*|\bpen[- ]?tests?\b|red[- ]team\w*", I),
    "bug_bounty": re.compile(
        r"bug bounty|vulnerability disclosure (?:program|programme|policy)|responsible disclosure|security\.txt|HackerOne|Bugcrowd", I),
    "incident_response": re.compile(
        r"incident response|security incidents?|breach notification|notify (?:affected )?customers", I),
    "backup_and_recovery": re.compile(
        r"\bbackups?\b|backed up|disaster recovery|business continuity|recovery (?:point|time) objective|\bRPO\b|\bRTO\b", I),
    "logging_and_monitoring": re.compile(
        r"audit logs?|security logging|\bSIEM\b|24\s*/\s*7|24x7|security operations cent(?:er|re)|intrusion (?:detection|prevention)|continuous(?:ly)? monitor", I),
    "security_training": re.compile(r"security (?:awareness )?training|phishing simulations?", I),
    "vendor_risk": re.compile(
        r"(?:vendor|third[- ]party|supplier) (?:risk|security|assessments?|reviews?|management)|\bsub-?processors?\b", I),
    "data_residency": re.compile(
        r"data residency|data localization|data localisation|EU data boundary|data (?:is|are) stored in|data cent(?:er|re)s? (?:located )?in", I),
}

_FRAMEWORKS = [
    ("SOC 2 Type II", r"SOC\s?2\s*(?:®)?\s*Type\s*(?:II|2)\b"),
    ("SOC 2 Type I", r"SOC\s?2\s*(?:®)?\s*Type\s*(?:I|1)\b"),
    ("SOC 2", r"SOC\s?2\b"),
    ("SOC 1", r"SOC\s?1\b"),
    ("SOC 3", r"SOC\s?3\b"),
    ("ISO/IEC 27001", r"ISO(?:/IEC)?\s?27001\b"),
    ("ISO/IEC 27017", r"ISO(?:/IEC)?\s?27017\b"),
    ("ISO/IEC 27018", r"ISO(?:/IEC)?\s?27018\b"),
    ("ISO/IEC 27701", r"ISO(?:/IEC)?\s?27701\b"),
    ("ISO 22301", r"ISO\s?22301\b"),
    ("ISO 9001", r"ISO\s?9001\b"),
    ("PCI DSS", r"PCI[- ]?DSS\b|\bPCI\b"),
    ("HIPAA", r"\bHIPAA\b"),
    ("HITRUST", r"\bHITRUST\b"),
    ("FedRAMP High", r"FedRAMP\s+High\b"),
    ("FedRAMP Moderate", r"FedRAMP\s+Moderate\b"),
    ("FedRAMP", r"\bFedRAMP\b"),
    ("StateRAMP", r"\bStateRAMP\b"),
    ("CSA STAR", r"CSA\s+STAR\b"),
    ("TISAX", r"\bTISAX\b"),
    ("C5", r"\bBSI\s+C5\b|\bC5\b(?=[^.]{0,40}(?:attest|BSI|catalogue|catalog))"),
    ("IRAP", r"\bIRAP\b"),
    ("GDPR", r"\bGDPR\b"),
    ("CCPA", r"\bCCPA\b|\bCPRA\b"),
    ("NIST SP 800-53", r"NIST\s*(?:SP\s*)?800-53"),
    ("NIST CSF", r"NIST\s+(?:CSF|Cybersecurity Framework)"),
    ("CMMC", r"\bCMMC\b"),
    ("Cyber Essentials Plus", r"Cyber Essentials Plus"),
    ("Cyber Essentials", r"Cyber Essentials\b"),
]
_FRAMEWORK_RE = [(name, re.compile(rx, I)) for name, rx in _FRAMEWORKS]

_QUALIFIERS = {
    "encryption_at_rest": re.compile(r"\bAES[- ]?(128|192|256)\b", I),
    "encryption_in_transit": re.compile(r"\bTLS\s?v?(1\.[0-3])\b", I),
}

_NEGATION = re.compile(
    r"\b(?:not|never|no longer|doesn't|does not|don't|do not|cannot|can't|isn't|is not|aren't|are not|"
    r"without|unsupported|lacks?)\b", I)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"“(])")
_BLOCKS = ["p", "li", "td", "dd", "dt", "blockquote", "figcaption", "h2", "h3", "h4", "h5", "h6"]
_HEADINGS = ["h1", "h2", "h3", "h4"]

_MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
_UPDATED = re.compile(
    rf"(?:last\s+(?:updated|modified|revised)|updated|effective(?:\s+date)?)\s*(?:on|as of)?\s*[:\-]?\s*"
    rf"((?:{_MONTHS})\s+\d{{1,2}},?\s+\d{{4}}|\d{{1,2}}\s+(?:{_MONTHS})\s+\d{{4}}|\d{{4}}-\d{{2}}-\d{{2}})", I)


@dataclass(frozen=True)
class ExtractedClaim:
    category: str
    assertion: str
    qualifier: str | None
    claim_text: str
    context_text: str
    section_heading: str | None

    @property
    def claim_hash(self) -> str:
        return hashlib.sha256(_squash(self.claim_text).lower().encode()).hexdigest()


@dataclass
class PageExtract:
    title: str | None = None
    published_at: datetime | None = None
    updated_on: date | None = None
    claims: list[ExtractedClaim] = field(default_factory=list)


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _parse_date(value: str) -> date | None:
    value = _squash(value).replace(",", "")
    for fmt in ("%B %d %Y", "%d %B %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            pass
    return None


def _parse_datetime(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        d = _parse_date(value)
        return datetime(d.year, d.month, d.day, tzinfo=UTC) if d else None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _dates(soup: BeautifulSoup, text: str) -> tuple[datetime | None, date | None]:
    published = updated = None
    for attrs in ({"property": "article:published_time"}, {"name": "date"}, {"name": "dc.date"},
                  {"itemprop": "datePublished"}):
        tag = soup.find("meta", attrs=attrs)
        if tag and tag.get("content"):
            published = _parse_datetime(tag["content"])
            if published:
                break
    for attrs in ({"property": "article:modified_time"}, {"itemprop": "dateModified"}):
        tag = soup.find("meta", attrs=attrs)
        if tag and tag.get("content") and (dt := _parse_datetime(tag["content"])):
            updated = dt.date()
            break
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string or "")
        except ValueError:
            continue
        for item in data if isinstance(data, list) else [data]:
            if isinstance(item, dict):
                if not published and item.get("datePublished"):
                    published = _parse_datetime(str(item["datePublished"]))
                if not updated and item.get("dateModified"):
                    dt = _parse_datetime(str(item["dateModified"]))
                    updated = dt.date() if dt else None
    if not updated and (m := _UPDATED.search(text)):
        updated = _parse_date(m.group(1))
    return published, updated


def _negated(sentence: str, start: int) -> bool:
    return bool(_NEGATION.search(sentence[max(0, start - 60):start]))


def _claims_in_sentence(sentence: str, context: str, heading: str | None) -> list[ExtractedClaim]:
    out: list[ExtractedClaim] = []
    for category, pattern in _P.items():
        m = pattern.search(sentence)
        if not m:
            continue
        q = _QUALIFIERS.get(category)
        qm = q.search(sentence) if q else None
        qualifier = None
        if qm:
            qualifier = f"AES-{qm.group(1)}" if category == "encryption_at_rest" else f"TLS {qm.group(1)}"
        out.append(ExtractedClaim(category, "negated" if _negated(sentence, m.start()) else "affirmed",
                                  qualifier, sentence, context, heading))
    seen: set[str] = set()
    for name, rx in _FRAMEWORK_RE:
        m = rx.search(sentence)
        if not m:
            continue
        family = name.split(" Type")[0].replace(" High", "").replace(" Moderate", "").replace(" Plus", "")
        if family in seen:  # "SOC 2 Type II" already found; don't add a plain "SOC 2" too
            continue
        seen.add(family)
        out.append(ExtractedClaim("compliance_certification",
                                  "negated" if _negated(sentence, m.start()) else "affirmed",
                                  name, sentence, context, heading))
    return out


def extract(html: bytes | str) -> PageExtract:
    soup = BeautifulSoup(html, "html.parser")
    for junk in soup(["script", "style", "noscript", "template", "nav", "svg", "form"]):
        if junk.name == "script" and junk.get("type") == "application/ld+json":
            continue
        junk.decompose()
    page = PageExtract(title=_squash(soup.title.get_text()) if soup.title else None)
    page.published_at, page.updated_on = _dates(soup, soup.get_text(" "))

    seen: set[tuple[str, str | None, str]] = set()
    for block in soup.find_all(_BLOCKS):
        if not isinstance(block, Tag):
            continue
        # Skip containers whose text is covered by a nested block (e.g. <li><p>..</p></li>).
        if block.find(_BLOCKS):
            continue
        context = _squash(block.get_text(" "))
        if len(context) < 12 or len(context) > 4000:
            continue
        heading_tag = block.find_previous(_HEADINGS) if block.name not in _HEADINGS else None
        heading = _squash(heading_tag.get_text(" ")) if heading_tag else None
        for sentence in _SENTENCE_SPLIT.split(context):
            sentence = sentence.strip()
            if len(sentence) < 12 or len(sentence) > 1000:
                continue
            for claim in _claims_in_sentence(sentence, context, heading):
                key = (claim.category, claim.qualifier, claim.claim_hash)
                if key not in seen:
                    seen.add(key)
                    page.claims.append(claim)
    return page
