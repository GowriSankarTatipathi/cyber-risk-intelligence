"""Normalization rules shared by models, importers and tests.

Normalized values are what uniqueness is enforced on, so two spellings of the
same identifier (for example CIK "789019" and "0000789019") collide.
"""

import re
import unicodedata

_CIK = re.compile(r"^\d{1,10}$")
_LEI = re.compile(r"^[A-Z0-9]{18}[0-9]{2}$")

# Legal-form suffixes stripped only for the *search* name. The legal name itself
# is always stored exactly as published.
_LEGAL_SUFFIXES = (
    "incorporated", "inc", "corporation", "corp", "company", "co", "limited",
    "ltd", "llc", "plc", "lp", "llp", "sa", "ag", "nv", "se", "holdings",
)


def normalize_cik(value: str) -> str:
    v = value.strip()
    if not _CIK.match(v):
        raise ValueError(f"Not a valid SEC CIK: {value!r}")
    return v.zfill(10)


def normalize_lei(value: str) -> str:
    v = value.strip().upper()
    if not _LEI.match(v):
        raise ValueError(f"Not a valid LEI: {value!r}")
    if not lei_checksum_ok(v):
        raise ValueError(f"LEI checksum failed: {value!r}")
    return v


def lei_checksum_ok(lei: str) -> bool:
    """ISO 17442 uses the ISO 7064 MOD 97-10 check digits."""
    digits = "".join(str(int(c, 36)) for c in lei)
    return int(digits) % 97 == 1


def normalize_ticker(value: str) -> str:
    v = value.strip().upper()
    if not v or not re.match(r"^[A-Z0-9.\-]{1,10}$", v):
        raise ValueError(f"Not a valid ticker: {value!r}")
    return v


def normalize_identifier(scheme: str, value: str) -> str:
    if scheme == "sec_cik":
        return normalize_cik(value)
    if scheme == "lei":
        return normalize_lei(value)
    if scheme == "ticker":
        return normalize_ticker(value)
    v = value.strip()
    if not v:
        raise ValueError("Identifier value is empty")
    return v.upper()


def normalize_name(name: str) -> str:
    """Lower-case, accent-free, punctuation-free name for matching and search.

    Used to *find* candidates, never to merge records automatically: "Apple Inc."
    and "Apple Hospitality REIT" stay separate entities.
    """
    v = unicodedata.normalize("NFKD", name)
    v = "".join(c for c in v if not unicodedata.combining(c)).lower()
    v = v.replace("&", " and ")
    # Join dotted initialisms ("s.a.", "n.v.", "u.s.") so suffix stripping sees "sa", "nv".
    v = re.sub(r"(?<=\b[a-z])\.(?=[a-z]\b)", "", v)
    v = re.sub(r"[^a-z0-9]+", " ", v).strip()
    words = v.split()
    while words and words[-1] in _LEGAL_SUFFIXES:
        words.pop()
    return " ".join(words)


def normalize_domain(domain: str) -> str:
    """Lower-case hostname in IDNA (punycode) form, without scheme, path or trailing dot."""
    v = domain.strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", v)
    v = v.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    v = v.rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".")
    if not v:
        raise ValueError(f"Not a domain: {domain!r}")
    v = v.encode("idna").decode("ascii")
    if not re.match(r"^(?=.{1,253}$)([a-z0-9](-*[a-z0-9])*\.)+[a-z0-9-]{2,63}$", v):
        raise ValueError(f"Not a valid domain: {domain!r}")
    return v
