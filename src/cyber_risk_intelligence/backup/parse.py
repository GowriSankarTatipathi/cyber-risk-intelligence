"""Read backup schedules out of a company's own sentences (issue 2.1).

Only what the sentence says is recorded. "Daily" and "continuously" stay different
(``daily`` with a 1440-minute interval; ``continuous`` with no interval). A sentence
about backups that gives no schedule leaves the frequency unknown (NULL), never a guess.
Frequencies attached to testing or review ("DR plans are tested annually") are not
backup frequencies and are skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

I = re.IGNORECASE

BACKUP_WORDS = re.compile(r"\bback(?:ed|ing|s)?[\s-]?ups?\b|\bsnapshots?\b|\breplicat(?:e|ed|es|ion|ing)\b", I)
OBJECTIVE_WORDS = re.compile(r"\bRPO\b|\bRTO\b|recovery (?:point|time) objectives?", I)

FREQUENCY_CLASSES = ("continuous", "sub_hourly", "hourly", "sub_daily", "daily", "weekly", "monthly", "other")
SCOPES = ("own_practice", "product_capability", "customer_responsibility")
METHODS = ("full", "incremental", "differential", "snapshot", "replication")

_NUM = (r"(\d+|one|two|three|four|five|six|seven|eight|nine|ten|twelve|fourteen|fifteen|twenty|thirty|"
        r"sixty|ninety)")
_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
          "ten": 10, "twelve": 12, "fourteen": 14, "fifteen": 15, "twenty": 20, "thirty": 30, "sixty": 60,
          "ninety": 90}
_UNIT_MINUTES = {"minute": 1, "min": 1, "hour": 60, "hr": 60, "day": 1440, "week": 10080, "month": 43200}

# (pattern, class, interval in minutes); checked in this order, first hit at a position wins.
_FREQUENCIES: list[tuple[re.Pattern, str | None, int | None]] = [
    (re.compile(r"\bcontinuous(?:ly)?\b|\breal[\s-]time\b|\bnear[\s-]real[\s-]time\b", I), "continuous", None),
    (re.compile(rf"\bevery\s+{_NUM}\s*(minute|min|hour|hr|day|week|month)s?\b", I), None, None),  # computed
    (re.compile(r"\bevery\s+(minute|hour|day|week|month)\b", I), None, None),  # computed, n = 1
    (re.compile(rf"\b{_NUM}\s+times?\s+(?:a|per|each)\s+day\b|\bmultiple times (?:a|per|each) day\b|"
                r"\bseveral times (?:a|per|each) day\b|\btwice (?:a|per|each) day\b|\bintra-?day\b", I), "sub_daily", None),
    (re.compile(r"\bhourly\b|\bonce (?:an|per|each) hour\b", I), "hourly", 60),
    (re.compile(r"\bdaily\b|\bnightly\b|\bonce (?:a|per|each) day\b|\beach day\b|\bevery night\b|"
                r"\bevery 24 hours\b|\b24x?\s?hours?\b", I), "daily", 1440),
    (re.compile(r"\bweekly\b|\bonce (?:a|per|each) week\b", I), "weekly", 10080),
    (re.compile(r"\bmonthly\b|\bonce (?:a|per|each) month\b", I), "monthly", 43200),
]
# A schedule word tied to testing or review is not a backup frequency.
_NOT_BACKUP_SCHEDULE = re.compile(r"\b(test(?:ed|s|ing)?|review(?:ed|s)?|exercis(?:e|ed|es)|audit(?:ed|s)?|"
                                  r"drills?|validat(?:e|ed|es)|verif(?:y|ied|ies)|restor(?:e|ed|ation) tests?|"
                                  r"monitor(?:ed|s|ing)?)\b", I)
# ... or right after it ("monthly disaster recovery test").
# Only words that qualify the noun in between; "nightly and restore tests ..." is still a backup schedule.
_SCHEDULE_OF_TEST = re.compile(r"^[ -]+(?:(?!and\b|or\b|with\b|while\b|but\b)[a-z/-]+ ){0,3}?"
                               r"(tests?|testing|reviews?|exercises?|audits?|drills?)\b", I)

_PRODUCT = re.compile(r"\b(you can|you may|lets you|allows? (?:you|customers|users|admins|administrators) to|"
                      r"enables? (?:you|customers|users) to|customers can|users can|admins can|"
                      r"configurable|can be configured|you configure|your backups?|schedule your)\b", I)
_CUSTOMER = re.compile(r"\b(customers? (?:is|are) responsible|responsibility of the customer|"
                       r"we recommend (?:that )?(?:you|customers)|you are responsible)\b", I)

_SYSTEM = re.compile(
    r"\b((?:customer|client|production|critical|business[\s-]critical|corporate|application|platform|service|"
    r"user|tenant|primary|all)\s+)?(data(?:bases?|stores?)?|systems?|servers?|files|content|workloads|"
    r"environments?|infrastructure|configurations?|repositories|records|applications?|email|mailboxes)\b", I)
_METHOD = {
    "full": re.compile(r"\bfull\b", I),
    "incremental": re.compile(r"\bincremental\b", I),
    "differential": re.compile(r"\bdifferential\b", I),
    "snapshot": re.compile(r"\bsnapshots?\b", I),
    "replication": re.compile(r"\breplicat", I),
}
_RETENTION = re.compile(rf"(?:retain(?:ed)?|kept|stored|retention(?: period)?(?: of)?)\D{{0,25}}?{_NUM}(?:\s*\(\d+\))?\s*[- ]?"
                        r"(day|week|month|year)s?|" + _NUM + r"[- ](day|week|month|year)s?[- ]retention", I)
_OBJECTIVE = re.compile(rf"\b(RPO|RTO|recovery point objective|recovery time objective)\b[^.;]{{0,40}}?"
                        rf"(?:of|is|:|=|within|under|less than|up to)?\s*{_NUM}\s*(minute|min|hour|hr|day)s?", I)
_RETENTION_DAYS = {"day": 1, "week": 7, "month": 30, "year": 365}


def _n(word: str) -> int:
    return int(word) if word.isdigit() else _WORDS[word.lower()]


def _class_for(minutes: int) -> str:
    if minutes < 60:
        return "sub_hourly"
    if minutes == 60:
        return "hourly"
    if minutes < 1440:
        return "sub_daily"
    if minutes == 1440:
        return "daily"
    if minutes == 10080:
        return "weekly"
    if minutes in (43200,):
        return "monthly"
    return "other"


@dataclass
class Frequency:
    frequency_class: str
    interval_minutes: int | None
    phrase: str


@dataclass
class BackupStatement:
    frequencies: list[Frequency] = field(default_factory=list)  # empty = schedule not stated
    scope: str = "own_practice"
    covered_system: str | None = None
    methods: list[str] = field(default_factory=list)
    retention_days: int | None = None
    retention_phrase: str | None = None
    rpo_minutes: int | None = None
    rto_minutes: int | None = None
    objective_phrase: str | None = None


def is_backup_statement(sentence: str) -> bool:
    return bool(BACKUP_WORDS.search(sentence) or OBJECTIVE_WORDS.search(sentence))


def _frequencies(sentence: str) -> list[Frequency]:
    anchors = [m.start() for m in BACKUP_WORDS.finditer(sentence)]
    found: list[Frequency] = []
    taken: list[tuple[int, int]] = []
    for rx, cls, interval in _FREQUENCIES:
        for m in rx.finditer(sentence):
            if any(m.start() < e and s < m.end() for s, e in taken):
                continue
            # Must sit near a backup word, and not be the schedule of a test or review.
            if not anchors or min(abs(m.start() - a) for a in anchors) > 80:
                continue
            before = sentence[max(0, m.start() - 30):m.start()]
            if _NOT_BACKUP_SCHEDULE.search(before) or _SCHEDULE_OF_TEST.search(sentence[m.end():m.end() + 40]):
                continue
            if cls is None:  # every N <unit>
                n = _n(m.group(1)) if m.lastindex and m.lastindex >= 2 else 1
                unit = (m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(1)).lower()
                minutes = n * _UNIT_MINUTES[unit]
                found.append(Frequency(_class_for(minutes), minutes, m.group(0)))
            else:
                found.append(Frequency(cls, interval, m.group(0)))
            taken.append((m.start(), m.end()))
    order = {id(f): sentence.find(f.phrase) for f in found}
    return sorted(found, key=lambda f: order[id(f)])


def read_backup_statement(sentence: str) -> BackupStatement | None:
    """The backup facts in one sentence, or None if it isn't about backups or recovery objectives."""
    if not is_backup_statement(sentence):
        return None
    st = BackupStatement(frequencies=_frequencies(sentence))
    if _CUSTOMER.search(sentence):
        st.scope = "customer_responsibility"
    elif _PRODUCT.search(sentence):
        st.scope = "product_capability"
    anchor = BACKUP_WORDS.search(sentence)
    if anchor:
        systems = list(_SYSTEM.finditer(sentence))
        if systems:
            best = min(systems, key=lambda m: abs(m.start() - anchor.start()))
            st.covered_system = best.group(0).strip().lower()
    st.methods = [name for name, rx in _METHOD.items() if rx.search(sentence)]
    r = _RETENTION.search(sentence)
    if r:
        num, unit = (r.group(1), r.group(2)) if r.group(1) else (r.group(3), r.group(4))
        st.retention_days, st.retention_phrase = _n(num) * _RETENTION_DAYS[unit.lower()], r.group(0).strip()
    for m in _OBJECTIVE.finditer(sentence):
        kind = m.group(1).lower()
        minutes = _n(m.group(2)) * _UNIT_MINUTES[m.group(3).lower()]
        if kind in ("rpo", "recovery point objective") and st.rpo_minutes is None:
            st.rpo_minutes = minutes
        elif kind in ("rto", "recovery time objective") and st.rto_minutes is None:
            st.rto_minutes = minutes
        st.objective_phrase = (st.objective_phrase + "; " if st.objective_phrase else "") + m.group(0).strip()
    return st
