"""Issue 1.2: the security headers a company website sends.

* ``http_security_checks``: one row per request to a company website's home page: what was asked,
  where redirects led, whether plain HTTP is sent on to HTTPS, and how it ended. A request that
  failed (``request_failed``) says nothing about the site's headers.
* ``http_security_observations``: for an answered check, one row per header: the raw value(s) and
  the graded result (``pass``, ``weak``, ``missing``, ``invalid`` or ``info``) under the named
  ``assessment_version``, so a result can be reproduced from the stored headers.

Only each company's known domain and its ``www.`` host are asked, home page only, headers only.
"""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, IdMixin, in_list

CHECK_OUTCOMES = ("answered", "request_failed")
HTTP_REDIRECT_OUTCOMES = ("redirects_to_https", "no_redirect", "redirects_elsewhere", "request_failed")
HEADER_RESULTS = ("pass", "weak", "missing", "invalid", "info")


class HttpSecurityCheck(IdMixin, Base):
    __tablename__ = "http_security_checks"

    domain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    host: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    requested_url: Mapped[str] = mapped_column(Text, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    final_url: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    redirects: Mapped[list | None] = mapped_column(JSONB(none_as_null=True))  # [[status, location], ...]
    http_redirect: Mapped[str] = mapped_column(Text, nullable=False)  # what http://<host>/ does
    http_redirect_location: Mapped[str | None] = mapped_column(Text)
    assessment_version: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_version_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), index=True
    )
    ingestion_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_runs.id", ondelete="SET NULL"), index=True
    )

    __table_args__ = (
        CheckConstraint(in_list("outcome", CHECK_OUTCOMES), name="outcome"),
        CheckConstraint(in_list("http_redirect", HTTP_REDIRECT_OUTCOMES), name="http_redirect"),
        CheckConstraint("(outcome = 'answered') = (evidence_version_id IS NOT NULL)", name="evidence_when_answered"),
        CheckConstraint("(outcome = 'answered') = (http_status IS NOT NULL)", name="status_when_answered"),
    )


class HttpSecurityObservation(IdMixin, Base):
    __tablename__ = "http_security_observations"

    check_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("http_security_checks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("domains.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    header: Mapped[str] = mapped_column(Text, nullable=False)  # lower-case header name
    observed_value: Mapped[str | None] = mapped_column(Text)  # every value sent, one per line; NULL = not sent
    value_count: Mapped[int] = mapped_column(Integer, nullable=False)
    result: Mapped[str] = mapped_column(Text, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_version_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("evidence_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    __table_args__ = (
        UniqueConstraint("check_id", "header", name="uq_http_security_observations_check_header"),
        CheckConstraint(in_list("result", HEADER_RESULTS), name="result"),
        CheckConstraint("header = lower(header)", name="header_lower"),
        CheckConstraint("(value_count = 0) = (observed_value IS NULL)", name="value_when_sent"),
        CheckConstraint("result <> 'missing' OR value_count = 0", name="missing_means_not_sent"),
    )
