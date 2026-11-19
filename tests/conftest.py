"""Test fixtures. Tests run against a real PostgreSQL database (TEST_DATABASE_URL).

The schema is rebuilt from the Alembic migrations once per test session, so the
tests also prove the migrations work. Each test runs inside a transaction that is
rolled back afterwards.
"""

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from cyber_risk_intelligence.config import database_url

ROOT = Path(__file__).resolve().parents[1]


def _test_url() -> str:
    try:
        return database_url(test=True)
    except RuntimeError:
        pytest.skip("TEST_DATABASE_URL is not set; database tests skipped")


@pytest.fixture(scope="session")
def engine():
    url = _test_url()
    if url == os.environ.get("DATABASE_URL"):
        pytest.exit("TEST_DATABASE_URL must not point at the main database", returncode=2)
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    eng = create_engine(url)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    with engine.connect() as conn:
        trans = conn.begin()
        s = Session(bind=conn, join_transaction_mode="create_savepoint")
        try:
            yield s
        finally:
            s.close()
            trans.rollback()
