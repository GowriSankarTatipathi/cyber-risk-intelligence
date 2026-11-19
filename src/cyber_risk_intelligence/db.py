"""Engine and session helpers."""

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import database_url


def make_engine(url: str | None = None, *, test: bool = False) -> Engine:
    return create_engine(url or database_url(test=test), future=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
