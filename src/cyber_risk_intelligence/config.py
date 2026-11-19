"""Database settings, read from the environment or a local .env file."""

import os

from dotenv import load_dotenv

load_dotenv()


def database_url(test: bool = False) -> str:
    """Return the SQLAlchemy URL for the main or test database."""
    name = "TEST_DATABASE_URL" if test else "DATABASE_URL"
    url = os.environ.get(name)
    if not url:
        raise RuntimeError(f"{name} is not set. Copy .env.example to .env and fill it in.")
    return url
