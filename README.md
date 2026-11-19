# cyber-risk-intelligence

Cybersecurity intelligence platform for collecting public company security data, historical incidents, vulnerabilities, financial losses, and risk evidence. It feeds the underwriting app in `cyber-underwriting-platform`, where the backlog lives.

Ground rules: public and passive data only, no active scanning without authorization, never store secrets or working credentials, a company's claim is not "verified", and missing data is recorded as unknown, not absent.

## Setup

Needs Python 3.12+ and PostgreSQL 16+ (the project runs PostgreSQL 18 in Docker on port 5433).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env        # then put the cyber_app password in .env (never commit it)
alembic upgrade head        # creates the schema in DATABASE_URL
pytest                      # uses TEST_DATABASE_URL; it is wiped and rebuilt on each run
```

The `cyber_app` role needs `CREATE` on the database (it owns it in the standard setup). The first migration runs `CREATE EXTENSION IF NOT EXISTS btree_gist`, which is a trusted extension, so the database owner can install it.

## Layout

* `src/cyber_risk_intelligence/models/`: SQLAlchemy models
* `src/cyber_risk_intelligence/normalize.py`: identifier, name and domain normalization
* `src/cyber_risk_intelligence/evidence/`: checksummed evidence storage (local folder or MinIO)
* `migrations/`: Alembic migrations
* `docs/schema/`: one page per schema issue ([17.1 company and legal entities](docs/schema/17.1-company-legal-entity.md), [17.7 evidence storage](docs/schema/17.7-evidence-storage.md))
