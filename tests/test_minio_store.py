"""Round-trip against a real MinIO. Skipped unless MINIO_ENDPOINT is set."""

import os
import uuid

import pytest

from cyber_risk_intelligence.evidence.store import sha256_hex

pytestmark = pytest.mark.skipif(not os.environ.get("MINIO_ENDPOINT"), reason="MINIO_ENDPOINT is not set")


def test_minio_round_trip():
    from cyber_risk_intelligence.evidence import MinioStore

    store = MinioStore(
        os.environ["MINIO_ENDPOINT"],
        os.environ["MINIO_ACCESS_KEY"],
        os.environ["MINIO_SECRET_KEY"],
        bucket=os.environ.get("EVIDENCE_TEST_BUCKET", "evidence-test"),
        secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
    )
    content = f"synthetic evidence {uuid.uuid4()}".encode()
    first = store.put(content, "text/plain")
    again = store.put(content, "text/plain")
    assert first == again
    assert first.sha256 == sha256_hex(content)
    assert store.get(first.key) == content
