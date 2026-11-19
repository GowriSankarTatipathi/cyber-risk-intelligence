"""Object storage for original evidence bytes.

Objects are content-addressed: the key is derived from the SHA-256, so storing
the same bytes twice is a no-op and a key never points at different content.
"""

import hashlib
import io
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class StoredObject:
    backend: str
    bucket: str
    key: str
    sha256: str
    size_bytes: int


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def object_key(sha256: str) -> str:
    return f"sha256/{sha256[:2]}/{sha256}"


class ObjectStore(Protocol):
    backend: str
    bucket: str

    def put(self, content: bytes, media_type: str) -> StoredObject: ...

    def get(self, key: str) -> bytes: ...


class LocalStore:
    """Files on disk. For development and tests; production uses MinIO."""

    backend = "local"

    def __init__(self, root: str | Path, bucket: str = "evidence"):
        self.root = Path(root)
        self.bucket = bucket

    def _path(self, key: str) -> Path:
        return self.root / self.bucket / key

    def put(self, content: bytes, media_type: str) -> StoredObject:
        digest = sha256_hex(content)
        key = object_key(digest)
        path = self._path(key)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(content)
            tmp.replace(path)
        return StoredObject(self.backend, self.bucket, key, digest, len(content))

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()


class MinioStore:
    """MinIO or any S3-compatible store. Needs ``pip install -e ".[minio]"``."""

    backend = "minio"

    def __init__(self, endpoint: str, access_key: str, secret_key: str, bucket: str = "evidence", secure: bool = False):
        from minio import Minio

        self.client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
        self.bucket = bucket
        if not self.client.bucket_exists(bucket):
            self.client.make_bucket(bucket)

    def put(self, content: bytes, media_type: str) -> StoredObject:
        from minio.error import S3Error

        digest = sha256_hex(content)
        key = object_key(digest)
        try:
            self.client.stat_object(self.bucket, key)
        except S3Error as err:
            if err.code not in ("NoSuchKey", "NoSuchObject"):
                raise
            self.client.put_object(
                self.bucket, key, io.BytesIO(content), len(content),
                content_type=media_type, metadata={"sha256": digest},
            )
        return StoredObject(self.backend, self.bucket, key, digest, len(content))

    def get(self, key: str) -> bytes:
        resp = self.client.get_object(self.bucket, key)
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()


def store_from_env() -> ObjectStore:
    """MinIO when MINIO_ENDPOINT is set, otherwise a local folder (EVIDENCE_DIR, default ./evidence)."""
    endpoint = os.environ.get("MINIO_ENDPOINT")
    bucket = os.environ.get("EVIDENCE_BUCKET", "evidence")
    if endpoint:
        return MinioStore(
            endpoint,
            os.environ["MINIO_ACCESS_KEY"],
            os.environ["MINIO_SECRET_KEY"],
            bucket=bucket,
            secure=os.environ.get("MINIO_SECURE", "false").lower() == "true",
        )
    return LocalStore(os.environ.get("EVIDENCE_DIR", "evidence"), bucket=bucket)
