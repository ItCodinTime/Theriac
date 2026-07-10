"""Vultr Object Storage client for manuals and object-locked evidence."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from schemas.control_plane import EvidenceBundle


class VultrObjectStorageError(RuntimeError):
    pass


class VultrObjectStorage:
    def __init__(self, client: Any | None = None) -> None:
        self.endpoint = os.getenv("VULTR_OBJECT_STORAGE_ENDPOINT", "")
        self.access_key = os.getenv("VULTR_OBJECT_STORAGE_ACCESS_KEY", "")
        self.secret_key = os.getenv("VULTR_OBJECT_STORAGE_SECRET_KEY", "")
        self.manual_bucket = os.getenv("VULTR_MANUAL_BUCKET", "panacea-manuals")
        self.evidence_bucket = os.getenv("VULTR_EVIDENCE_BUCKET", "panacea-evidence")
        self.strict = os.getenv("VULTR_NATIVE_STRICT", "false").lower() == "true"
        self._client = client

    @property
    def configured(self) -> bool:
        return bool(self.endpoint and self.access_key and self.secret_key)

    def _s3(self):
        if self._client is not None:
            return self._client
        if not self.configured:
            raise VultrObjectStorageError("Vultr Object Storage credentials are not configured")
        try:
            import boto3
        except ImportError as exc:
            raise VultrObjectStorageError("boto3 is required for Vultr Object Storage") from exc
        self._client = boto3.client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=os.getenv("VULTR_OBJECT_STORAGE_REGION", "us-east-1"),
        )
        return self._client

    def store_manual(self, filename: str, content: bytes, content_type: str) -> str:
        digest = hashlib.sha256(content).hexdigest()
        safe_name = "".join(char for char in filename if char.isalnum() or char in "._-") or "manual.pdf"
        key = f"manuals/{digest[:16]}/{safe_name}"
        self._s3().put_object(
            Bucket=self.manual_bucket,
            Key=key,
            Body=content,
            ContentType=content_type,
            Metadata={"sha256": digest, "system": "panacea"},
        )
        return key

    def seal_evidence(self, bundle: EvidenceBundle) -> tuple[str, str]:
        client = self._s3()
        previous_hash = ""
        try:
            head = client.get_object(Bucket=self.evidence_bucket, Key="evidence/HEAD")
            previous_hash = head["Body"].read().decode().strip()
        except Exception:
            previous_hash = ""

        unsigned = bundle.model_copy(
            update={"previous_evidence_sha256": previous_hash, "evidence_sha256": ""}
        )
        canonical = json.dumps(unsigned.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        evidence_hash = hashlib.sha256(canonical.encode()).hexdigest()
        sealed = unsigned.model_copy(update={"evidence_sha256": evidence_hash})
        body = json.dumps(sealed.model_dump(mode="json"), sort_keys=True, indent=2).encode()
        key = f"evidence/{bundle.created_at:%Y/%m/%d}/{bundle.evidence_id}.json"

        kwargs: dict[str, Any] = {
            "Bucket": self.evidence_bucket,
            "Key": key,
            "Body": body,
            "ContentType": "application/json",
            "Metadata": {"sha256": evidence_hash, "previous-sha256": previous_hash},
        }
        retention_days = int(os.getenv("VULTR_EVIDENCE_RETENTION_DAYS", "0"))
        if retention_days > 0:
            kwargs.update(
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=datetime.now(timezone.utc) + timedelta(days=retention_days),
            )
        client.put_object(**kwargs)
        client.put_object(
            Bucket=self.evidence_bucket,
            Key="evidence/HEAD",
            Body=evidence_hash.encode(),
            ContentType="text/plain",
        )
        return key, evidence_hash

    def presigned_url(self, key: str, expires_in: int = 300) -> str:
        """Short-lived, read-only URL into the evidence bucket — lets a
        compliance reviewer fetch one sealed bundle without bucket access."""
        return self._s3().generate_presigned_url(
            "get_object",
            Params={"Bucket": self.evidence_bucket, "Key": key},
            ExpiresIn=expires_in,
        )
