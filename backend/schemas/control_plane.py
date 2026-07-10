"""Internal schemas for policy leases, enforcement receipts, and evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from schemas.contract_a import ContractA
from schemas.contract_b import ContractB


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RuleChange(BaseModel):
    port: int
    action: Literal["ALLOW", "DENY"]
    status: str
    resource_ids: list[str] = Field(default_factory=list)
    probe_status: Literal["reachable", "blocked", "unavailable"] = "unavailable"


class EnforcementReceipt(BaseModel):
    provider: Literal["vultr"] = "vultr"
    enforcement_plane: str
    vpc_id: str
    gateway_id: str | None = None
    device_ip: str | None = None
    changes: list[RuleChange]
    enforced_at: datetime = Field(default_factory=utc_now)


class PolicyLease(BaseModel):
    lease_id: str
    source_doc_id: str
    policy: ContractB
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    status: Literal["ACTIVE", "REVOKED", "EXPIRED"] = "ACTIVE"
    receipt: EnforcementReceipt


class EvidenceBundle(BaseModel):
    evidence_id: str
    created_at: datetime = Field(default_factory=utc_now)
    contract_a: ContractA
    contract_b: ContractB
    lease: PolicyLease
    manual_sha256: str
    retrieved_context: str
    model_id: str
    prompt_version: str = "panacea-v2"
    operator_id: str = "panacea-agent"
    previous_evidence_sha256: str = ""
    evidence_sha256: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
