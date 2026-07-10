"""Vultr Managed Database (PostgreSQL) client for durable policy leases and
the evidence-bundle index.

Every function here is a no-op (returns immediately / returns empty) when
VULTR_DATABASE_URL is not set, except in strict mode where it fails closed —
matching the graceful-degradation pattern used by the other Vultr services.
Without this, an active firewall lease and its expiry timer live only in this
process's memory: a restart forgets both, and the enforced rule is never
retracted or renewed.
"""

from __future__ import annotations

import json
import os
from typing import Any

from schemas.control_plane import PolicyLease


class VultrDatabaseError(RuntimeError):
    pass


_pool: Any = None


def configured() -> bool:
    return bool(os.getenv("VULTR_DATABASE_URL", ""))


def _strict() -> bool:
    return os.getenv("VULTR_NATIVE_STRICT", "false").lower() == "true"


async def _get_pool() -> Any:
    global _pool
    if _pool is not None:
        return _pool

    dsn = os.getenv("VULTR_DATABASE_URL", "")
    if not dsn:
        raise VultrDatabaseError("VULTR_DATABASE_URL is not configured")
    try:
        import asyncpg
    except ImportError as exc:
        raise VultrDatabaseError("asyncpg is required for Vultr Managed Database") from exc

    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)
    async with pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS panacea_policy_leases (
                lease_id TEXT PRIMARY KEY,
                vpc_id TEXT NOT NULL,
                lease_json JSONB NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS panacea_evidence_index (
                evidence_id TEXT PRIMARY KEY,
                object_key TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    _pool = pool
    return _pool


async def save_lease(lease: PolicyLease) -> None:
    """Durably upserts a policy lease. No-op unless VULTR_DATABASE_URL is set."""
    if not configured():
        if _strict():
            raise VultrDatabaseError("VULTR_DATABASE_URL is required in strict mode")
        return
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO panacea_policy_leases (lease_id, vpc_id, lease_json, expires_at)
            VALUES ($1, $2, $3::jsonb, $4)
            ON CONFLICT (lease_id) DO UPDATE
                SET lease_json = EXCLUDED.lease_json, expires_at = EXCLUDED.expires_at
            """,
            lease.lease_id,
            lease.policy.target_vpc_id,
            json.dumps(lease.model_dump(mode="json"), separators=(",", ":")),
            lease.expires_at,
        )


async def delete_lease(lease_id: str) -> None:
    if not configured():
        return
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM panacea_policy_leases WHERE lease_id = $1", lease_id)


async def load_active_leases() -> list[PolicyLease]:
    """Returns every durably stored lease, including already-expired ones —
    the caller decides whether to re-arm or immediately retract each one."""
    if not configured():
        return []
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT lease_json FROM panacea_policy_leases")
    return [PolicyLease.model_validate(json.loads(row["lease_json"])) for row in rows]


async def save_evidence_index(evidence_id: str, object_key: str, sha256: str) -> None:
    """Records where a sealed evidence bundle lives so it can be looked up by
    ID later (e.g. for a presigned read-access URL) without scanning the
    Object Storage bucket. No-op unless VULTR_DATABASE_URL is set."""
    if not configured():
        if _strict():
            raise VultrDatabaseError("VULTR_DATABASE_URL is required in strict mode")
        return
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO panacea_evidence_index (evidence_id, object_key, sha256)
            VALUES ($1, $2, $3)
            ON CONFLICT (evidence_id) DO UPDATE
                SET object_key = EXCLUDED.object_key, sha256 = EXCLUDED.sha256
            """,
            evidence_id,
            object_key,
            sha256,
        )


async def get_evidence_object_key(evidence_id: str) -> str | None:
    if not configured():
        return None
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT object_key FROM panacea_evidence_index WHERE evidence_id = $1", evidence_id
        )
    return row["object_key"] if row else None
