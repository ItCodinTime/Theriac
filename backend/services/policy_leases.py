"""Runtime renewal boundary for expiring Vultr network permissions.

Leases are also durably written to Vultr Managed Database (when configured)
so an active firewall lease survives a backend restart instead of being
forgotten along with its in-memory expiry timer — see restore_leases().
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from agent.tools.firewall import restore_active_policy
from schemas.control_plane import PolicyLease
from services.vultr_database import delete_lease, load_active_leases, save_lease
from services.vultr_events import publish_event
from services.vultr_firewall import retract_rules


_expiry_tasks: dict[str, asyncio.Task] = {}


async def schedule_expiry(lease: PolicyLease) -> None:
    """Persists the lease durably, then schedules automatic removal of all
    permissions when it expires."""
    await save_lease(lease)
    _arm(lease)


def _arm(lease: PolicyLease) -> None:
    existing = _expiry_tasks.pop(lease.lease_id, None)
    if existing:
        existing.cancel()
    _expiry_tasks[lease.lease_id] = asyncio.create_task(_expire(lease))


async def _expire(lease: PolicyLease) -> None:
    delay = max(0.0, (lease.expires_at - datetime.now(timezone.utc)).total_seconds())
    try:
        await asyncio.sleep(delay)
        receipt = await asyncio.to_thread(retract_rules, lease.policy)
        await publish_event(
            "policy.expired",
            lease.lease_id,
            {"lease_id": lease.lease_id, "source_doc_id": lease.source_doc_id, "receipt": receipt},
        )
    finally:
        _expiry_tasks.pop(lease.lease_id, None)
        await delete_lease(lease.lease_id)


async def cancel_expiry(lease_id: str) -> None:
    task = _expiry_tasks.pop(lease_id, None)
    if task:
        task.cancel()
    await delete_lease(lease_id)


async def restore_leases() -> None:
    """Rehydrates in-flight leases from Vultr Managed Database on startup.
    Leases that already expired while the process was down are retracted
    immediately instead of being re-armed."""
    for lease in await load_active_leases():
        if lease.expires_at <= datetime.now(timezone.utc):
            try:
                receipt = await asyncio.to_thread(retract_rules, lease.policy)
                await publish_event(
                    "policy.expired",
                    lease.lease_id,
                    {"lease_id": lease.lease_id, "source_doc_id": lease.source_doc_id, "receipt": receipt},
                )
            finally:
                await delete_lease(lease.lease_id)
            continue

        restore_active_policy(
            lease.policy.target_vpc_id,
            lease.policy,
            {
                "status": "applied",
                "vpc_id": lease.policy.target_vpc_id,
                "lease_id": lease.lease_id,
                "expires_at": lease.expires_at.isoformat(),
                "receipt": lease.receipt.model_dump(mode="json"),
            },
        )
        _arm(lease)
