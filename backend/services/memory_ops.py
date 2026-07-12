"""Local Supermemory operations: inspect, trace, fleet recall, timelines, export.

These helpers are intentionally API-shaped but independent from FastAPI. The
agent-facing RAG facade stays in ``services.memory``; this module exposes the
operational controls needed to see, audit, and curate the local memory plane.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from schemas.attack_event import AttackHistorySummary
from schemas.contract_a import ContractA
from schemas.contract_b import ContractB
from services.supermemory import (
    CVE_CONTAINER_TAG,
    SupermemoryClient,
    SupermemoryError,
    _record_text,
    attack_container_tag,
    device_container_tag,
)


REGISTRY_CONTAINER_TAG = "theriac-memory-registry"
IMMUNITY_CONTAINER_TAG = "immunity-memory"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record_id(record: dict[str, Any]) -> str:
    for key in ("id", "documentId", "document_id", "customId"):
        value = record.get(key)
        if value is not None:
            return str(value)
    return ""


def _metadata(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("metadata")
    return value if isinstance(value, dict) else {}


def _compact_doc(record: dict[str, Any]) -> dict[str, Any]:
    metadata = _metadata(record)
    text = _record_text(record)
    return {
        "id": _record_id(record),
        "type": str(metadata.get("type") or ""),
        "metadata": metadata,
        "preview": text.replace("\n", " ")[:300],
    }


async def register_memory_space(
    space: str,
    *,
    kind: str,
    device_model: str = "",
    client: SupermemoryClient | None = None,
) -> None:
    """Best-effort registry entry so local spaces are discoverable.

    Supermemory scopes reads by container tag but does not provide a stable global
    tag listing in all local builds. A tiny registry space gives the backend a
    portable index without adding another database.
    """
    if not space:
        return
    sm = client or SupermemoryClient()
    payload = {
        "space": space,
        "kind": kind,
        "device_model": device_model,
        "updated_at": _now_iso(),
    }
    try:
        await sm.add_document(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            container_tag=REGISTRY_CONTAINER_TAG,
            metadata={
                "type": "memory-space",
                "space": space,
                "kind": kind,
                "device_model": device_model,
                "updated_at": payload["updated_at"],
            },
        )
    except SupermemoryError:
        pass


async def list_memory_spaces(
    *,
    client: SupermemoryClient | None = None,
) -> list[dict[str, Any]]:
    """Return known local Supermemory spaces from the registry plus defaults."""
    sm = client or SupermemoryClient()
    spaces: dict[str, dict[str, Any]] = {
        CVE_CONTAINER_TAG: {"space": CVE_CONTAINER_TAG, "kind": "cve", "device_model": ""},
        IMMUNITY_CONTAINER_TAG: {"space": IMMUNITY_CONTAINER_TAG, "kind": "immunity", "device_model": ""},
        REGISTRY_CONTAINER_TAG: {"space": REGISTRY_CONTAINER_TAG, "kind": "registry", "device_model": ""},
    }
    try:
        docs = await sm.list_documents(REGISTRY_CONTAINER_TAG, limit=500)
    except SupermemoryError:
        return list(spaces.values())

    for doc in docs:
        metadata = _metadata(doc)
        space = str(metadata.get("space") or "").strip()
        if not space:
            text = _record_text(doc)
            try:
                payload = json.loads(text)
                space = str(payload.get("space") or "").strip()
                metadata = {**payload, **metadata}
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
        if not space:
            continue
        current = spaces.get(space, {})
        spaces[space] = {
            "space": space,
            "kind": str(metadata.get("kind") or current.get("kind") or "unknown"),
            "device_model": str(metadata.get("device_model") or current.get("device_model") or ""),
            "updated_at": str(metadata.get("updated_at") or current.get("updated_at") or ""),
        }
    return sorted(spaces.values(), key=lambda item: (item.get("kind", ""), item.get("space", "")))


async def inspect_space(
    space: str,
    *,
    limit: int = 100,
    include_profile: bool = True,
    client: SupermemoryClient | None = None,
) -> dict[str, Any]:
    """List documents, type counts, and optional Supermemory profile for a space."""
    sm = client or SupermemoryClient()
    docs = await sm.list_documents(space, limit=limit)
    compact = [_compact_doc(doc) for doc in docs]
    counts: dict[str, int] = {}
    for doc in compact:
        doc_type = doc["type"] or "unknown"
        counts[doc_type] = counts.get(doc_type, 0) + 1
    profile = await sm.get_profile_text(space) if include_profile else ""
    return {
        "space": space,
        "document_count": len(compact),
        "type_counts": counts,
        "profile": profile,
        "documents": compact,
    }


async def search_with_trace(
    query: str,
    *,
    space: str,
    limit: int = 5,
    client: SupermemoryClient | None = None,
) -> dict[str, Any]:
    """Search graph first, chunk fallback second, returning the exact path used."""
    sm = client or SupermemoryClient()
    trace: list[dict[str, Any]] = []
    graph_records = await sm.search(query, container_tag=space, limit=limit)
    trace.append({"tier": "graph", "endpoint": "/v4/search", "hits": len(graph_records)})
    records = graph_records
    used_tier = "graph"
    if not graph_records:
        records = await sm.search_documents(query, container_tag=space, limit=limit)
        used_tier = "chunks"
        trace.append({"tier": "chunks", "endpoint": "/v3/search", "hits": len(records)})
    return {
        "query": query,
        "space": space,
        "used_tier": used_tier,
        "trace": trace,
        "results": [_compact_doc(record) for record in records],
    }


async def fleet_recall(
    device_model: str,
    *,
    related_models: list[str] | None = None,
    limit_per_device: int = 20,
    client: SupermemoryClient | None = None,
) -> dict[str, Any]:
    """Recall attack and policy memory for this device plus registered peers."""
    sm = client or SupermemoryClient()
    models = list(dict.fromkeys([device_model, *(related_models or [])]))
    if not related_models:
        try:
            for entry in await list_memory_spaces(client=sm):
                model = str(entry.get("device_model") or "")
                if model and model not in models:
                    models.append(model)
        except SupermemoryError:
            pass

    devices: list[dict[str, Any]] = []
    shared_harden_ports: dict[int, int] = {}
    shared_cves: set[str] = set()
    for model in models:
        try:
            from services.attack_memory import query_attack_history

            attack_history = await query_attack_history(model, client=sm, limit=limit_per_device)
        except Exception:  # noqa: BLE001
            attack_history = AttackHistorySummary(
                device_model=model,
                space=attack_container_tag(model),
                narrative="Attack recall unavailable",
            )
        try:
            incidents = await search_with_trace(
                f"prior enforcement policy outcome drift {model}",
                space=device_container_tag(model),
                limit=5,
                client=sm,
            )
        except SupermemoryError:
            incidents = {"results": [], "trace": []}
        for port in attack_history.harden_ports:
            shared_harden_ports[int(port)] = shared_harden_ports.get(int(port), 0) + 1
        shared_cves.update(attack_history.related_cves)
        devices.append(
            {
                "device_model": model,
                "device_space": device_container_tag(model),
                "attack_space": attack_history.space,
                "attack_history": attack_history.model_dump(),
                "policy_memory": incidents.get("results", []),
            }
        )

    return {
        "seed_device": device_model,
        "devices": devices,
        "shared_harden_ports": [
            {"port": port, "device_count": count}
            for port, count in sorted(shared_harden_ports.items(), key=lambda item: (-item[1], item[0]))
        ],
        "shared_cves": sorted(shared_cves),
        "narrative": (
            f"Fleet recall checked {len(devices)} device profile(s); "
            f"shared harden ports={sorted(shared_harden_ports)}; shared CVEs={sorted(shared_cves)}."
        ),
    }


async def record_policy_facts(
    *,
    contract_a: ContractA,
    contract_b: ContractB,
    cve_evidence: str = "",
    attack_history: AttackHistorySummary | None = None,
    client: SupermemoryClient | None = None,
) -> list[str]:
    """Persist a small contradiction ledger for the current policy decision."""
    sm = client or SupermemoryClient()
    space = device_container_tag(contract_a.device_model)
    await register_memory_space(space, kind="device", device_model=contract_a.device_model, client=sm)
    doc_ids: list[str] = []
    manual_ports = {p.port: p for p in contract_a.allowed_ports}
    policy = {rule.port: rule.action for rule in contract_b.firewall_rules}
    attacked = set(attack_history.harden_ports if attack_history else [])
    cve_ids = sorted(set(__import__("re").findall(r"CVE-\d{4}-\d{4,7}", cve_evidence or "")))

    facts: list[dict[str, Any]] = []
    for port, allowed in manual_ports.items():
        facts.append({
            "fact_type": "manual_requires_port",
            "device_model": contract_a.device_model,
            "firmware_version": contract_a.firmware_version,
            "port": port,
            "protocol": allowed.protocol,
            "reason": allowed.reason,
        })
    for port, action in policy.items():
        facts.append({
            "fact_type": "policy_decision",
            "device_model": contract_a.device_model,
            "port": port,
            "action": action,
            "cve_flagged": contract_b.cve_flagged,
        })
        if port in manual_ports and action == "DENY":
            reason = "attack_memory" if port in attacked else "cve_or_zero_trust"
            facts.append({
                "fact_type": "contradiction",
                "device_model": contract_a.device_model,
                "port": port,
                "manual": "requires",
                "policy": "denies",
                "reason": reason,
                "cves": cve_ids,
            })
    if attack_history:
        for probed in attack_history.probed_ports:
            facts.append({
                "fact_type": "attack_seen_on_port",
                "device_model": contract_a.device_model,
                "port": probed.get("port"),
                "count": probed.get("count"),
                "weighted_count": probed.get("weighted_count"),
                "related_cves": probed.get("related_cves", []),
                "last_seen": probed.get("last_seen", ""),
            })

    for fact in facts:
        content = json.dumps({"type": "memory-fact", **fact, "recorded_at": _now_iso()}, sort_keys=True)
        doc_id = await sm.add_document(
            content,
            container_tag=space,
            metadata={
                "type": "memory-fact",
                "fact_type": str(fact.get("fact_type") or ""),
                "device_model": contract_a.device_model,
                "port": int(fact.get("port") or 0),
                "description": f"{fact.get('fact_type')} port {fact.get('port')} for {contract_a.device_model}",
            },
        )
        doc_ids.append(doc_id)
    return doc_ids


async def record_policy_outcome(
    *,
    device_model: str,
    lease_id: str,
    outcome: str,
    notes: str = "",
    confidence_score: int | None = None,
    operator_id: str = "",
    client: SupermemoryClient | None = None,
) -> str:
    """Store operational feedback for a policy: useful, overridden, outage, etc."""
    sm = client or SupermemoryClient()
    space = device_container_tag(device_model)
    await register_memory_space(space, kind="device", device_model=device_model, client=sm)
    payload = {
        "type": "policy-outcome",
        "device_model": device_model,
        "lease_id": lease_id,
        "outcome": outcome,
        "notes": notes,
        "confidence_score": confidence_score,
        "operator_id": operator_id,
        "recorded_at": _now_iso(),
    }
    return await sm.add_document(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        container_tag=space,
        metadata={
            "type": "policy-outcome",
            "device_model": device_model,
            "lease_id": lease_id,
            "outcome": outcome,
            "description": f"Policy outcome {outcome} for {device_model}; lease {lease_id}",
            "recorded_at": payload["recorded_at"],
        },
    )


async def device_timeline(
    device_model: str,
    *,
    limit: int = 200,
    client: SupermemoryClient | None = None,
) -> dict[str, Any]:
    """Return a per-device memory timeline from manual through outcomes."""
    sm = client or SupermemoryClient()
    space = device_container_tag(device_model)
    docs = await sm.list_documents(space, limit=limit)
    events: list[dict[str, Any]] = []
    for doc in docs:
        metadata = _metadata(doc)
        doc_type = str(metadata.get("type") or "unknown")
        stamp = str(
            metadata.get("updated_at")
            or metadata.get("recorded_at")
            or metadata.get("observed_at")
            or metadata.get("createdAt")
            or ""
        )
        events.append({
            "timestamp": stamp,
            "type": doc_type,
            "id": _record_id(doc),
            "description": str(metadata.get("description") or metadata.get("fact_type") or doc_type),
            "metadata": metadata,
            "preview": _record_text(doc).replace("\n", " ")[:220],
        })
    events.sort(key=lambda item: item.get("timestamp") or "")
    return {"device_model": device_model, "space": space, "events": events, "count": len(events)}


async def export_device_snapshot(
    device_model: str,
    *,
    include_immunity: bool = False,
    client: SupermemoryClient | None = None,
) -> dict[str, Any]:
    """Export local memory metadata/docs for audit or demo replay."""
    sm = client or SupermemoryClient()
    spaces = [device_container_tag(device_model), attack_container_tag(device_model), CVE_CONTAINER_TAG]
    if include_immunity:
        spaces.append(IMMUNITY_CONTAINER_TAG)
    snapshot = {
        "snapshot_type": "theriac-local-memory",
        "device_model": device_model,
        "exported_at": _now_iso(),
        "spaces": {},
    }
    for space in spaces:
        try:
            snapshot["spaces"][space] = await inspect_space(
                space,
                limit=500,
                include_profile=False,
                client=sm,
            )
        except SupermemoryError as exc:
            snapshot["spaces"][space] = {"space": space, "error": str(exc)}
    snapshot["generated_at_unix"] = time.time()
    return snapshot
