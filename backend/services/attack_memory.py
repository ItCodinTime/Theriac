"""Attack-telemetry memory — observed probes/blocks live in Supermemory.

Each device gets an ``attacks:<slug>`` container. Ingested events become the
evidence behind ``check_attack_history``: repeated probes on a port harden the
next zero-trust policy (ALLOW → DENY) and show up in the incident memo.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from schemas.attack_event import AttackEvent, AttackHistorySummary
from schemas.contract_b import ContractB, FirewallRule
from services.supermemory import (
    SupermemoryClient,
    SupermemoryError,
    attack_container_tag,
)

# Minimum observed probes on a port before the next scan forces DENY.
_HARDEN_THRESHOLD = int(os.getenv("ATTACK_HARDEN_THRESHOLD", "1"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def ingest_attack_event(
    event: AttackEvent,
    *,
    client: SupermemoryClient | None = None,
) -> dict[str, Any]:
    """Write one attack/probe event into the device's attacks:* Supermemory space."""
    sm = client or SupermemoryClient()
    space = attack_container_tag(event.device_model)
    payload = event.model_dump(mode="json")
    content = json.dumps(payload, separators=(",", ":"), default=str)
    description = (
        f"{event.event_type} on {event.device_model} port {event.attempted_port}/{event.protocol}"
        + (f" from {event.source_ip}" if event.source_ip else "")
    )
    doc_id = await sm.add_document(
        content,
        container_tag=space,
        metadata={
            "type": "attack-event",
            "device_model": event.device_model,
            "attempted_port": event.attempted_port,
            "protocol": event.protocol,
            "severity": event.severity,
            "event_type": event.event_type,
            "source_ip": event.source_ip or "",
            "description": description,
            "observed_at": event.observed_at.isoformat() if event.observed_at else _now_iso(),
        },
    )
    return {"status": "stored", "space": space, "doc_id": doc_id, "description": description}


async def query_attack_history(
    device_model: str,
    *,
    client: SupermemoryClient | None = None,
    limit: int = 50,
) -> AttackHistorySummary:
    """Recall attack telemetry for a device and derive ports to harden."""
    sm = client or SupermemoryClient()
    space = attack_container_tag(device_model)
    events: list[dict[str, Any]] = []
    doc_ids: list[str] = []

    try:
        records = await sm.search(
            f"attack probe blocked connection lateral movement against {device_model}",
            container_tag=space,
            limit=limit,
        )
        if not records:
            records = await sm.search_documents(
                f"attack probe port {device_model}",
                container_tag=space,
                limit=limit,
            )
        for record in records:
            parsed = _parse_event_record(record)
            if parsed:
                events.append(parsed)
            doc_id = _record_id(record)
            if doc_id:
                doc_ids.append(doc_id)
    except SupermemoryError:
        records = []

    # Deterministic metadata scan — same pattern as immunity FP recall.
    try:
        documents = await sm.list_documents(space, limit=max(limit, 50))
    except (SupermemoryError, Exception):  # noqa: BLE001
        documents = []

    for doc in documents:
        metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        if metadata.get("type") not in ("attack-event", None) and "attempted_port" not in metadata:
            # Skip unrelated docs; still accept attack-event or port-tagged rows.
            if metadata.get("type") and metadata.get("type") != "attack-event":
                continue
        parsed = _parse_event_record(doc)
        if not parsed and "attempted_port" in metadata:
            try:
                parsed = {
                    "device_model": str(metadata.get("device_model") or device_model),
                    "attempted_port": int(metadata["attempted_port"]),
                    "protocol": str(metadata.get("protocol") or "TCP"),
                    "severity": str(metadata.get("severity") or "high"),
                    "event_type": str(metadata.get("event_type") or "unauthorized_lateral_probe"),
                    "observed_at": str(metadata.get("observed_at") or ""),
                    "source_ip": str(metadata.get("source_ip") or ""),
                    "reason": str(metadata.get("description") or ""),
                }
            except (TypeError, ValueError):
                parsed = None
        if parsed:
            # Deduplicate by port+observed_at+source
            key = (
                parsed.get("attempted_port"),
                parsed.get("observed_at"),
                parsed.get("source_ip"),
            )
            if not any(
                (e.get("attempted_port"), e.get("observed_at"), e.get("source_ip")) == key
                for e in events
            ):
                events.append(parsed)
        doc_id = _record_id(doc)
        if doc_id and doc_id not in doc_ids:
            doc_ids.append(doc_id)

    port_stats: dict[int, dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "protocols": set(), "severities": set(), "last_seen": ""}
    )
    for event in events:
        port = int(event.get("attempted_port") or 0)
        if port < 1:
            continue
        stats = port_stats[port]
        stats["count"] += 1
        if event.get("protocol"):
            stats["protocols"].add(str(event["protocol"]).upper())
        if event.get("severity"):
            stats["severities"].add(str(event["severity"]).lower())
        seen = str(event.get("observed_at") or "")
        if seen >= str(stats["last_seen"]):
            stats["last_seen"] = seen

    probed_ports = [
        {
            "port": port,
            "count": data["count"],
            "last_seen": data["last_seen"],
            "protocols": sorted(data["protocols"]),
            "severities": sorted(data["severities"]),
        }
        for port, data in sorted(port_stats.items(), key=lambda item: (-item[1]["count"], item[0]))
    ]
    harden_ports = [p["port"] for p in probed_ports if p["count"] >= _HARDEN_THRESHOLD]

    if not probed_ports:
        narrative = (
            f"No prior attack telemetry in Supermemory space {space} for {device_model}."
        )
    else:
        bits = [
            f"port {p['port']} probed {p['count']}×"
            + (f" (last {p['last_seen']})" if p["last_seen"] else "")
            for p in probed_ports[:8]
        ]
        narrative = (
            f"Attack memory for {device_model} ({space}): {'; '.join(bits)}. "
            f"Harden (force DENY) ports: {harden_ports or 'none'}."
        )

    return AttackHistorySummary(
        device_model=device_model,
        space=space,
        total_events=len(events),
        probed_ports=probed_ports,
        harden_ports=harden_ports,
        narrative=narrative,
        memory_doc_ids=doc_ids[:20],
    )


def _parse_event_record(record: dict[str, Any]) -> dict[str, Any] | None:
    from services.supermemory import _record_text

    text = _record_text(record).strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if "attempted_port" not in data:
        return None
    return data


def _record_id(record: dict[str, Any]) -> str:
    for key in ("id", "documentId", "document_id"):
        value = record.get(key)
        if value is not None:
            return str(value)
    return ""


def harden_policy_from_attacks(
    contract_b: ContractB,
    history: AttackHistorySummary,
) -> tuple[ContractB, list[str]]:
    """Force DENY on ports with enough attack telemetry; return (policy, change notes).

    Attack memory beats a weak manual ALLOW: if a port was probed, the next scan
    denies it and records a citation note for the memo.
    """
    harden = {int(p) for p in history.harden_ports}
    if not harden:
        return contract_b, []

    notes: list[str] = []
    by_port = {rule.port: rule for rule in contract_b.firewall_rules}
    new_rules: list[FirewallRule] = []

    for rule in contract_b.firewall_rules:
        if rule.port in harden and rule.action == "ALLOW":
            new_rules.append(FirewallRule(port=rule.port, action="DENY"))
            count = next((p["count"] for p in history.probed_ports if p["port"] == rule.port), 1)
            notes.append(
                f"Port {rule.port} flipped ALLOW→DENY — attack memory ({count} probe(s) in {history.space})"
            )
        else:
            new_rules.append(rule)

    for port in sorted(harden):
        if port not in by_port:
            new_rules.append(FirewallRule(port=port, action="DENY"))
            count = next((p["count"] for p in history.probed_ports if p["port"] == port), 1)
            notes.append(
                f"Port {port} added as DENY — attack memory ({count} probe(s) in {history.space})"
            )

    return contract_b.model_copy(update={"firewall_rules": new_rules}), notes
