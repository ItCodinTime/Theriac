"""Attack-telemetry memory — observed probes/blocks live in Supermemory.

Each device gets an ``attacks:<slug>`` container. Ingested events become the
evidence behind ``check_attack_history``: repeated probes on a port harden the
next zero-trust policy (ALLOW → DENY). CVE correlation writes device → CVE →
port edges so exploit attempts on a CVE-linked port harden more aggressively.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from schemas.attack_event import AttackCorrelation, AttackEvent, AttackHistorySummary
from schemas.contract_b import ContractB, FirewallRule
from services.cve_attack_graph import correlate_cves_for_port, primary_cve_for_port
from services.supermemory import (
    SupermemoryClient,
    SupermemoryError,
    attack_container_tag,
)

# Minimum observed probes on a port before the next scan forces DENY.
_HARDEN_THRESHOLD = int(os.getenv("ATTACK_HARDEN_THRESHOLD", "1"))
# CVE-correlated probes harden even at this lower count (default: same as base).
_CVE_HARDEN_THRESHOLD = int(os.getenv("ATTACK_CVE_HARDEN_THRESHOLD", "1"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def ingest_attack_event(
    event: AttackEvent,
    *,
    client: SupermemoryClient | None = None,
    run_immunity: bool = False,
) -> dict[str, Any]:
    """Write one attack/probe event into the device's attacks:* Supermemory space.

    Auto-correlates a related CVE (device → CVE → port) when not provided, and
    stores a graph-link document so recall can surface the edge explicitly.
    """
    sm = client or SupermemoryClient()
    space = attack_container_tag(event.device_model)

    related_cve = (event.related_cve or "").strip()
    if not related_cve:
        related_cve = primary_cve_for_port(
            event.device_model,
            event.attempted_port,
            firmware_version=event.firmware_version,
        )
        if related_cve:
            event = event.model_copy(update={"related_cve": related_cve})

    payload = event.model_dump(mode="json")
    content = json.dumps(payload, separators=(",", ":"), default=str)
    description = (
        f"{event.event_type} on {event.device_model} port {event.attempted_port}/{event.protocol}"
        + (f" from {event.source_ip}" if event.source_ip else "")
        + (f" · {related_cve}" if related_cve else "")
    )
    metadata = {
        "type": "attack-event",
        "device_model": event.device_model,
        "attempted_port": event.attempted_port,
        "protocol": event.protocol,
        "severity": event.severity,
        "event_type": event.event_type,
        "source_ip": event.source_ip or "",
        "related_cve": related_cve,
        "observation_source": event.observation_source or "",
        "description": description,
        "observed_at": event.observed_at.isoformat() if event.observed_at else _now_iso(),
    }
    doc_id = await sm.add_document(content, container_tag=space, metadata=metadata)

    link_id = ""
    if related_cve:
        link_id = await _store_correlation_edge(
            sm,
            space=space,
            device_model=event.device_model,
            port=event.attempted_port,
            cve_id=related_cve,
            event_doc_id=doc_id,
            source_ip=event.source_ip,
        )

    immunity: dict[str, Any] | None = None
    if run_immunity:
        immunity = await _bridge_immunity(event)

    return {
        "status": "stored",
        "space": space,
        "doc_id": doc_id,
        "related_cve": related_cve or None,
        "correlation_doc_id": link_id or None,
        "description": description,
        "immunity": immunity,
    }


async def _store_correlation_edge(
    sm: SupermemoryClient,
    *,
    space: str,
    device_model: str,
    port: int,
    cve_id: str,
    event_doc_id: str,
    source_ip: str,
) -> str:
    """Persist an explicit device → CVE → port memory edge for graph recall."""
    edge = {
        "type": "attack-cve-link",
        "device_model": device_model,
        "port": port,
        "cve_id": cve_id,
        "event_doc_id": event_doc_id,
        "source_ip": source_ip,
        "observed_at": _now_iso(),
        "edge": f"{device_model} --probed:{port}--> {cve_id}",
    }
    return await sm.add_document(
        json.dumps(edge, separators=(",", ":")),
        container_tag=space,
        metadata={
            "type": "attack-cve-link",
            "device_model": device_model,
            "attempted_port": port,
            "related_cve": cve_id,
            "description": edge["edge"],
        },
    )


async def _bridge_immunity(event: AttackEvent) -> dict[str, Any] | None:
    """Best-effort AHI evaluate so attack memory and immune memory stay in sync."""
    try:
        from schemas.immunity import SecurityAlert
        from services.immunity import evaluate_alert

        alert = SecurityAlert(
            alert_id=f"atk-{event.attempted_port}-{int(datetime.now(timezone.utc).timestamp())}",
            manufacturer=event.device_model.split("_")[0] if "_" in event.device_model else event.device_model,
            device_type=event.device_model,
            firmware_version=event.firmware_version or "",
            protocol=event.protocol,
            destination_port=event.attempted_port,
            source_ip=event.source_ip or "",
            attack_category=event.event_type,
            severity=event.severity,
            vulnerability=event.related_cve or "",
            raw_summary=event.raw_summary or event.reason,
        )
        evaluation = await evaluate_alert(alert)
        return {
            "fingerprint": evaluation.fingerprint.fingerprint,
            "confidence": evaluation.confidence,
            "recommendation": evaluation.recommendation[:240],
            "false_positive_history": evaluation.false_positive_history,
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "skipped", "error": str(exc)[:200]}


async def query_attack_history(
    device_model: str,
    *,
    client: SupermemoryClient | None = None,
    limit: int = 50,
) -> AttackHistorySummary:
    """Recall attack telemetry for a device and derive ports/CVEs to harden."""
    sm = client or SupermemoryClient()
    space = attack_container_tag(device_model)
    events: list[dict[str, Any]] = []
    doc_ids: list[str] = []

    try:
        records = await sm.search(
            f"attack probe blocked connection CVE exploit against {device_model}",
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
            if parsed and parsed.get("type") != "attack-cve-link":
                events.append(parsed)
            doc_id = _record_id(record)
            if doc_id:
                doc_ids.append(doc_id)
    except SupermemoryError:
        pass

    try:
        documents = await sm.list_documents(space, limit=max(limit, 50))
    except (SupermemoryError, Exception):  # noqa: BLE001
        documents = []

    for doc in documents:
        metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        doc_type = str(metadata.get("type") or "")
        if doc_type == "attack-cve-link":
            doc_id = _record_id(doc)
            if doc_id and doc_id not in doc_ids:
                doc_ids.append(doc_id)
            continue
        if doc_type and doc_type != "attack-event" and "attempted_port" not in metadata:
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
                    "related_cve": str(metadata.get("related_cve") or ""),
                }
            except (TypeError, ValueError):
                parsed = None
        if parsed:
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
        lambda: {
            "count": 0,
            "protocols": set(),
            "severities": set(),
            "last_seen": "",
            "related_cves": set(),
        }
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
        cve = str(event.get("related_cve") or "").strip()
        if not cve:
            cve = primary_cve_for_port(
                device_model, port, firmware_version=str(event.get("firmware_version") or "")
            )
        if cve:
            stats["related_cves"].add(cve)
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
            "related_cves": sorted(data["related_cves"]),
        }
        for port, data in sorted(port_stats.items(), key=lambda item: (-item[1]["count"], item[0]))
    ]

    harden_ports: list[int] = []
    for p in probed_ports:
        threshold = _CVE_HARDEN_THRESHOLD if p["related_cves"] else _HARDEN_THRESHOLD
        if p["count"] >= threshold:
            harden_ports.append(p["port"])

    correlations: list[AttackCorrelation] = []
    related_cves: list[str] = []
    for p in probed_ports:
        for cve_id in p["related_cves"]:
            if cve_id not in related_cves:
                related_cves.append(cve_id)
            hits = correlate_cves_for_port(device_model, p["port"])
            rationale = next(
                (h["rationale"] for h in hits if h["cve_id"] == cve_id),
                f"{cve_id} linked to probes on port {p['port']}",
            )
            correlations.append(
                AttackCorrelation(
                    device_model=device_model,
                    port=p["port"],
                    cve_id=cve_id,
                    probe_count=p["count"],
                    severity=next((h.get("severity", "") for h in hits if h["cve_id"] == cve_id), ""),
                    rationale=rationale,
                )
            )

    if not probed_ports:
        narrative = f"No prior attack telemetry in Supermemory space {space} for {device_model}."
    else:
        bits = [
            f"port {p['port']} probed {p['count']}×"
            + (f" → {','.join(p['related_cves'])}" if p["related_cves"] else "")
            for p in probed_ports[:8]
        ]
        narrative = (
            f"Attack memory for {device_model} ({space}): {'; '.join(bits)}. "
            f"Harden (force DENY) ports: {harden_ports or 'none'}. "
            f"CVE graph: {related_cves or 'none'}."
        )

    return AttackHistorySummary(
        device_model=device_model,
        space=space,
        total_events=len(events),
        probed_ports=probed_ports,
        harden_ports=harden_ports,
        related_cves=related_cves,
        correlations=correlations,
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
    if data.get("type") == "attack-cve-link":
        return data
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

    Attack memory beats a weak manual ALLOW. CVE-correlated probes get an extra
    citation note so the memo shows the device → CVE → exploit edge.
    """
    harden = {int(p) for p in history.harden_ports}
    if not harden:
        return contract_b, []

    cve_by_port: dict[int, list[str]] = {}
    for corr in history.correlations:
        cve_by_port.setdefault(corr.port, []).append(corr.cve_id)

    notes: list[str] = []
    by_port = {rule.port: rule for rule in contract_b.firewall_rules}
    new_rules: list[FirewallRule] = []

    for rule in contract_b.firewall_rules:
        if rule.port in harden and rule.action == "ALLOW":
            new_rules.append(FirewallRule(port=rule.port, action="DENY"))
            count = next((p["count"] for p in history.probed_ports if p["port"] == rule.port), 1)
            cves = cve_by_port.get(rule.port) or []
            cve_note = f" · CVE graph {','.join(cves)}" if cves else ""
            notes.append(
                f"Port {rule.port} flipped ALLOW→DENY — attack memory "
                f"({count} probe(s) in {history.space}){cve_note}"
            )
        else:
            new_rules.append(rule)

    for port in sorted(harden):
        if port not in by_port:
            new_rules.append(FirewallRule(port=port, action="DENY"))
            count = next((p["count"] for p in history.probed_ports if p["port"] == port), 1)
            cves = cve_by_port.get(port) or []
            cve_note = f" · CVE graph {','.join(cves)}" if cves else ""
            notes.append(
                f"Port {port} added as DENY — attack memory "
                f"({count} probe(s) in {history.space}){cve_note}"
            )

    updates: dict[str, Any] = {"firewall_rules": new_rules}
    # Ground cve_flagged from the attack↔CVE graph when the agent left it empty.
    if history.related_cves and (
        not contract_b.cve_flagged or contract_b.cve_flagged.strip().upper() == "NONE"
    ):
        updates["cve_flagged"] = history.related_cves[0]

    return contract_b.model_copy(update=updates), notes
