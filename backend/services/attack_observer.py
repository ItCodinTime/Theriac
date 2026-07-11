"""Continuous / one-shot attack observation — probes + log parsing → attack memory.

Sources:
  * Active TCP probes against the target (attacker-VM style)
  * HL7 listener log lines (``Connection from ('ip', port)``)
  * Optional firewall rule poll (Vultr group) for attacker-source allow presence
"""

from __future__ import annotations

import os
import re
import socket
from datetime import datetime, timezone
from typing import Any

from schemas.attack_event import AttackEvent, ObserveRequest
from services.attack_memory import ingest_attack_event

_HL7_CONN_RE = re.compile(
    r"Connection from\s+\('?(?P<ip>[0-9.]+)'?,\s*(?P<src_port>\d+)\)",
    re.IGNORECASE,
)


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    if not host:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def parse_hl7_log_line(
    line: str,
    *,
    device_model: str = "Philips_IntelliVue",
    firmware_version: str = "L.0",
    hl7_port: int = 3200,
) -> AttackEvent | None:
    """Parse an HL7 listener stdout/journal line into an AttackEvent."""
    match = _HL7_CONN_RE.search(line)
    if not match:
        return None
    ip = match.group("ip")
    attacker = _env("VULTR_ATTACKER_PUBLIC_IP")
    event_type = "hl7_connection"
    severity: str = "medium"
    reason = f"HL7 listener accepted TCP connection on port {hl7_port} from {ip}"
    if attacker and ip == attacker.split("/")[0]:
        event_type = "unauthorized_lateral_probe"
        severity = "high"
        reason = (
            f"Attacker VM {ip} connected to HL7 port {hl7_port} on clinical device "
            f"{device_model}"
        )
    return AttackEvent(
        device_model=device_model,
        attempted_port=hl7_port,
        protocol="TCP",
        source_ip=ip,
        event_type=event_type,
        severity=severity,  # type: ignore[arg-type]
        firmware_version=firmware_version,
        reason=reason,
        raw_summary=line.strip(),
        observation_source="hl7_listener",
        reachable=True,
    )


async def observe_once(request: ObserveRequest | None = None) -> dict[str, Any]:
    """Probe configured target ports and ingest each attempt into attack memory."""
    req = request or ObserveRequest()
    target = _env("VULTR_TARGET_PUBLIC_IP")
    attacker = _env("VULTR_ATTACKER_PUBLIC_IP")
    ingested: list[dict[str, Any]] = []
    probes: list[dict[str, Any]] = []

    for port in req.ports:
        reachable = _tcp_reachable(target, port) if target else None
        if reachable is True:
            event_type = "unauthorized_lateral_probe"
            reason = (
                f"Active probe from observer reached {target}:{port} "
                f"(device {req.device_model} still exposed)"
            )
            severity = "high"
        elif reachable is False:
            event_type = "blocked_connection"
            reason = (
                f"Active probe to {target}:{port} timed out / refused — "
                f"likely blocked by cloud firewall (good)"
            )
            severity = "medium"
        else:
            event_type = "ids_alert"
            reason = f"Observer recorded intent to probe port {port} (no target IP configured)"
            severity = "medium"

        event = AttackEvent(
            device_model=req.device_model,
            attempted_port=port,
            protocol=req.protocol,
            source_ip=attacker,
            event_type=event_type,
            severity=severity,  # type: ignore[arg-type]
            firmware_version=req.firmware_version,
            reason=reason,
            raw_summary=(
                f"observe_once target={target or 'unset'} port={port} "
                f"reachable={reachable} at {datetime.now(timezone.utc).isoformat()}"
            ),
            observation_source="attack_observer",
            reachable=reachable,
        )
        # Always ingest probes that got through; also ingest blocked probes so
        # memory learns the attack *attempt* (immune system saw the pathogen).
        stored = await ingest_attack_event(event, run_immunity=req.run_immunity)
        probes.append(
            {
                "port": port,
                "reachable": reachable,
                "event_type": event_type,
                "related_cve": stored.get("related_cve"),
            }
        )
        ingested.append(stored)

    fw_snapshot = _poll_firewall_attacker_rules()
    return {
        "status": "ok",
        "target_ip": target or None,
        "attacker_ip": attacker or None,
        "probes": probes,
        "ingested": ingested,
        "firewall_snapshot": fw_snapshot,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }


def _poll_firewall_attacker_rules() -> dict[str, Any]:
    """Best-effort snapshot of attacker-source rules on the Vultr firewall group."""
    try:
        from services import vultr_firewall as vf

        group_id = vf._firewall_group_id()  # noqa: SLF001
        if not group_id:
            return {"status": "skipped", "reason": "VULTR_FIREWALL_GROUP_ID unset"}
        listing = vf.list_current_rules(group_id)
        return listing
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)[:200]}


async def ingest_hl7_log_lines(
    lines: list[str],
    *,
    device_model: str = "Philips_IntelliVue",
    firmware_version: str = "L.0",
    run_immunity: bool = False,
) -> list[dict[str, Any]]:
    """Parse and ingest a batch of HL7 listener log lines."""
    results: list[dict[str, Any]] = []
    for line in lines:
        event = parse_hl7_log_line(line, device_model=device_model, firmware_version=firmware_version)
        if event is None:
            continue
        results.append(await ingest_attack_event(event, run_immunity=run_immunity))
    return results
