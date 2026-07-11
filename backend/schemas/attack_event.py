# Attack telemetry event — observed probes / blocked connections fed into Supermemory.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AttackEvent(BaseModel):
    """One observed attack / probe / blocked-connection event against a device."""

    device_model: str = Field(min_length=1, description="Device under attack, e.g. Philips_IntelliVue")
    attempted_port: int = Field(ge=1, le=65535, description="Port that was probed or blocked")
    protocol: Literal["TCP", "UDP"] = "TCP"
    source_ip: str = Field(default="", description="Attacker source IP if known")
    event_type: str = Field(
        default="unauthorized_lateral_probe",
        description="Event class, e.g. unauthorized_lateral_probe, blocked_connection, ids_alert, hl7_connection",
    )
    severity: Literal["critical", "high", "medium", "low"] = "high"
    firmware_version: str = Field(default="", description="Firmware if known at observation time")
    reason: str = Field(default="", description="Short human-readable why this is an attack signal")
    observed_at: datetime = Field(default_factory=_utc_now)
    raw_summary: str = Field(default="", description="Optional free-text from IDS / firewall / HL7 logs")
    related_cve: str = Field(
        default="",
        description="Correlated CVE id when device→CVE→port graph match is known",
    )
    observation_source: str = Field(
        default="",
        description="Emitter: attack_simulator | hl7_listener | firewall_poll | ids | manual",
    )
    reachable: bool | None = Field(
        default=None,
        description="True if TCP connect succeeded (probe got through); False if blocked/timeout",
    )


class AttackCorrelation(BaseModel):
    """One device → CVE → observed exploit-attempt edge."""

    device_model: str
    port: int
    cve_id: str
    probe_count: int = 0
    severity: str = ""
    rationale: str = ""


class AttackHistorySummary(BaseModel):
    """Structured attack-history recall returned to the agent tool / API."""

    device_model: str
    space: str
    total_events: int = 0
    probed_ports: list[dict] = Field(
        default_factory=list,
        description="[{port, count, last_seen, protocols, severities, related_cves}]",
    )
    harden_ports: list[int] = Field(
        default_factory=list,
        description="Ports that should be DENY'd more aggressively on the next policy",
    )
    related_cves: list[str] = Field(
        default_factory=list,
        description="CVE ids correlated to observed attack ports for this device",
    )
    correlations: list[AttackCorrelation] = Field(default_factory=list)
    narrative: str = ""
    memory_doc_ids: list[str] = Field(default_factory=list)


class ObserveRequest(BaseModel):
    """One-shot observation cycle: probe target ports and ingest results."""

    device_model: str = "Philips_IntelliVue"
    firmware_version: str = "L.0"
    ports: list[int] = Field(default_factory=lambda: [22, 3200, 24005])
    protocol: Literal["TCP", "UDP"] = "TCP"
    run_immunity: bool = True
