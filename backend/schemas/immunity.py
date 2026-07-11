# Pydantic models for the Adaptive Host Immunity (AHI) module.
# Follows the same flat-model-per-concept pattern as contract_a.py / contract_b.py.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Input: a security alert arriving from an IDS/SIEM/orchestrator.
# ---------------------------------------------------------------------------
class SecurityAlert(BaseModel):
    """Incoming security alert to be evaluated by the immune system."""

    alert_id: str = Field(default="", description="External alert identifier (optional).")
    manufacturer: str = Field(default="", description="Device manufacturer, e.g. 'Philips'.")
    device_type: str = Field(default="", description="Device class, e.g. 'MRI', 'InfusionPump'.")
    firmware_version: str = Field(default="", description="Firmware revision, e.g. '2.1'.")
    protocol: str = Field(default="", description="Network protocol, e.g. 'SMB', 'TCP', 'UDP'.")
    destination_port: int | None = Field(default=None, ge=1, le=65535, description="Target port.")
    source_ip: str = Field(default="", description="Attacker source IP (for context, NOT fingerprinting).")
    mitre_technique: str = Field(default="", description="MITRE ATT&CK technique id, e.g. 'T1110'.")
    attack_category: str = Field(default="", description="High-level category, e.g. 'Credential Attack'.")
    severity: Literal["critical", "high", "medium", "low"] = Field(
        default="medium", description="Alert severity from the upstream detector."
    )
    vulnerability: str = Field(default="", description="CVE or vulnerability reference.")
    asset_role: str = Field(default="", description="Network role of the target asset, e.g. 'clinical'.")
    behavioral_sequence: str = Field(default="", description="Observed attack behaviour sequence.")
    raw_summary: str = Field(default="", description="Free-text summary from the detection source.")


# ---------------------------------------------------------------------------
# Immune fingerprint — stable identity for an attack pattern.
# ---------------------------------------------------------------------------
class ImmuneFingerprint(BaseModel):
    """A stable, IP-independent fingerprint that identifies an attack pattern."""

    fingerprint: str = Field(description="Slug-form fingerprint, e.g. 'philips_mri_fw2.1_smb445_t1110_credential_attack'.")
    components: list[str] = Field(default_factory=list, description="Ordered list of fields composited into the slug.")


# ---------------------------------------------------------------------------
# Memory record — what gets stored in / retrieved from Supermemory.
# ---------------------------------------------------------------------------
class ImmuneMemoryRecord(BaseModel):
    """One immune-memory record stored in Supermemory."""

    fingerprint: str
    attack_type: str = ""
    manufacturer: str = ""
    device_type: str = ""
    confidence: float = Field(default=50.0, ge=0, le=100)
    recommendation: str = ""
    action_taken: str = ""
    analyst_feedback: str = ""
    false_positive: bool = False
    incident_summary: str = ""
    timestamp: datetime = Field(default_factory=_utc_now)


# ---------------------------------------------------------------------------
# Analyst feedback — the human feedback loop input.
# ---------------------------------------------------------------------------
class AnalystFeedback(BaseModel):
    """Analyst judgment on a previous incident."""

    fingerprint: str = Field(description="The immune fingerprint of the incident being reviewed.")
    is_false_positive: bool = Field(description="True if the analyst confirms this was a false positive.")
    feedback_text: str = Field(default="", description="Free-form analyst notes.")
    action_taken: str = Field(default="", description="What the analyst ultimately did (e.g. 'ignored', 'blocked', 'escalated').")


# ---------------------------------------------------------------------------
# Output: the full immunity evaluation result.
# ---------------------------------------------------------------------------
class HistoricalMatch(BaseModel):
    """A single similar incident retrieved from memory."""

    fingerprint: str
    confidence: float
    action_taken: str = ""
    false_positive: bool = False
    incident_summary: str = ""
    timestamp: datetime | None = None


class ImmunityEvaluation(BaseModel):
    """Full response from the immunity evaluation endpoint."""

    fingerprint: ImmuneFingerprint
    similar_incidents: list[HistoricalMatch] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=100, description="Final adjusted confidence score.")
    recommendation: str = Field(description="Recommended response action.")
    reasoning: str = Field(description="Human-readable explanation of how the decision was reached.")
    is_known_pattern: bool = Field(default=False, description="True if similar incidents exist in memory.")
    false_positive_history: bool = Field(
        default=False, description="True if this pattern was previously flagged as a false positive."
    )
