"""Adaptive Host Immunity (AHI) service — the decision-making brain.

This service implements the biological-immune-system analogy: incoming security
alerts are fingerprinted into stable, IP-independent attack patterns, then
compared against Supermemory for historical matches. The system learns over time
because every evaluation result and every analyst judgment is stored back into
memory, influencing future confidence scores and recommendations.

Separation of concerns:
    • ``SupermemoryClient`` (services/supermemory.py) — raw memory I/O.
    • This module — all security reasoning, fingerprinting, and scoring logic.
"""

from __future__ import annotations

import json
import logging
import re

from schemas.immunity import (
    AnalystFeedback,
    HistoricalMatch,
    ImmuneFingerprint,
    ImmuneMemoryRecord,
    ImmunityEvaluation,
    SecurityAlert,
)
from services.audit_log import append_audit_entry
from services.supermemory import SupermemoryClient, SupermemoryError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — read from config when the module is used at runtime; the
# hardcoded default matches config.py so tests work without env vars.
# ---------------------------------------------------------------------------
IMMUNITY_CONTAINER_TAG = "immunity-memory"

_SEVERITY_BASE_SCORES: dict[str, float] = {
    "critical": 85.0,
    "high": 70.0,
    "medium": 50.0,
    "low": 30.0,
}

# Boost / penalty caps
_CONFIRMED_BOOST_PER_MATCH = 10.0
_CONFIRMED_BOOST_CAP = 30.0
_RECURRENCE_BOOST_PER_MATCH = 5.0
_RECURRENCE_BOOST_CAP = 15.0
_FALSE_POSITIVE_PENALTY_PER_MATCH = 15.0
_FALSE_POSITIVE_PENALTY_CAP = 30.0


def _get_container_tag() -> str:
    """Resolve the container tag, preferring the config value at runtime."""
    try:
        from config import IMMUNITY_CONTAINER_TAG as configured_tag
        return configured_tag
    except Exception:  # noqa: BLE001 — config may not load in test env
        return IMMUNITY_CONTAINER_TAG


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------
def _normalize(value: str) -> str:
    """Lowercase, strip, collapse non-alphanumerics into underscores."""
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def generate_fingerprint(alert: SecurityAlert) -> ImmuneFingerprint:
    """Create a stable, IP-independent fingerprint from a security alert.

    The fingerprint composites security-relevant context fields so the same
    attack pattern against the same device class always produces the same slug,
    regardless of source IP changes.

    Fields included: manufacturer, device_type, firmware_version, protocol+port,
    mitre_technique, attack_category, vulnerability, behavioral_sequence,
    asset_role.
    """
    raw_components: list[tuple[str, str]] = [
        ("manufacturer", alert.manufacturer),
        ("device_type", alert.device_type),
        ("firmware_version", f"fw{alert.firmware_version}" if alert.firmware_version else ""),
        (
            "protocol_port",
            f"{alert.protocol}{alert.destination_port}" if alert.protocol and alert.destination_port else alert.protocol,
        ),
        ("mitre_technique", alert.mitre_technique),
        ("attack_category", alert.attack_category),
        ("vulnerability", alert.vulnerability),
        ("behavioral_sequence", alert.behavioral_sequence),
        ("asset_role", alert.asset_role),
    ]

    components: list[str] = []
    slug_parts: list[str] = []
    for _label, value in raw_components:
        if not value:
            continue
        normalized = _normalize(value)
        if normalized:
            components.append(value)
            slug_parts.append(normalized)

    fingerprint = "_".join(slug_parts) if slug_parts else "unknown"
    return ImmuneFingerprint(fingerprint=fingerprint, components=components)


# ---------------------------------------------------------------------------
# Memory search helpers
# ---------------------------------------------------------------------------
def _extract_text_from_record(record: dict) -> str:
    """Extract text content from a Supermemory search result record.

    Handles the multiple response shapes the Supermemory API may return,
    matching the defensive extraction pattern in supermemory.py._record_text.
    """
    for key in ("content", "text", "chunk", "memory", "summary"):
        candidate = record.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    # Fall back to nested chunks (returned by /v3/search).
    chunks = record.get("chunks")
    if isinstance(chunks, list):
        for chunk in chunks:
            if isinstance(chunk, dict):
                text = chunk.get("content", "").strip()
                if text:
                    return text
    # Fall back to nested document object.
    nested = record.get("document")
    if isinstance(nested, dict):
        return _extract_text_from_record(nested)
    return ""


async def _search_similar(
    fingerprint: str,
    *,
    client: SupermemoryClient | None = None,
    limit: int = 10,
) -> list[ImmuneMemoryRecord]:
    """Query Supermemory for historical incidents matching this fingerprint.

    Tries the graph-aware /v4/search first, then falls back to chunk-level
    /v3/search when the graph has no matching memories yet — matching the
    resilient retrieval pattern used by the existing memory facade.
    """
    sm = client or SupermemoryClient()
    tag = _get_container_tag()

    # Primary: graph-aware search (/v4/search)
    records = await sm.search(fingerprint, container_tag=tag, limit=limit)

    # Fallback: chunk-level search (/v3/search) when graph is empty.
    if not records:
        records = await sm.search_documents(fingerprint, container_tag=tag, limit=limit)

    results: list[ImmuneMemoryRecord] = []
    for record in records:
        text = _extract_text_from_record(record)
        if not text:
            continue

        try:
            data = json.loads(text)
            results.append(ImmuneMemoryRecord(**data))
        except (json.JSONDecodeError, TypeError, ValueError):
            # Unstructured memory — wrap it as a minimal record.
            results.append(ImmuneMemoryRecord(
                fingerprint=fingerprint,
                incident_summary=text[:500],
            ))

    return results


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------
def compute_confidence(
    base_severity: str,
    similar_records: list[ImmuneMemoryRecord],
) -> tuple[float, str]:
    """Compute the adjusted confidence score from severity and historical memory.

    Returns (final_score, reasoning_explanation).

    Formula:
        base(severity)
        + confirmed_boost   (capped at 30)
        + recurrence_boost  (capped at 15)
        - fp_penalty        (capped at 30)
        = clamped to [0, 100]
    """
    base = _SEVERITY_BASE_SCORES.get(base_severity, 50.0)
    reasoning_parts: list[str] = [f"Base score {base:.0f} (severity={base_severity})"]

    # Confirmed true-positive boost
    confirmed = [r for r in similar_records if not r.false_positive and r.action_taken]
    confirmed_boost = min(len(confirmed) * _CONFIRMED_BOOST_PER_MATCH, _CONFIRMED_BOOST_CAP)
    if confirmed_boost > 0:
        reasoning_parts.append(
            f"+{confirmed_boost:.0f} from {len(confirmed)} previously confirmed incident(s)"
        )

    # Recurrence boost (any match, regardless of confirmation status)
    recurrence_boost = min(len(similar_records) * _RECURRENCE_BOOST_PER_MATCH, _RECURRENCE_BOOST_CAP)
    if recurrence_boost > 0:
        reasoning_parts.append(
            f"+{recurrence_boost:.0f} recurrence boost ({len(similar_records)} historical match(es))"
        )

    # False-positive penalty
    false_positives = [r for r in similar_records if r.false_positive]
    fp_penalty = min(len(false_positives) * _FALSE_POSITIVE_PENALTY_PER_MATCH, _FALSE_POSITIVE_PENALTY_CAP)
    if fp_penalty > 0:
        reasoning_parts.append(
            f"-{fp_penalty:.0f} from {len(false_positives)} previous false-positive(s)"
        )

    raw = base + confirmed_boost + recurrence_boost - fp_penalty
    final = max(0.0, min(100.0, raw))
    reasoning_parts.append(f"= Final confidence {final:.0f}")

    return final, "; ".join(reasoning_parts)


# ---------------------------------------------------------------------------
# Recommendation generation
# ---------------------------------------------------------------------------
def generate_recommendation(
    alert: SecurityAlert,
    confidence: float,
    similar_records: list[ImmuneMemoryRecord],
) -> str:
    """Produce a human-readable recommended action based on confidence and history."""
    false_positives = [r for r in similar_records if r.false_positive]
    confirmed = [r for r in similar_records if not r.false_positive and r.action_taken]

    # If every historical match was a false positive, recommend monitoring only.
    if false_positives and not confirmed:
        return (
            "MONITOR — This attack pattern was previously confirmed as a false positive "
            f"({len(false_positives)} time(s)). Recommend monitoring only; do not auto-block."
        )

    # High confidence with confirmed precedent → immediate mitigation.
    if confidence >= 80 and confirmed:
        past_actions = ", ".join(dict.fromkeys(r.action_taken for r in confirmed if r.action_taken))
        fp_note = ""
        if false_positives:
            fp_note = (
                f" Note: {len(false_positives)} past false-positive(s) also on record; "
                "review before permanent policy."
            )
        return (
            f"BLOCK IMMEDIATELY — High confidence ({confidence:.0f}%) with "
            f"{len(confirmed)} confirmed precedent(s). "
            f"Previous action(s): {past_actions or 'recorded'}. "
            f"Apply firewall rule and escalate to SOC.{fp_note}"
        )

    # High confidence but no precedent.
    if confidence >= 80:
        return (
            f"BLOCK — High confidence ({confidence:.0f}%) novel attack. "
            "Apply firewall rule and alert the security team."
        )

    # Medium confidence.
    if confidence >= 50:
        fp_note = ""
        if false_positives:
            fp_note = (
                f" Caution: {len(false_positives)} past false-positive(s) match this pattern."
            )
        return (
            f"INVESTIGATE — Moderate confidence ({confidence:.0f}%). "
            f"Flag for analyst review before taking automated action.{fp_note}"
        )

    # Low confidence.
    return (
        f"LOG — Low confidence ({confidence:.0f}%). "
        "Record the incident for trend analysis; no automated action recommended."
    )


# ---------------------------------------------------------------------------
# Memory storage
# ---------------------------------------------------------------------------
async def _store_memory(
    record: ImmuneMemoryRecord,
    *,
    client: SupermemoryClient | None = None,
    record_type: str = "immune-memory",
) -> str:
    """Persist an immune memory record into Supermemory."""
    sm = client or SupermemoryClient()
    content = record.model_dump_json()
    doc_id = await sm.add_document(
        content,
        container_tag=_get_container_tag(),
        metadata={
            "type": record_type,
            "fingerprint": record.fingerprint,
            "attack_type": record.attack_type,
            "false_positive": str(record.false_positive).lower(),
        },
    )
    return doc_id


# ---------------------------------------------------------------------------
# Public API — evaluate an incoming alert
# ---------------------------------------------------------------------------
async def evaluate_alert(
    alert: SecurityAlert,
    *,
    client: SupermemoryClient | None = None,
) -> ImmunityEvaluation:
    """Full AHI evaluation pipeline for an incoming security alert.

    Steps:
        1. Generate immune fingerprint
        2. Search Supermemory for similar incidents
        3. Compute adjusted confidence
        4. Generate recommendation
        5. Store new immune memory record
        6. Return complete evaluation

    Degrades gracefully: if Supermemory is unreachable, the evaluation proceeds
    with no historical context (empty memory) rather than crashing. This matches
    the resilience contract the existing memory facade follows.
    """
    sm = client or SupermemoryClient()

    # Step 1: Fingerprint
    fp = generate_fingerprint(alert)

    # Step 2: Search memory (graceful degradation if Supermemory is down)
    similar_records: list[ImmuneMemoryRecord] = []
    memory_available = True
    try:
        similar_records = await _search_similar(fp.fingerprint, client=sm)
    except (SupermemoryError, Exception) as exc:  # noqa: BLE001
        logger.warning("Supermemory search failed; proceeding without history: %s", exc)
        memory_available = False

    # Step 3: Confidence
    confidence, reasoning = compute_confidence(alert.severity, similar_records)
    if not memory_available:
        reasoning += " [WARNING: Supermemory unavailable — no historical context]"

    # Step 4: Recommendation
    recommendation = generate_recommendation(alert, confidence, similar_records)

    # Build historical-match summaries for the response.
    historical_matches: list[HistoricalMatch] = [
        HistoricalMatch(
            fingerprint=r.fingerprint,
            confidence=r.confidence,
            action_taken=r.action_taken,
            false_positive=r.false_positive,
            incident_summary=r.incident_summary[:300],
            timestamp=r.timestamp,
        )
        for r in similar_records
    ]

    is_known = len(similar_records) > 0
    has_fp_history = any(r.false_positive for r in similar_records)

    # Step 5: Store new record (best-effort — never fail the evaluation)
    incident_summary = (
        f"Alert {alert.alert_id or 'N/A'}: {alert.attack_category or 'unknown'} "
        f"targeting {alert.manufacturer} {alert.device_type} "
        f"via {alert.protocol}:{alert.destination_port or '?'}. "
        f"Confidence: {confidence:.0f}%. Recommendation: {recommendation[:100]}"
    )
    new_record = ImmuneMemoryRecord(
        fingerprint=fp.fingerprint,
        attack_type=alert.attack_category,
        manufacturer=alert.manufacturer,
        device_type=alert.device_type,
        confidence=confidence,
        recommendation=recommendation,
        incident_summary=incident_summary,
    )
    try:
        await _store_memory(new_record, client=sm, record_type="immune-evaluation")
    except (SupermemoryError, Exception) as exc:  # noqa: BLE001
        logger.warning("Failed to store immune memory: %s", exc)

    # Audit trail
    append_audit_entry({
        "event": "immunity_evaluation",
        "fingerprint": fp.fingerprint,
        "confidence": confidence,
        "is_known_pattern": is_known,
        "false_positive_history": has_fp_history,
        "recommendation": recommendation[:200],
        "memory_available": memory_available,
    })

    # Step 6: Return evaluation
    return ImmunityEvaluation(
        fingerprint=fp,
        similar_incidents=historical_matches,
        confidence=confidence,
        recommendation=recommendation,
        reasoning=reasoning,
        is_known_pattern=is_known,
        false_positive_history=has_fp_history,
    )


# ---------------------------------------------------------------------------
# Public API — record analyst feedback (human-in-the-loop)
# ---------------------------------------------------------------------------
async def record_feedback(
    feedback: AnalystFeedback,
    *,
    client: SupermemoryClient | None = None,
) -> ImmuneMemoryRecord:
    """Store analyst judgment so the immune system learns from human decisions.

    If an analyst marks an incident as a false positive, future searches for
    the same fingerprint will retrieve that judgment and reduce confidence
    accordingly. Conversely, confirmed true-positives boost future scores.
    """
    sm = client or SupermemoryClient()

    record = ImmuneMemoryRecord(
        fingerprint=feedback.fingerprint,
        analyst_feedback=feedback.feedback_text,
        false_positive=feedback.is_false_positive,
        action_taken=feedback.action_taken,
        incident_summary=(
            f"Analyst feedback: {'FALSE POSITIVE' if feedback.is_false_positive else 'CONFIRMED'}. "
            f"{feedback.feedback_text}"
        ),
    )
    await _store_memory(record, client=sm, record_type="immune-feedback")

    append_audit_entry({
        "event": "immunity_feedback",
        "fingerprint": feedback.fingerprint,
        "is_false_positive": feedback.is_false_positive,
        "action_taken": feedback.action_taken,
    })

    return record
