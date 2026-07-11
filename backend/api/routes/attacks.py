# Attack telemetry API — ingest, observe, HL7 log bridge, history recall.

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.auth import require_operator
from schemas.attack_event import AttackEvent, AttackHistorySummary, ObserveRequest
from services.attack_memory import ingest_attack_event, query_attack_history
from services.attack_observer import ingest_hl7_log_lines, observe_once

router = APIRouter()


class Hl7LogBatch(BaseModel):
    lines: list[str] = Field(default_factory=list)
    device_model: str = "Philips_IntelliVue"
    firmware_version: str = "L.0"
    run_immunity: bool = False


@router.post("/api/v1/attacks")
async def ingest_attack(
    event: AttackEvent,
    operator_id: str = Depends(require_operator),
    run_immunity: bool = Query(default=False),
):
    """Store an observed attack/probe/blocked-connection event in Supermemory.

    Auto-correlates device → CVE → port. Set ``run_immunity=true`` to also
    fingerprint the event into the Adaptive Host Immunity memory space.
    """
    try:
        result = await ingest_attack_event(event, run_immunity=run_immunity)
        return {
            **result,
            "operator_id": operator_id,
            "message": (
                f"Attack telemetry stored. Next policy scan for {event.device_model} "
                f"will recall probes on port {event.attempted_port}"
                + (f" (CVE {result.get('related_cve')})" if result.get("related_cve") else "")
                + "."
            ),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/api/v1/attacks/observe")
async def observe_attacks(
    request: ObserveRequest | None = None,
    operator_id: str = Depends(require_operator),
):
    """One-shot observation: probe target ports, ingest results, optional AHI bridge.

    Uses ``VULTR_TARGET_PUBLIC_IP`` / ``VULTR_ATTACKER_PUBLIC_IP``. This is the
    continuous-loop substitute when you don't yet have a log shipper — cron it.
    """
    try:
        result = await observe_once(request)
        return {**result, "operator_id": operator_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/api/v1/attacks/hl7-logs")
async def ingest_hl7_logs(
    batch: Hl7LogBatch,
    operator_id: str = Depends(require_operator),
):
    """Parse HL7 listener stdout/journal lines and ingest matching connections."""
    try:
        results = await ingest_hl7_log_lines(
            batch.lines,
            device_model=batch.device_model,
            firmware_version=batch.firmware_version,
            run_immunity=batch.run_immunity,
        )
        return {
            "status": "ok",
            "ingested": len(results),
            "results": results,
            "operator_id": operator_id,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/api/v1/attacks/{device_model}", response_model=AttackHistorySummary)
async def get_attack_history(
    device_model: str,
    operator_id: str = Depends(require_operator),
):
    """Recall aggregated attack history + CVE correlations for a device."""
    try:
        return await query_attack_history(device_model)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
