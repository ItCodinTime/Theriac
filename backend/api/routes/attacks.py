# POST /api/v1/attacks — ingest observed attack / probe telemetry into Supermemory.
# GET  /api/v1/attacks/{device_model} — recall attack history for a device.

from fastapi import APIRouter, Depends, HTTPException

from api.auth import require_operator
from schemas.attack_event import AttackEvent, AttackHistorySummary
from services.attack_memory import ingest_attack_event, query_attack_history

router = APIRouter()


@router.post("/api/v1/attacks")
async def ingest_attack(
    event: AttackEvent,
    operator_id: str = Depends(require_operator),
):
    """Store an observed attack/probe/blocked-connection event in Supermemory.

    Writes into the per-device ``attacks:<slug>`` space so the next agent run can
    call ``check_attack_history`` and harden the firewall policy.
    """
    try:
        result = await ingest_attack_event(event)
        return {
            **result,
            "operator_id": operator_id,
            "message": (
                f"Attack telemetry stored. Next policy scan for {event.device_model} "
                f"will recall probes on port {event.attempted_port}."
            ),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/api/v1/attacks/{device_model}", response_model=AttackHistorySummary)
async def get_attack_history(
    device_model: str,
    operator_id: str = Depends(require_operator),
):
    """Recall aggregated attack history for a device from Supermemory."""
    try:
        return await query_attack_history(device_model)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
