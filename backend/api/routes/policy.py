# DELETE /api/v1/policy/{device_id} — Human Override endpoint. Retracts the active firewall rule for a given device.

import sys
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agent.orchestrator import retract_policy
from api.auth import require_operator
from api.websocket import broadcast
from services.vultr_events import publish_event

router = APIRouter()


@router.delete("/api/v1/policy/{device_id}")
async def human_override(device_id: str, operator_id: str = Depends(require_operator)):
    """
    Human Override — immediately retracts the active firewall policy for a device.
    Called by Oleh's frontend when the operator flags a false positive.
    Broadcasts the retraction event to all WebSocket clients.
    """
    try:
        result = await retract_policy(device_id)

        if result.get("status") == "not_found":
            raise HTTPException(
                status_code=404,
                detail=f"No active policy found for device '{device_id}'",
            )

        await broadcast({
            "type": "content",
            "text": f"[HUMAN OVERRIDE] Policy retracted for device '{device_id}'. Firewall rules removed from {result.get('vpc_id', 'unknown VPC')}.",
        })
        await publish_event(
            "policy.revoked",
            device_id,
            {"device_id": device_id, "operator_id": operator_id, "result": result},
        )

        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
