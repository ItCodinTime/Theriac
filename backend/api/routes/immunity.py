# POST /api/v1/immunity/evaluate — Evaluate an incoming security alert through the immune system.
# POST /api/v1/immunity/feedback — Record analyst judgment for the human feedback loop.
# Follows the existing route conventions: APIRouter, /api/v1/ prefix, Depends(require_operator).

from fastapi import APIRouter, Depends, HTTPException

from api.auth import require_operator
from schemas.immunity import AnalystFeedback, ImmunityEvaluation, SecurityAlert
from services.immunity import evaluate_alert, record_feedback

router = APIRouter()


@router.post("/api/v1/immunity/evaluate", response_model=ImmunityEvaluation)
async def evaluate_security_alert(
    alert: SecurityAlert,
    operator_id: str = Depends(require_operator),
):
    """Evaluate a security alert through the Adaptive Host Immunity system.

    Generates an immune fingerprint, searches Supermemory for similar historical
    incidents, adjusts confidence based on past outcomes and analyst feedback,
    and returns a recommendation. The evaluation is stored as a new immune memory
    so the system becomes smarter over time.
    """
    try:
        result = await evaluate_alert(alert)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/api/v1/immunity/feedback")
async def submit_analyst_feedback(
    feedback: AnalystFeedback,
    operator_id: str = Depends(require_operator),
):
    """Record analyst judgment on a previous incident.

    Marking an incident as a false positive trains the immune system to lower
    confidence for identical patterns in the future. Confirmed incidents boost
    future confidence scores.
    """
    try:
        record = await record_feedback(feedback)
        return {
            "status": "recorded",
            "fingerprint": record.fingerprint,
            "false_positive": record.false_positive,
            "message": (
                "Feedback stored. Future evaluations of this pattern will "
                "reflect this judgment."
            ),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
