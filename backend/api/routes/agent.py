# POST /api/v1/agent/run — Receives a device_id, triggers the 7-step orchestration loop, and returns Contract B.
# POST /api/v1/agent/explain — Returns a plain-English compliance justification for a given policy.
# POST /api/v1/agent/multi-run — Runs the pipeline across multiple devices concurrently.

import asyncio
import sys
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agent.orchestrator import explain_policy, run_pipeline
from api.auth import require_operator
from api.websocket import broadcast
from schemas.contract_b import ContractB
from services.audit_log import read_audit_log
from services.vultr_inference import StreamToken
from services.vultr_object_storage import VultrObjectStorage, VultrObjectStorageError

router = APIRouter()


class AgentRunRequest(BaseModel):
    raw_pdf_text: str
    vpc_id: str = "vpc-medical-01"


class ExplainRequest(BaseModel):
    policy: ContractB


class MultiRunRequest(BaseModel):
    devices: list[AgentRunRequest]


@router.post("/api/v1/agent/run", response_model=ContractB)
async def run_agent(request: AgentRunRequest, operator_id: str = Depends(require_operator)):
    """
    Triggers the full 7-step PANACEA pipeline.
    Streams reasoning tokens to connected WebSocket clients in real time.
    Returns the final Contract B payload once the pipeline completes.
    """
    try:
        storage = VultrObjectStorage()
        object_key = ""
        if storage.configured:
            object_key = storage.store_manual(
                "inline-manual.txt",
                request.raw_pdf_text.encode(),
                "text/plain",
            )
        elif storage.strict:
            raise VultrObjectStorageError("Vultr Object Storage is required in strict mode")

        async def on_token(token: StreamToken) -> None:
            await broadcast({"type": token.type, "text": token.text})

        result = await run_pipeline(
            raw_pdf_text=request.raw_pdf_text,
            vpc_id=request.vpc_id,
            on_token=on_token,
            operator_id=operator_id,
            manual_object_key=object_key,
        )
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/agent/explain")
async def explain_agent_decision(request: ExplainRequest, operator_id: str = Depends(require_operator)):
    """
    Given a ContractB policy decision, Nemotron produces a plain-English justification
    that a hospital compliance officer could read. Suitable for regulatory audit trails.
    """
    try:
        explanation = await explain_policy(request.policy)
        return {"explanation": explanation, "policy_vpc_id": request.policy.target_vpc_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/agent/multi-run")
async def multi_run_agent(request: MultiRunRequest, operator_id: str = Depends(require_operator)):
    """
    Runs the PANACEA pipeline across multiple devices concurrently.
    Returns a list of ContractB results — one per device. Demonstrates the agent
    protecting a network, not just one box.
    """
    if not request.devices:
        raise HTTPException(status_code=400, detail="Provide at least one device.")
    if len(request.devices) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 devices per multi-run call.")

    async def _run_one(device: AgentRunRequest, idx: int) -> dict:
        try:
            async def on_token(token: StreamToken) -> None:
                await broadcast({
                    "type": token.type,
                    "text": f"[Device {idx + 1}] {token.text}",
                })

            result = await run_pipeline(
                raw_pdf_text=device.raw_pdf_text,
                vpc_id=device.vpc_id,
                on_token=on_token,
                operator_id=operator_id,
            )
            return {"status": "ok", "vpc_id": device.vpc_id, "policy": result.model_dump()}
        except Exception as exc:
            return {"status": "error", "vpc_id": device.vpc_id, "error": str(exc)}

    results = await asyncio.gather(*[_run_one(d, i) for i, d in enumerate(request.devices)])
    return {"results": list(results), "total": len(results)}


@router.get("/api/v1/agent/audit")
async def get_audit_log(limit: int = 50, operator_id: str = Depends(require_operator)):
    """
    Returns the last `limit` entries from the structured audit log.
    Every autonomous agent decision is permanently recorded here.
    """
    entries = read_audit_log(limit=limit)
    return {"entries": entries, "count": len(entries)}
