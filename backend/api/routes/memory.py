"""Operational API for the local Supermemory plane."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.auth import require_operator
from services.memory_ops import (
    device_timeline,
    export_device_snapshot,
    fleet_recall,
    inspect_space,
    list_memory_spaces,
    record_policy_outcome,
    search_with_trace,
)

router = APIRouter()


class MemorySearchRequest(BaseModel):
    space: str = Field(min_length=1)
    query: str = Field(min_length=1)
    limit: int = Field(default=5, ge=1, le=50)


class FleetRecallRequest(BaseModel):
    device_model: str = Field(min_length=1)
    related_models: list[str] = Field(default_factory=list)
    limit_per_device: int = Field(default=20, ge=1, le=100)


class PolicyOutcomeRequest(BaseModel):
    device_model: str = Field(min_length=1)
    lease_id: str = Field(min_length=1)
    outcome: str = Field(
        min_length=1,
        description="Operational result, e.g. enforced, useful, overridden, outage, expired_cleanly.",
    )
    notes: str = ""
    confidence_score: int | None = Field(default=None, ge=0, le=100)


@router.get("/api/v1/memory/spaces")
async def get_memory_spaces(operator_id: str = Depends(require_operator)):
    """List registered local Supermemory spaces."""
    try:
        spaces = await list_memory_spaces()
        return {"spaces": spaces, "count": len(spaces)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/api/v1/memory/spaces/{space}")
async def get_memory_space(
    space: str,
    limit: int = Query(default=100, ge=1, le=500),
    include_profile: bool = True,
    operator_id: str = Depends(require_operator),
):
    """Inspect documents, type counts, and profile text for a memory space."""
    try:
        return await inspect_space(space, limit=limit, include_profile=include_profile)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/api/v1/memory/search")
async def search_memory(request: MemorySearchRequest, operator_id: str = Depends(require_operator)):
    """Search a memory space and return the exact graph/chunk retrieval trace."""
    try:
        return await search_with_trace(request.query, space=request.space, limit=request.limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/api/v1/memory/fleet-recall")
async def recall_fleet_memory(request: FleetRecallRequest, operator_id: str = Depends(require_operator)):
    """Recall attack and policy memory across this device and related peers."""
    try:
        return await fleet_recall(
            request.device_model,
            related_models=request.related_models,
            limit_per_device=request.limit_per_device,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/api/v1/memory/devices/{device_model}/timeline")
async def get_device_timeline(
    device_model: str,
    limit: int = Query(default=200, ge=1, le=500),
    operator_id: str = Depends(require_operator),
):
    """Return manual, drift, facts, enforcement, and outcome memory for a device."""
    try:
        return await device_timeline(device_model, limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/api/v1/memory/devices/{device_model}/export")
async def export_memory_snapshot(
    device_model: str,
    include_immunity: bool = False,
    operator_id: str = Depends(require_operator),
):
    """Export a local memory snapshot for audit or demo replay."""
    try:
        return await export_device_snapshot(device_model, include_immunity=include_immunity)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/api/v1/memory/policy-outcomes")
async def submit_policy_outcome(
    request: PolicyOutcomeRequest,
    operator_id: str = Depends(require_operator),
):
    """Record human or operational feedback about a policy outcome."""
    try:
        doc_id = await record_policy_outcome(
            device_model=request.device_model,
            lease_id=request.lease_id,
            outcome=request.outcome,
            notes=request.notes,
            confidence_score=request.confidence_score,
            operator_id=operator_id,
        )
        return {"status": "recorded", "doc_id": doc_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
