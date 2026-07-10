"""GET /api/v1/evidence/{evidence_id} — presigned, read-only access to a sealed evidence bundle."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from api.auth import require_operator
from services.vultr_database import get_evidence_object_key
from services.vultr_object_storage import VultrObjectStorage

router = APIRouter()


@router.get("/api/v1/evidence/{evidence_id}")
async def get_evidence_url(evidence_id: str, operator_id: str = Depends(require_operator)) -> dict:
    """
    Looks up where a sealed evidence bundle lives (via the Vultr Managed
    Database index) and returns a short-lived presigned Vultr Object Storage
    URL to it, so a compliance reviewer never needs direct bucket access.
    """
    object_key = await get_evidence_object_key(evidence_id)
    if not object_key:
        raise HTTPException(status_code=404, detail=f"No evidence indexed for '{evidence_id}'")

    storage = VultrObjectStorage()
    if not storage.configured:
        raise HTTPException(status_code=503, detail="Vultr Object Storage is not configured")

    expires_in = 300
    url = storage.presigned_url(object_key, expires_in=expires_in)
    return {"evidence_id": evidence_id, "url": url, "expires_in": expires_in}
