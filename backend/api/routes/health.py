# GET /healthz — Simple liveness check so Vultr and the frontend can confirm the backend is up.

import os

import httpx
from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("/healthz")
async def health_check():
    return {"status": "ok", "service": "panacea-backend"}


@router.get("/readyz")
async def readiness_check():
    """Verify the mandatory Vultr inference plane before receiving traffic."""
    base_url = os.getenv("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1")
    api_key = os.getenv("VULTR_INFERENCE_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="Vultr Inference is not configured")
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(
                f"{base_url.rstrip('/')}/health",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            response.raise_for_status()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Vultr Inference is unavailable") from exc
    return {
        "status": "ready",
        "inference": "ok",
        "native_strict": os.getenv("VULTR_NATIVE_STRICT", "false").lower() == "true",
    }
