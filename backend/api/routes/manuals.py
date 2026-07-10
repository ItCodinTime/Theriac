"""Upload a PDF manual into the Vultr-native PANACEA pipeline."""

from __future__ import annotations

import io

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pypdf import PdfReader

from agent.orchestrator import run_pipeline
from api.auth import require_operator
from api.websocket import broadcast
from schemas.contract_b import ContractB
from services.vultr_inference import StreamToken
from services.vultr_object_storage import VultrObjectStorage, VultrObjectStorageError
from services.vultr_vector import VultrVectorStore


router = APIRouter()


@router.post("/api/v1/manuals/run", response_model=ContractB)
async def upload_manual(
    file: UploadFile = File(...),
    vpc_id: str = Form("vpc-medical-01"),
    operator_id: str = Depends(require_operator),
) -> ContractB:
    content = await file.read()
    if not content.startswith(b"%PDF"):
        raise HTTPException(status_code=415, detail="A PDF manual is required")
    try:
        pages = PdfReader(io.BytesIO(content)).pages
        text = "\n\n".join(page.extract_text() or "" for page in pages).strip()
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Unable to parse PDF: {exc}") from exc
    if not text:
        raise HTTPException(status_code=422, detail="PDF contains no extractable text")

    storage = VultrObjectStorage()
    object_key = ""
    vector_file_id = ""
    try:
        if storage.configured:
            object_key = storage.store_manual(file.filename or "manual.pdf", content, "application/pdf")
        elif storage.strict:
            raise VultrObjectStorageError("Vultr Object Storage is required in strict mode")

        vector = VultrVectorStore()
        collection_id = await vector.ensure_collection()
        vector_file_id = await vector.add_file(
            collection_id,
            file.filename or "manual.pdf",
            content,
        )

        async def on_token(token: StreamToken) -> None:
            await broadcast({"type": token.type, "text": token.text})

        return await run_pipeline(
            text,
            vpc_id,
            on_token,
            manual_object_key=object_key,
            operator_id=operator_id,
            source_doc_id=vector_file_id,
        )
    except VultrObjectStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
