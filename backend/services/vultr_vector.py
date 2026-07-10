"""Vultr Vector Store ingestion for medical-device manuals.

This module deliberately talks to Vultr's managed Vector Store API directly.
It has no local database or alternate vector-store fallback.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

import httpx

from schemas.contract_a import ContractA


DEFAULT_BASE_URL = "https://api.vultrinference.com/v1/vector_store"


def _vector_store_api_key() -> str:
    """Vector store collections are scoped to the main Vultr account API key, not inference key."""
    return os.getenv("VULTR_API_KEY", "") or os.getenv("VULTR_INFERENCE_API_KEY", "")


def _vector_store_base_url() -> str:
    return (os.getenv("VULTR_VECTOR_STORE_URL") or DEFAULT_BASE_URL).rstrip("/")


class VultrVectorStoreError(RuntimeError):
    """Raised when managed Vector Store ingestion cannot be completed."""


@dataclass(frozen=True)
class IngestionResult:
    collection_id: str
    source_doc_id: str
    item_ids: tuple[str, ...]
    chunk_count: int


def chunk_manual(text: str, chunk_size: int = 2_000, overlap: int = 200) -> list[str]:
    """Split manual text into bounded, overlapping chunks near natural boundaries."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be non-negative and smaller than chunk_size")

    normalized = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        raise ValueError("manual text must not be empty")

    chunks: list[str] = []
    start = 0
    text_length = len(normalized)

    while start < text_length:
        end = min(start + chunk_size, text_length)
        if end < text_length:
            # Prefer a paragraph, line, sentence, or word boundary in the latter
            # half of the window. Fall back to an exact character boundary.
            lower_bound = start + chunk_size // 2
            candidates = (
                normalized.rfind("\n\n", lower_bound, end),
                normalized.rfind("\n", lower_bound, end),
                normalized.rfind(". ", lower_bound, end),
                normalized.rfind(" ", lower_bound, end),
            )
            boundary = max(candidates)
            # The chosen boundary must still advance beyond the requested
            # overlap; otherwise very large overlaps could stall the loop.
            if boundary > start + overlap:
                end = boundary + (2 if normalized[boundary:boundary + 2] in {"\n\n", ". "} else 1)

        chunk = normalized[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= text_length:
            break
        start = end - overlap

    return chunks


class VultrVectorStore:
    """Small async client for Vultr Serverless Inference Vector Store."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        collection_id: str | None = None,
        collection_name: str | None = None,
        timeout: float | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key or _vector_store_api_key()
        self.base_url = (base_url or _vector_store_base_url()).rstrip("/")
        self.collection_id = collection_id or os.getenv("VULTR_VECTOR_COLLECTION_ID", "")
        self.collection_name = collection_name or os.getenv("VULTR_VECTOR_COLLECTION_NAME", "panacea-manuals")
        self.timeout = timeout or float(os.getenv("VULTR_VECTOR_TIMEOUT", "30"))
        self._client = client

        if not self.api_key:
            raise VultrVectorStoreError("VULTR_INFERENCE_API_KEY is required for Vultr Vector Store")
        if not self.collection_id and not self.collection_name:
            raise VultrVectorStoreError(
                "VULTR_VECTOR_COLLECTION_ID or VULTR_VECTOR_COLLECTION_NAME is required"
            )

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    # Vultr's Vector Store intermittently returns these under concurrent load
    # (e.g. multi-device runs ingesting/querying the same collection at once):
    # 422 "Internal Error" on /items, and a transient "Collection not found" on
    # /RAG while another ingest is still indexing. All are safe to retry.
    _RETRYABLE_STATUS = frozenset({409, 422, 425, 429, 500, 502, 503, 504})
    _MAX_ATTEMPTS = 5

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        last_error: Exception | None = None
        headers = self._headers.copy()
        if "files" in kwargs:
            headers.pop("Content-Type", None)
        for attempt in range(self._MAX_ATTEMPTS):
            try:
                if self._client is not None:
                    response = await self._client.request(method, url, headers=headers, **kwargs)
                else:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        response = await client.request(method, url, headers=headers, **kwargs)

                if response.is_error:
                    detail = response.text[:500]
                    endpoint = url.rsplit("/", 2)[-2:]
                    error = VultrVectorStoreError(
                        f"Vultr Vector Store returned HTTP {response.status_code} "
                        f"at .../{'/'.join(endpoint)}: {detail}"
                    )
                    if response.status_code in self._RETRYABLE_STATUS and attempt < self._MAX_ATTEMPTS - 1:
                        last_error = error
                        await asyncio.sleep(0.5 * (2**attempt))
                        continue
                    raise error
                return response
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = exc
                if attempt < self._MAX_ATTEMPTS - 1:
                    await asyncio.sleep(0.5 * (2**attempt))

        raise VultrVectorStoreError(
            f"Vultr Vector Store request failed after {self._MAX_ATTEMPTS} attempts: {last_error}"
        )

    async def ensure_collection(self) -> str:
        """Return the configured collection, creating it by name when necessary.

        Concurrent callers (e.g. two device manuals ingested at the same time,
        each with their own VultrVectorStore() instance and no pre-set
        collection_id) can race to create the same named collection. Vultr's
        API rejects the loser with a 422 "duplicate collection name" error
        rather than idempotently returning the winner's ID. On that specific
        conflict we re-resolve by name instead of failing, so concurrent
        onboarding converges on one shared collection instead of one side
        erroring out.
        """
        if self.collection_id:
            return self.collection_id

        found = await self._find_by_name()
        if found:
            self.collection_id = found
            return self.collection_id

        try:
            response = await self._request(
                "POST",
                self.base_url,
                json={"name": self.collection_name},
            )
        except VultrVectorStoreError as exc:
            if "duplicate" not in str(exc).lower():
                raise
            # The winning create can still be in flight when our POST is
            # rejected — a short retry window isn't enough under real
            # contention, so this is deliberately generous (~7.5s worst case).
            resolved = await self._find_by_name(retries=6)
            if not resolved:
                raise VultrVectorStoreError(
                    f"Collection '{self.collection_name}' reported as a duplicate but could not "
                    "be resolved by name — Vultr Vector Store listing may be lagging."
                ) from exc
            self.collection_id = resolved
            return self.collection_id

        self.collection_id = _response_id(response.json())
        return self.collection_id

    async def _find_by_name(self, retries: int = 1) -> str | None:
        for attempt in range(retries):
            if attempt:
                await asyncio.sleep(0.25 * (2 ** (attempt - 1)))
            response = await self._request("GET", self.base_url)
            for collection in _records(response.json(), "collections", "vector_stores"):
                if collection.get("name") == self.collection_name and collection.get("id"):
                    return str(collection["id"])
        return None

    async def add_item(self, collection_id: str, content: str, description: str) -> str:
        # auto_chunk lets Vultr split content that exceeds the embedder's max
        # sequence length into ~300-token pieces automatically, avoiding HTTP 422.
        # When it chunks, the response returns multiple item IDs — we return the first.
        response = await self._request(
            "POST",
            f"{self.base_url}/{collection_id}/items",
            json={"content": content, "description": description[:500], "auto_chunk": True},
        )
        return _response_id(response.json())

    async def add_file(
        self,
        collection_id: str,
        filename: str,
        content: bytes,
        content_type: str = "application/pdf",
    ) -> str:
        """Upload the original document through Vultr Vector Store's file endpoint."""
        response = await self._request(
            "POST",
            f"{self.base_url}/{collection_id}/files",
            files={"file": (filename, content, content_type)},
        )
        return _response_id(response.json())

    async def ingest_manual(
        self,
        manual_text: str,
        contract: ContractA,
        *,
        chunk_size: int = 2_000,
        overlap: int = 200,
    ) -> IngestionResult:
        """Chunk a manual and store every chunk in Vultr with Contract A context."""
        chunks = chunk_manual(manual_text, chunk_size=chunk_size, overlap=overlap)
        collection_id = await self.ensure_collection()

        source_doc_id = contract.source_doc_id.strip()
        if not source_doc_id:
            digest = hashlib.sha256(manual_text.encode("utf-8")).hexdigest()[:16]
            source_doc_id = await self.add_item(
                collection_id,
                content=f"PANACEA manual source record sha256:{digest}",
                description=f"Source record for {contract.device_model} manual",
            )

        stored_contract = contract.model_copy(update={"source_doc_id": source_doc_id})
        contract_json = json.dumps(stored_contract.model_dump(), separators=(",", ":"))
        item_ids: list[str] = []

        for index, chunk in enumerate(chunks, start=1):
            # Keep per-chunk content minimal — device+firmware header only.
            # Full CONTRACT_A is already stored in the source record above.
            content = (
                f"Device: {stored_contract.device_model} | Firmware: {stored_contract.firmware_version} | "
                f"Source: {source_doc_id}\n\n{chunk}"
            )
            description = (
                f"{stored_contract.device_model} {stored_contract.firmware_version}; "
                f"source {source_doc_id}; chunk {index}/{len(chunks)}"
            )
            item_ids.append(await self.add_item(collection_id, content, description))

        return IngestionResult(
            collection_id=collection_id,
            source_doc_id=source_doc_id,
            item_ids=tuple(item_ids),
            chunk_count=len(chunks),
        )

    async def rag_query(self, collection_id: str, query: str, model: str | None = None) -> str:
        """Ground a query in a Vultr Vector Store collection using Vultr RAG."""
        rag_url = self.base_url.rsplit("/vector_store", 1)[0] + "/chat/completions/RAG"
        response = await self._request(
            "POST",
            rag_url,
            json={
                "collection": collection_id,
                "model": model or os.getenv("VULTR_RAG_MODEL", "qwen2.5-32b-instruct"),
                "messages": [{"role": "user", "content": query}],
                "max_tokens": int(os.getenv("VULTR_RAG_MAX_TOKENS", "700")),
                "temperature": 0,
            },
        )
        try:
            message = response.json()["choices"][0]["message"]
            return message.get("content") or message.get("reasoning_content") or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise VultrVectorStoreError("Unexpected response from Vultr RAG endpoint") from exc


async def ingest_manual(
    manual_text: str,
    contract: ContractA,
    *,
    chunk_size: int | None = None,
    overlap: int | None = None,
) -> IngestionResult:
    """Environment-configured ingestion entry point used by the orchestrator."""
    return await VultrVectorStore().ingest_manual(
        manual_text,
        contract,
        chunk_size=chunk_size if chunk_size is not None else int(os.getenv("VULTR_VECTOR_CHUNK_SIZE", "2000")),
        overlap=overlap if overlap is not None else int(os.getenv("VULTR_VECTOR_CHUNK_OVERLAP", "200")),
    )


async def query_manual(collection_id: str, contract: ContractA) -> str:
    """Retrieve manufacturer evidence relevant to a proposed policy."""
    ports = ", ".join(f"{item.protocol} {item.port}" for item in contract.allowed_ports) or "none"
    query = (
        f"For device {contract.device_model} firmware {contract.firmware_version}, return only the "
        f"manual evidence that justifies these network ports: {ports}. Include warnings or restrictions."
    )
    store = VultrVectorStore(collection_id=collection_id)
    last_error: Exception | None = None
    for attempt in range(4):
        if attempt:
            await asyncio.sleep(2 ** (attempt - 1))
        try:
            result = await store.rag_query(collection_id, query)
            if result.strip():
                return result
        except VultrVectorStoreError as exc:
            last_error = exc
    raise VultrVectorStoreError(f"Manual chunks were not queryable after indexing wait: {last_error}")


async def query_cve(device_model: str, firmware_version: str) -> str:
    """Query the Vultr-hosted CVE knowledge collection; never calls an external CVE API."""
    collection_id = os.getenv("VULTR_CVE_COLLECTION_ID", "")
    if not collection_id:
        raise VultrVectorStoreError("VULTR_CVE_COLLECTION_ID is required for CVE grounding")
    # The CVE collection may live under a different Vultr account than the manuals
    # collection (it was ingested with the inference key). Allow a dedicated key so
    # RAG can authenticate against whichever account owns the CVE collection.
    cve_api_key = (
        os.getenv("VULTR_CVE_API_KEY")
        or os.getenv("VULTR_INFERENCE_API_KEY")
        or None
    )
    query = (
        f"A {device_model} running software revision/firmware '{firmware_version}' is deployed on "
        "the network. From the CVE collection, return every CVE whose affected_versions could apply "
        "to this device. Treat revision letters as inclusive ranges (for example 'Rev B-M' includes "
        "revisions C, D, ... L), and treat 'Version N and prior' as including earlier revisions. "
        "Match on the device family even if the exact revision string is not listed verbatim. "
        "Return a concise JSON array where each item has cve_id, severity, affected_versions, and "
        "mitigation. Only return cve_id NONE if no CVE in the collection could plausibly apply."
    )
    return await VultrVectorStore(collection_id=collection_id, api_key=cve_api_key).rag_query(
        collection_id, query
    )


async def retrieve_document(query: str, device_model: str, top_k: int = 3) -> str:
    """Targeted agent-tool retrieval through Vultr's managed RAG endpoint."""
    collection_id = os.getenv("VULTR_VECTOR_COLLECTION_ID", "")
    if not collection_id:
        raise VultrVectorStoreError("VULTR_VECTOR_COLLECTION_ID is required for document retrieval")
    grounded_query = (
        f"Return up to {top_k} exact manual passages for device {device_model} relevant to: {query}. "
        "For each passage, include the Vultr source item identifier when available."
    )
    return await VultrVectorStore(collection_id=collection_id).rag_query(collection_id, grounded_query)


def _records(payload: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", *keys):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _records(value, *keys)
            if nested:
                return nested
    return []


def _response_id(payload: Any) -> str:
    # auto_chunk responses return a list of items — take the first ID.
    if isinstance(payload, list):
        for entry in payload:
            try:
                return _response_id(entry)
            except VultrVectorStoreError:
                continue
        raise VultrVectorStoreError("Vultr Vector Store response list contained no resource ID")
    if isinstance(payload, dict):
        value = payload.get("id") or payload.get("file_id") or payload.get("item_id")
        if value is not None:
            return str(value)
        for key in ("data", "items", "collection", "vector_store", "item", "file"):
            if key in payload:
                try:
                    return _response_id(payload[key])
                except VultrVectorStoreError:
                    pass
    raise VultrVectorStoreError("Vultr Vector Store response did not include a resource ID")
