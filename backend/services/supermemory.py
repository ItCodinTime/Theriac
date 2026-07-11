"""Self-hosted Supermemory client — Theriac's primary memory / RAG engine.

Supermemory runs as a single local binary (default http://localhost:6767) with an
embedded graph engine and local embeddings. Retrieval therefore stays entirely
inside the hospital boundary (zero data egress); only the memory-extraction LLM
is pointed at Vultr Serverless Inference. This module talks to that local server
directly and has no external vector-store dependency.

Spaces are expressed through Supermemory's ``containerTags``: one tag per device
(``device:<slug>``) for manuals + enforcement outcomes, a shared ``cve-knowledge``
tag for the CVE corpus, and ``attacks:<slug>`` for observed probe / blocked-
connection telemetry that hardens the next policy. The ontology-aware memory
graph and the per-container profile are built automatically as documents are
ingested.

Payload field names (``containerTags``, the ``/v4/search`` result shape) follow
Supermemory's documented API but are resolved defensively — helpers tolerate the
common response envelopes so a minor server-version drift degrades gracefully
instead of crashing a live run. Confirm exact shapes against the OpenAPI docs the
server serves on first boot at ``:6767``.
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any

import httpx


DEFAULT_BASE_URL = "http://localhost:6767"
CVE_CONTAINER_TAG = "cve-knowledge"
BASELINE_MARKER = "device-baseline"


class SupermemoryError(RuntimeError):
    """Raised when the local Supermemory server cannot satisfy a request."""


def _base_url() -> str:
    return (os.getenv("SUPERMEMORY_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")


def _api_key() -> str:
    # A key is generated and printed by the server on first boot. Self-hosted
    # dev builds also accept unauthenticated localhost calls, so this is optional.
    return os.getenv("SUPERMEMORY_API_KEY", "")


def device_container_tag(device_model: str) -> str:
    """Stable per-device space tag, e.g. 'device:philips_intellivue'."""
    slug = re.sub(r"[^a-z0-9]+", "_", (device_model or "unknown").strip().lower()).strip("_")
    return f"device:{slug or 'unknown'}"


def attack_container_tag(device_model: str) -> str:
    """Per-device attack-telemetry space, e.g. 'attacks:philips_intellivue'."""
    slug = re.sub(r"[^a-z0-9]+", "_", (device_model or "unknown").strip().lower()).strip("_")
    return f"attacks:{slug or 'unknown'}"


class SupermemoryClient:
    """Small async client for a self-hosted Supermemory server."""

    # Transient statuses the local server can return while a just-ingested
    # document is still being indexed into the graph, or under concurrent load
    # from a multi-device run. All are safe to retry.
    _RETRYABLE_STATUS = frozenset({409, 425, 429, 500, 502, 503, 504})
    _MAX_ATTEMPTS = 5

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = (base_url or _base_url()).rstrip("/")
        self.api_key = api_key if api_key is not None else _api_key()
        self.timeout = timeout or float(os.getenv("SUPERMEMORY_TIMEOUT", "30"))
        self._client = client

    @property
    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        url = f"{self.base_url}{path}"
        last_error: Exception | None = None
        for attempt in range(self._MAX_ATTEMPTS):
            try:
                if self._client is not None:
                    response = await self._client.request(method, url, headers=self._headers, **kwargs)
                else:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        response = await client.request(method, url, headers=self._headers, **kwargs)

                if response.is_error:
                    error = SupermemoryError(
                        f"Supermemory returned HTTP {response.status_code} at {path}: {response.text[:500]}"
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

        raise SupermemoryError(
            f"Supermemory request to {path} failed after {self._MAX_ATTEMPTS} attempts: {last_error}"
        )

    # ------------------------------------------------------------------
    # Ingestion — /v3/documents
    # ------------------------------------------------------------------
    async def add_document(
        self,
        content: str,
        *,
        container_tag: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Store one document. Supermemory extracts memories and graph edges itself."""
        payload: dict[str, Any] = {"content": content, "containerTags": [container_tag]}
        if metadata:
            payload["metadata"] = metadata
        response = await self._request("POST", "/v3/documents", json=payload)
        return _extract_id(response.json())

    # ------------------------------------------------------------------
    # Retrieval — /v4/search (hybrid semantic search + rerank)
    # ------------------------------------------------------------------
    async def search(
        self,
        query: str,
        *,
        container_tag: str,
        rerank: bool = True,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Hybrid semantic search scoped to a container tag, reranked by default."""
        payload = {
            "q": query,
            "containerTags": [container_tag],
            "rerank": rerank,
            "limit": limit,
        }
        response = await self._request("POST", "/v4/search", json=payload)
        return _result_records(response.json())

    async def search_documents(self, query: str, *, container_tag: str, limit: int = 5) -> list[dict[str, Any]]:
        """Chunk-level semantic search over the embedded document chunks (/v3/search).

        Unlike /v4/search — which queries the extracted memory *graph* — this hits
        the raw embedded chunks, so it returns grounded passages even when memory
        extraction is weak or unavailable (e.g. a small self-hosted model). Used as
        the retrieval floor so THERIAC always has cited evidence to reason over.
        """
        response = await self._request(
            "POST", "/v3/search", json={"q": query, "containerTags": [container_tag], "limit": limit}
        )
        return _result_records(response.json())

    async def search_text(
        self,
        query: str,
        *,
        container_tag: str,
        rerank: bool = True,
        limit: int = 5,
    ) -> str:
        """Search and flatten the top passages into a single grounding-evidence blob.

        Tries the graph-aware /v4/search first, then falls back to chunk-level
        /v3/search when the graph has no matching memories yet — so retrieval is
        resilient to the memory-extraction model's strength.
        """
        records = await self.search(query, container_tag=container_tag, rerank=rerank, limit=limit)
        passages = [text for text in (_record_text(record) for record in records) if text]
        if not passages:
            records = await self.search_documents(query, container_tag=container_tag, limit=limit)
            passages = [text for text in (_record_text(record) for record in records) if text]
        return "\n\n".join(passages)

    # ------------------------------------------------------------------
    # Profile — /v4/profile (auto-synthesized per-container narrative)
    # ------------------------------------------------------------------
    async def get_profile_text(self, container_tag: str) -> str:
        """Return the synthesized profile narrative for a container, or '' if none."""
        try:
            response = await self._request(
                "POST", "/v4/profile", json={"containerTags": [container_tag]}
            )
        except SupermemoryError:
            return ""
        payload = response.json()
        if isinstance(payload, dict):
            for key in ("profile", "summary", "content", "text"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    return value
        return ""

    # ------------------------------------------------------------------
    # Durable structured read-back — used for restart-safe drift baselines.
    # Profiles are synthesized prose; drift needs an exact prior Contract A, so
    # the baseline is stored as a marked document and read back deterministically.
    # ------------------------------------------------------------------
    async def list_documents(self, container_tag: str, *, limit: int = 100) -> list[dict[str, Any]]:
        # The real endpoint is POST /v3/documents/list (GET /v3/documents is 404),
        # returning {"memories": [...], "pagination": {...}}. Each record carries
        # metadata/title/timestamps but NOT the raw content — so structured
        # read-back (drift baselines) is stored in and recovered from metadata.
        response = await self._request(
            "POST", "/v3/documents/list", json={"containerTags": [container_tag], "limit": limit}
        )
        return _result_records(response.json())

    async def health(self) -> bool:
        """Best-effort liveness probe for the local server."""
        try:
            await self._request("GET", "/")
            return True
        except SupermemoryError:
            return False


# ---------------------------------------------------------------------------
# Response-shape helpers — tolerant of the common Supermemory envelopes.
# ---------------------------------------------------------------------------
def _result_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("results", "documents", "memories", "matches", "data", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _record_text(record: dict[str, Any]) -> str:
    for key in ("content", "text", "chunk", "memory", "summary"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    # /v3/search nests the matched passages under a 'chunks' array.
    chunks = record.get("chunks")
    if isinstance(chunks, list):
        parts = [c.get("content", "").strip() for c in chunks if isinstance(c, dict)]
        joined = "\n".join(p for p in parts if p)
        if joined:
            return joined
    # Some search shapes nest the passage under a 'document' object.
    nested = record.get("document")
    if isinstance(nested, dict):
        return _record_text(nested)
    return ""


def _extract_id(payload: Any) -> str:
    if isinstance(payload, list):
        for entry in payload:
            try:
                return _extract_id(entry)
            except SupermemoryError:
                continue
    if isinstance(payload, dict):
        for key in ("id", "documentId", "document_id", "customId"):
            value = payload.get(key)
            if value is not None:
                return str(value)
        for key in ("document", "data", "result"):
            if key in payload:
                try:
                    return _extract_id(payload[key])
                except SupermemoryError:
                    pass
    raise SupermemoryError("Supermemory response did not include a document id")
