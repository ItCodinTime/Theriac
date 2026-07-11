"""Memory facade — Theriac's single entry point for memory / RAG.

This module preserves the exact names the orchestrator has always imported
(``ingest_manual``, ``query_manual``, ``query_cve``, ``retrieve_document``,
``IngestionResult``) so the RAG backbone can be swapped underneath it without
touching the agentic loop. The primary engine is now a locally-run Supermemory
instance (graph + hybrid search + durable per-device profiles); the legacy Vultr
Vector Store is kept only as an optional sealed-evidence archive tier, enabled
with ``VULTR_ARCHIVE_ENABLED=true``.

Every function degrades non-fatally: a memory hiccup should soften the answer,
never 500 a live enforcement run — matching the orchestrator's existing
try/except contract around the old Vultr calls.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from schemas.contract_a import ContractA
from services.supermemory import (
    BASELINE_MARKER,
    CVE_CONTAINER_TAG,
    SupermemoryClient,
    SupermemoryError,
    device_container_tag,
)
from services.vultr_vector import IngestionResult

# Public alias so callers catch one memory-layer error type regardless of engine.
MemoryError = SupermemoryError


@dataclass(frozen=True)
class MemoryCitationTrail:
    """Structured Supermemory refs for the incident-memo citation trail."""

    space: str = ""
    source_doc_id: str = ""
    item_ids: tuple[str, ...] = ()
    prior_incidents: tuple[str, ...] = field(default_factory=tuple)


__all__ = [
    "IngestionResult",
    "MemoryCitationTrail",
    "MemoryError",
    "ingest_manual",
    "query_manual",
    "query_cve",
    "retrieve_document",
    "record_enforcement",
    "query_prior_incidents",
    "build_citation_trail",
    "load_device_profile",
    "save_device_profile",
]


def _archive_enabled() -> bool:
    return os.getenv("VULTR_ARCHIVE_ENABLED", "false").lower() == "true"


def _search_limit() -> int:
    return int(os.getenv("SUPERMEMORY_SEARCH_LIMIT", "5"))


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
async def ingest_manual(manual_text: str, contract: ContractA) -> IngestionResult:
    """Store a device manual in its Supermemory space and build the graph.

    Supermemory performs its own memory extraction and chunking, so the manual is
    ingested as one document scoped to the device's container tag. Returns an
    ``IngestionResult`` shaped exactly like the old Vultr path so the orchestrator
    is unchanged (``collection_id`` now carries the container tag).
    """
    tag = device_container_tag(contract.device_model)
    client = SupermemoryClient()
    # Supermemory metadata values must be scalars (string/number/boolean) — no
    # arrays — so the port list is stored as a comma-joined string.
    metadata = {
        "device_model": contract.device_model,
        "firmware_version": contract.firmware_version,
        "type": "manual",
        "required_ports": ",".join(str(p.port) for p in contract.allowed_ports),
    }
    doc_id = await client.add_document(manual_text, container_tag=tag, metadata=metadata)

    source_doc_id = contract.source_doc_id.strip() or doc_id

    if _archive_enabled():
        # Best-effort mirror to the legacy Vultr Vector Store for the sealed
        # evidence archive. Never let an archive failure break the live run.
        try:
            from services.vultr_vector import ingest_manual as _vultr_ingest

            await _vultr_ingest(manual_text, contract)
        except Exception:  # noqa: BLE001 — archive is strictly best-effort
            pass

    return IngestionResult(
        collection_id=tag,
        source_doc_id=source_doc_id,
        item_ids=(doc_id,),
        chunk_count=1,
    )


# ---------------------------------------------------------------------------
# Retrieval (hybrid search + rerank)
# ---------------------------------------------------------------------------
async def query_manual(collection_id: str, contract: ContractA) -> str:
    """Return reranked manual passages that justify the proposed ports."""
    ports = ", ".join(f"{item.protocol} {item.port}" for item in contract.allowed_ports) or "none"
    query = (
        f"For device {contract.device_model} firmware {contract.firmware_version}, the manual "
        f"evidence that justifies these network ports: {ports}. Include any warnings or restrictions."
    )
    tag = collection_id or device_container_tag(contract.device_model)
    result = await SupermemoryClient().search_text(query, container_tag=tag, limit=_search_limit())
    if not result.strip():
        raise MemoryError("No manual passages returned from Supermemory search")
    return result


async def query_cve(device_model: str, firmware_version: str) -> str:
    """Return reranked CVE passages for a device/firmware from the CVE space.

    Raw reranked passages (not a synthesized answer) are returned deliberately:
    the orchestrator regex-extracts CVE ids from this text, and passages carry the
    exact ``cve_id`` strings without paraphrase drift.
    """
    query = (
        f"A {device_model} running software revision/firmware '{firmware_version}' is deployed. "
        "Return every CVE whose affected_versions could apply. Treat revision letters as inclusive "
        "ranges (e.g. 'Rev B-M' includes C..L) and 'Version N and prior' as including earlier "
        "revisions. Match on the device family even if the exact revision is not listed verbatim. "
        "Include cve_id, severity, affected_versions, and mitigation for each."
    )
    result = await SupermemoryClient().search_text(
        query, container_tag=CVE_CONTAINER_TAG, limit=_search_limit()
    )
    if not result.strip():
        return '{"cve_id": "NONE", "note": "No matching CVE in the Supermemory CVE space"}'
    return result


async def retrieve_document(query: str, device_model: str, top_k: int = 3) -> str:
    """Targeted agent-tool retrieval scoped to the device's Supermemory space."""
    tag = device_container_tag(device_model)
    grounded_query = f"Manual passages for device {device_model} relevant to: {query}"
    result = await SupermemoryClient().search_text(grounded_query, container_tag=tag, limit=top_k)
    if not result.strip():
        raise MemoryError(f"No passages for '{query}' in Supermemory space {tag}")
    return result


# ---------------------------------------------------------------------------
# Write-back
# ---------------------------------------------------------------------------
async def record_enforcement(collection_id: str, payload: dict, description: str) -> None:
    """Write an enforcement outcome back into the device's memory graph."""
    tag = collection_id or "device:unknown"
    content = json.dumps(payload, separators=(",", ":"), default=str)
    await SupermemoryClient().add_document(
        content, container_tag=tag, metadata={"type": "enforcement", "description": description}
    )


async def query_prior_incidents(device_model: str, *, limit: int = 5) -> list[str]:
    """Return short summaries of prior enforcement / incident memory for a device.

    Used by the incident memo so citations show institutional history from
    Supermemory — not just the current manual page refs.
    """
    tag = device_container_tag(device_model)
    client = SupermemoryClient()
    summaries: list[str] = []

    # Prefer semantic recall of prior enforcements / isolations.
    try:
        records = await client.search(
            f"prior firewall enforcement isolation incident for {device_model}",
            container_tag=tag,
            limit=limit,
        )
        if not records:
            records = await client.search_documents(
                f"enforcement isolation {device_model}",
                container_tag=tag,
                limit=limit,
            )
        for record in records:
            text = _summarize_memory_record(record)
            if text and text not in summaries:
                summaries.append(text)
            if len(summaries) >= limit:
                return summaries
    except SupermemoryError:
        pass

    # Deterministic fallback: list docs and pick enforcement metadata.
    try:
        documents = await client.list_documents(tag, limit=max(limit * 4, 20))
    except SupermemoryError:
        return summaries

    for doc in documents:
        metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        if metadata.get("type") != "enforcement":
            continue
        description = str(metadata.get("description") or "").strip()
        doc_id = str(doc.get("id") or doc.get("documentId") or doc.get("document_id") or "").strip()
        line = description or "Prior enforcement outcome on record"
        if doc_id:
            line = f"{line} [sm:{doc_id}]"
        if line not in summaries:
            summaries.append(line)
        if len(summaries) >= limit:
            break
    return summaries


def build_citation_trail(
    *,
    device_model: str,
    ingestion: IngestionResult | None,
    prior_incidents: list[str] | None = None,
) -> MemoryCitationTrail:
    """Assemble the Supermemory citation block for the incident memo."""
    if ingestion is None:
        return MemoryCitationTrail(
            space=device_container_tag(device_model),
            prior_incidents=tuple(prior_incidents or ()),
        )
    return MemoryCitationTrail(
        space=ingestion.collection_id or device_container_tag(device_model),
        source_doc_id=ingestion.source_doc_id,
        item_ids=tuple(ingestion.item_ids or ()),
        prior_incidents=tuple(prior_incidents or ()),
    )


def _summarize_memory_record(record: dict) -> str:
    """Flatten a search hit into a one-line citation-friendly summary."""
    from services.supermemory import _record_text  # local helper, shared shape

    text = _record_text(record).strip()
    doc_id = str(
        record.get("id")
        or record.get("documentId")
        or record.get("document_id")
        or ""
    ).strip()
    if not text:
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        text = str(metadata.get("description") or "").strip()
    if not text:
        return ""
    # Enforcement payloads are JSON — pull a readable lease / CVE hint if present.
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            lease = payload.get("lease") if isinstance(payload.get("lease"), dict) else {}
            contract_b = payload.get("contract_b") if isinstance(payload.get("contract_b"), dict) else {}
            lease_id = lease.get("lease_id") or payload.get("lease_id") or ""
            cve = contract_b.get("cve_flagged") or ""
            bits = ["Prior enforcement"]
            if cve and str(cve).upper() != "NONE":
                bits.append(f"CVE {cve}")
            if lease_id:
                bits.append(f"lease {lease_id}")
            text = " — ".join(bits)
    except (json.JSONDecodeError, TypeError, ValueError):
        text = text.replace("\n", " ")[:180]
    if doc_id:
        return f"{text} [sm:{doc_id}]"
    return text


# ---------------------------------------------------------------------------
# Durable device profile — restart-safe drift baseline
# ---------------------------------------------------------------------------
# Supermemory's /v4/profile returns synthesized prose; drift needs the exact prior
# Contract A, so the structured baseline is stored as a marked document and read
# back deterministically. This is what makes drift survive a backend restart —
# the old in-memory _policy_history dict did not.
#
# The baseline is carried in the document's *metadata*, not its content: the
# /v3/documents/list endpoint returns metadata + timestamps but NOT the raw
# content, so metadata is the only field we can reliably recover on read-back.


async def save_device_profile(
    device_model: str,
    contract: ContractA,
    enforcement: dict | None = None,
) -> None:
    """Persist this scan's Contract A as the device's durable drift baseline."""
    tag = device_container_tag(device_model)
    envelope = {
        "updated_at": time.time(),
        "contract_a": contract.model_dump(),
        "enforcement": enforcement or {},
    }
    ports = ", ".join(f"{p.protocol} {p.port}" for p in contract.allowed_ports) or "none"
    content = (
        f"Drift baseline for {device_model} firmware {contract.firmware_version}; "
        f"required ports: {ports}."
    )
    try:
        await SupermemoryClient().add_document(
            content,
            container_tag=tag,
            metadata={
                "type": BASELINE_MARKER,
                "device_model": device_model,
                # Stored as a JSON string so it survives regardless of whether the
                # server preserves nested metadata objects.
                "baseline": json.dumps(envelope, separators=(",", ":")),
            },
        )
    except SupermemoryError:
        # Losing the baseline write only costs the next run's drift comparison;
        # it must never fail the enforcement run itself.
        pass


async def load_device_profile(device_model: str) -> ContractA | None:
    """Load the most recent durable Contract A baseline for a device, if any."""
    tag = device_container_tag(device_model)
    try:
        documents = await SupermemoryClient().list_documents(tag)
    except SupermemoryError:
        return None

    latest: tuple[float, dict] | None = None
    for doc in documents:
        metadata = doc.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("type") != BASELINE_MARKER:
            continue
        raw = metadata.get("baseline")
        try:
            envelope = json.loads(raw) if isinstance(raw, str) else raw
            contract_data = envelope["contract_a"]
            stamp = float(envelope.get("updated_at", 0))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
        if latest is None or stamp > latest[0]:
            latest = (stamp, contract_data)

    if latest is None:
        return None
    try:
        return ContractA(**latest[1])
    except Exception:  # noqa: BLE001 — a malformed baseline should not crash drift
        return None
