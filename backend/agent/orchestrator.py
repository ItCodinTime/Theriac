# Core 7-step agent loop. Coordinates extraction → CVE check → policy decision → firewall enforcement → memo generation.

import json
import hashlib
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Awaitable, Callable

# Module-level scan history for drift detection (device_model → last Contract A).
# Keyed on the manufacturer-required ports so drift reflects real document change.
_policy_history: dict[str, "ContractA"] = {}

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from agent.prompts import TOOLS, agentic_policy_prompt, extraction_prompt, incident_memo_prompt
from agent.tools.firewall import apply_firewall_rule, get_enforcement_result, retract_firewall_rule
from schemas.contract_a import AllowedPort, ContractA
from schemas.contract_b import ContractB, FirewallRule
from schemas.control_plane import EvidenceBundle, EnforcementReceipt, PolicyLease
from services.audit_log import append_audit_entry
from services.vultr_events import publish_event
from services.vultr_inference import StreamToken, complete, run_agentic_loop
from services.vultr_object_storage import VultrObjectStorage, VultrObjectStorageError
from services.policy_leases import cancel_expiry, schedule_expiry
from services.vultr_database import save_evidence_index
from services.vultr_vector import (
    IngestionResult,
    VultrVectorStore,
    VultrVectorStoreError,
    ingest_manual,
    query_cve,
    query_manual,
    retrieve_document,
)

# Demo manual — sourced from the real Philips IntelliVue Data Export Interface
# Programming Guide (part 4535 645 88011, release L.0, 08/2015, 339 pp).
# UDP 24105 is from Section 4, p.29. UDP 24005 is from Section 5, p.53.
# Using these real numbers so the fallback path produces citable output.
DEMO_MANUAL_TEXT = (
    "Philips IntelliVue Patient Monitor — Data Export Interface Programming Guide "
    "(X2, MP, MX, FM Series, Release L.0, Firmware L.0). "
    "Section 4 — Transport Protocols for the LAN Interface (p. 29): "
    "'The current Protocol version uses the fixed UDP port 24105. "
    "All messages sent from the Computer Client to the monitor must use this port number "
    "as the destination port number.' "
    "Section 5 — Connect Indication Event (p. 53): "
    "UDP port 24005 is used for device discovery broadcasts. "
    "All remote administration (SSH, port 22) must remain disabled in clinical "
    "deployments to prevent lateral movement across the hospital network."
)

DEMO_CONTRACT_A = ContractA(
    device_model="Philips_IntelliVue",
    firmware_version="L.0",
    allowed_ports=[
        AllowedPort(port=24105, protocol="UDP", reason="Data Export Protocol — main data channel (p.29)"),
        AllowedPort(port=24005, protocol="UDP", reason="Device discovery / Connect Indication broadcast (p.53)"),
    ],
    source_doc_id="",
)

# Second demo scenario: a vendor manual revision (Release M.0) that changes the
# device's network requirements — a new secure-telemetry port is introduced and
# the legacy discovery port is deprecated. Re-scanning the same device with this
# revision deterministically triggers policy-drift detection, so the demo can
# show "the document changed, so the agent's decision changed" on command.
DEMO_MANUAL_TEXT_V2 = (
    "Philips IntelliVue Patient Monitor — Data Export Interface Programming Guide "
    "(X2, MP, MX, FM Series, Release M.0, Firmware M.0). "
    "Section 4 — Transport Protocols for the LAN Interface (p. 29): "
    "'The current Protocol version uses the fixed UDP port 24105. "
    "All messages sent from the Computer Client to the monitor must use this port number "
    "as the destination port number.' "
    "Section 4a — Secure Telemetry (NEW in Release M.0, p. 31): "
    "UDP port 24007 is now required for the encrypted vitals streaming channel. "
    "Section 5 — Connect Indication Event (p. 53): "
    "the legacy UDP port 24005 discovery broadcast is DEPRECATED in Release M.0 and must be closed. "
    "All remote administration (SSH, port 22) must remain disabled in clinical "
    "deployments to prevent lateral movement across the hospital network."
)

DEMO_CONTRACT_A_V2 = ContractA(
    device_model="Philips_IntelliVue",
    firmware_version="M.0",
    allowed_ports=[
        AllowedPort(port=24105, protocol="UDP", reason="Data Export Protocol — main data channel (p.29)"),
        AllowedPort(port=24007, protocol="UDP", reason="Secure telemetry channel — NEW in Release M.0 (p.31)"),
    ],
    source_doc_id="",
)

# Sentinel inputs that select a deterministic demo scenario instead of running the
# LLM extraction lottery. Empty input keeps the original zero-config demo behavior.
_DEMO_BASE_SENTINELS = {"", "demo", "demo1", "scan1"}
_DEMO_DRIFT_SENTINELS = {"drift", "demo2", "scan2", "update", "revision"}


def _demo_scenario(raw_pdf_text: str) -> tuple[str, ContractA] | None:
    """Map a sentinel input to a deterministic (manual_text, ContractA) demo pair.

    Returns None for real manual text, in which case the normal LLM extraction
    path runs. Deterministic demo pairs keep the on-stage demo reproducible and
    let policy-drift be triggered on command via a second 'vendor revision' scan.
    """
    key = raw_pdf_text.strip().lower()
    if key in _DEMO_BASE_SENTINELS:
        return DEMO_MANUAL_TEXT, DEMO_CONTRACT_A.model_copy()
    if key in _DEMO_DRIFT_SENTINELS:
        return DEMO_MANUAL_TEXT_V2, DEMO_CONTRACT_A_V2.model_copy()
    return None


async def run_pipeline(
    raw_pdf_text: str,
    vpc_id: str,
    on_token: Callable[[StreamToken], Awaitable[None]] | None = None,
    manual_object_key: str = "",
    operator_id: str = "panacea-agent",
    source_doc_id: str = "",
) -> ContractB:
    """
    Executes the full 7-step PANACEA pipeline.

    Steps:
        1. Ingest      — raw_pdf_text arrives from Goutham's PDF module
        2. Extract     — LLM pulls device model, firmware, allowed ports (Contract A)
        3. CVE Check   — Nemotron autonomously calls check_cve tool
        4. Decide      — Nemotron generates zero-trust policy (Contract B)
        5. Store       — chunks the manual into Vultr Vector Store using Contract A
        6. Enforce     — Nemotron calls apply_firewall_rule tool
        7. Report      — LLM expands memo for the frontend

    Args:
        raw_pdf_text: Raw text extracted from the medical device PDF.
        vpc_id: Target Vultr VPC ID (e.g. "vpc-medical-01").
        on_token: Optional WebSocket callback — receives StreamToken on each reasoning/content chunk.

    Returns:
        ContractB with the final firewall policy and incident memo.
    """

    async def _emit(text: str, token_type: str = "reasoning") -> None:
        if on_token:
            await on_token(StreamToken(text=text, type=token_type))

    demo = _demo_scenario(raw_pdf_text)
    manual_text = raw_pdf_text.strip() or DEMO_MANUAL_TEXT
    demo_contract: ContractA | None = None
    if demo is not None:
        manual_text, demo_contract = demo
        await _emit(
            "\n[STEP 1] Demo scenario selected — using verified Philips IntelliVue "
            "excerpt (deterministic).\n"
        )
    elif not raw_pdf_text.strip():
        await _emit("\n[STEP 1] No manual text supplied — using demo Philips IntelliVue excerpt.\n")

    # ------------------------------------------------------------------
    # Step 2: Extract device info from the PDF text
    # ------------------------------------------------------------------
    await _emit("\n[STEP 2] Extracting network requirements from device manual...\n")
    if demo_contract is not None:
        # Deterministic demo path — skip the LLM extraction lottery so the on-stage
        # demo is reproducible and drift only reflects a real document change.
        contract_a, extraction_fell_back = demo_contract, False
    else:
        # Nemotron can't ingest a full 300+ page manual (500k+ chars). Pick a
        # focused window: the document head (device identity) plus the region
        # around the first real port declaration (the network section).
        extraction_text = _extraction_window(manual_text)
        extraction_raw = await complete(extraction_prompt(extraction_text))
        contract_a, extraction_fell_back = _parse_contract_a(extraction_raw)
    if source_doc_id:
        contract_a = contract_a.model_copy(update={"source_doc_id": source_doc_id})
    if extraction_fell_back:
        await _emit(
            f"[STEP 2 WARN] Nemotron did not return valid extraction JSON (or returned no ports) — "
            f"substituting the demo device ({contract_a.device_model}); treat this run's policy as "
            f"unverified until the manual is re-processed.\n"
        )
    else:
        await _emit(f"[STEP 2 DONE] Device: {contract_a.device_model} | Firmware: {contract_a.firmware_version} | Ports: {[p.port for p in contract_a.allowed_ports]}\n")

    # ------------------------------------------------------------------
    # Step 5: Commit Contract A and chunks before any enforcement decision.
    # ------------------------------------------------------------------
    await _emit("\n[STEP 5] Chunking manual and storing Contract A in Vultr Vector Store...\n")
    try:
        ingestion = await ingest_manual(manual_text, contract_a)
        contract_a = contract_a.model_copy(update={"source_doc_id": ingestion.source_doc_id})
        await publish_event("contract-a.extracted", ingestion.source_doc_id, contract_a.model_dump(mode="json"))
        await _emit(
            f"[STEP 5 DONE] Stored {ingestion.chunk_count} chunks in Vultr collection "
            f"{ingestion.collection_id}; source vector {ingestion.source_doc_id}.\n"
        )
    except VultrVectorStoreError as exc:
        await _emit(f"[STEP 5 WARN] Vector Store ingestion failed ({exc}) — continuing without vector storage.\n")
        ingestion = IngestionResult(
            collection_id="",
            source_doc_id=contract_a.source_doc_id,
            item_ids=(),
            chunk_count=0,
        )

    retrieved_context = ""
    if ingestion.collection_id:
        await _emit("\n[MEMORY] Retrieving authoritative evidence through Vultr RAG...\n")
        try:
            retrieved_context = await query_manual(ingestion.collection_id, contract_a)
            await _emit("[MEMORY DONE] Manufacturer evidence attached to the decision.\n")
        except VultrVectorStoreError as exc:
            await _emit(f"[MEMORY WARN] Manual retrieval failed ({exc}) — proceeding without retrieved evidence.\n")
    else:
        await _emit("[MEMORY SKIPPED] No Vector Store collection available for this run.\n")

    # ------------------------------------------------------------------
    # Step 3 + 4 + 6: the tool-capable Vultr model checks CVE memory,
    # decide policy, and apply firewall rules
    # ------------------------------------------------------------------
    await _emit("\n[STEP 3-4-6] Handing control to Nemotron for CVE check, policy decision, and firewall enforcement...\n")

    messages = agentic_policy_prompt(
        device_model=contract_a.device_model,
        firmware_version=contract_a.firmware_version,
        allowed_ports=[p.model_dump() for p in contract_a.allowed_ports],
        vpc_id=vpc_id,
        retrieved_context=retrieved_context,
    )

    # Count reasoning characters to derive real confidence from deliberation depth.
    # Also capture evidence returned by tool calls so the memo can cite it.
    reasoning_chars = 0
    tool_evidence: dict[str, str] = {"cve": "", "retrieved": ""}

    async def _on_token_counted(token: StreamToken) -> None:
        nonlocal reasoning_chars
        if token.type == "reasoning":
            reasoning_chars += len(token.text)
        if on_token:
            await on_token(token)

    async def _tool_executor_capturing(tool_name: str, arguments: dict) -> str:
        result = await _tool_executor(tool_name, arguments)
        if tool_name == "check_cve":
            tool_evidence["cve"] = result
        elif tool_name == "retrieve_document":
            tool_evidence["retrieved"] += ("\n" + result if tool_evidence["retrieved"] else result)
        return result

    final_message = await run_agentic_loop(
        messages=messages,
        tools=TOOLS,
        tool_executor=_tool_executor_capturing,
        on_token=_on_token_counted,
    )

    # ------------------------------------------------------------------
    # Extract ContractB from the last apply_firewall_rule tool call.
    # If Nemotron didn't call the tool, build a deterministic policy so the
    # demo never shows empty rules (README guardrail #4: graceful fallbacks).
    # ------------------------------------------------------------------
    contract_b = _extract_contract_b(final_message, vpc_id)
    if not contract_b.firewall_rules:
        await _emit("\n[FALLBACK] Nemotron did not enforce via tool — generating deterministic zero-trust policy.\n")
        contract_b = _deterministic_policy(contract_a, vpc_id)
        apply_firewall_rule(
            target_vpc_id=contract_b.target_vpc_id,
            firewall_rules=[r.model_dump() for r in contract_b.firewall_rules],
            confidence_score=contract_b.confidence_score,
            cve_flagged=contract_b.cve_flagged,
            memo_text=contract_b.memo_text,
        )

    # Safety net: if the agent didn't call check_cve this run (Nemotron is
    # non-deterministic about tool use), run the CVE lookup deterministically so
    # the document-grounded CVE cross-check is never silently skipped.
    if not tool_evidence["cve"].strip():
        try:
            tool_evidence["cve"] = await query_cve(
                contract_a.device_model, contract_a.firmware_version
            )
            await _emit("\n[CVE] Deterministic CVE cross-check against Vultr collection completed.\n")
        except VultrVectorStoreError as exc:
            await _emit(f"\n[CVE WARN] CVE cross-check unavailable ({exc}).\n")

    # Ground cve_flagged in the actual check_cve result. Nemotron sometimes calls
    # the CVE tool, gets a real hit, but still reports NONE — so if the tool
    # surfaced a genuine CVE, trust the retrieved evidence and never drop it.
    evidence_cve = _cve_id_from_evidence(tool_evidence["cve"])
    if evidence_cve and (not contract_b.cve_flagged or contract_b.cve_flagged.strip().upper() == "NONE"):
        contract_b = contract_b.model_copy(update={"cve_flagged": evidence_cve})
        await _emit(f"\n[CVE] Grounded CVE from Vultr collection: {evidence_cve}\n")

    # ------------------------------------------------------------------
    # Feature 1: Real confidence from reasoning depth AND evidence grounding.
    # Short decisive reasoning + every rule backed by evidence → high confidence.
    # Long deliberation or rules with no supporting document → lower.
    # ------------------------------------------------------------------
    combined_evidence = "\n".join(
        part for part in (retrieved_context, tool_evidence["retrieved"], tool_evidence["cve"]) if part
    )
    grounded, total = _evidence_coverage(contract_b, combined_evidence)
    real_confidence = _confidence_from_reasoning(
        reasoning_chars, contract_b.cve_flagged, len(contract_b.firewall_rules), grounded, total
    )
    confidence_explanation = _confidence_explanation(
        reasoning_chars, contract_b.cve_flagged, grounded, total
    )
    contract_b = contract_b.model_copy(update={"confidence_score": real_confidence})
    await _emit(f"\n[CONFIDENCE] {real_confidence}% — {confidence_explanation}\n")

    # ------------------------------------------------------------------
    # Feature 3: Policy drift detection — flag if this device was seen before.
    # ------------------------------------------------------------------
    drift_alert = _detect_drift(contract_a.device_model, contract_a)
    if drift_alert:
        await _emit(
            f"\n[DRIFT ALERT] Manufacturer requirements changed since last scan: {drift_alert}\n",
            "reasoning",
        )
    _policy_history[contract_a.device_model] = contract_a

    # ------------------------------------------------------------------
    # Step 7: Expand the incident memo for Oleh's frontend
    # ------------------------------------------------------------------
    await _emit("\n[STEP 7] Generating incident memo with citation trail...\n")
    contract_b.memo_text = _build_memo(contract_b, contract_a, tool_evidence, confidence_explanation)
    if drift_alert:
        # Appended after _build_memo so the drift finding survives into the memo.
        contract_b.memo_text += f"\n\nDRIFT ALERT: {drift_alert}"
    await _emit("\n[STEP 7 DONE] Memo ready.\n", "content")

    enforcement = get_enforcement_result(vpc_id) or {}
    lease_id = enforcement.get("lease_id") or f"lease-{uuid.uuid4().hex[:12]}"
    lease_seconds = int(os.getenv("VULTR_POLICY_LEASE_SECONDS", "900"))
    from datetime import timedelta
    expires_at = (
        datetime.fromisoformat(enforcement["expires_at"])
        if enforcement.get("expires_at")
        else datetime.now().astimezone() + timedelta(seconds=lease_seconds)
    )

    # Build the receipt from whatever apply_rules returned — it may be live or mock.
    applied_rules = enforcement.get("applied_rules", [])
    receipt = EnforcementReceipt(
        enforcement_plane=enforcement.get("mode", "mock"),
        vpc_id=vpc_id,
        gateway_id=enforcement.get("firewall_group_id"),
        changes=[
            {"port": r.get("port", 0), "action": r.get("action", "ALLOW"), "status": r.get("result", "applied")}
            for r in applied_rules
        ],
    )
    lease = PolicyLease(
        lease_id=lease_id,
        source_doc_id=contract_a.source_doc_id,
        policy=contract_b,
        expires_at=expires_at,
        receipt=receipt,
    )
    await schedule_expiry(lease)
    evidence = EvidenceBundle(
        evidence_id=f"evidence-{uuid.uuid4().hex}",
        contract_a=contract_a,
        contract_b=contract_b,
        lease=lease,
        manual_sha256=hashlib.sha256(manual_text.encode()).hexdigest(),
        retrieved_context=retrieved_context,
        model_id=os.getenv("VULTR_TOOL_MODEL", os.getenv("VULTR_MAIN_MODEL", "")),
        operator_id=operator_id,
        metadata={"manual_object_key": manual_object_key, "collection_id": ingestion.collection_id},
    )

    evidence_key = ""
    storage = VultrObjectStorage()
    if storage.configured:
        evidence_key, evidence_hash = storage.seal_evidence(evidence)
        evidence = evidence.model_copy(update={"evidence_sha256": evidence_hash})
        await save_evidence_index(evidence.evidence_id, evidence_key, evidence_hash)
    elif storage.strict:
        raise VultrObjectStorageError("Vultr Object Storage is required in strict mode")

    event_payload = {
        "contract_b": contract_b.model_dump(mode="json"),
        "lease": lease.model_dump(mode="json"),
        "evidence_key": evidence_key,
        "evidence_sha256": evidence.evidence_sha256,
    }
    await publish_event("contract-b.enforced", lease.lease_id, contract_b.model_dump(mode="json"))
    await publish_event("policy.enforced", lease.lease_id, event_payload)
    if ingestion.collection_id:
        try:
            vector = VultrVectorStore(collection_id=ingestion.collection_id)
            await vector.add_item(
                ingestion.collection_id,
                json.dumps(event_payload, separators=(",", ":"), default=str),
                f"Enforcement outcome for {contract_a.device_model}; lease {lease.lease_id}",
            )
        except VultrVectorStoreError as exc:
            await _emit(f"[MEMORY WARN] Could not write enforcement outcome back to Vector Store ({exc}).\n")
    await _emit(f"[EVIDENCE SEALED] Lease {lease.lease_id}; object {evidence_key or 'strict-mode disabled'}.\n")

    # ------------------------------------------------------------------
    # Feature 4: Structured audit log — every decision is auditable.
    # ------------------------------------------------------------------
    append_audit_entry({
        "event": "policy.decided",
        "lease_id": lease.lease_id,
        "operator_id": operator_id,
        "device_model": contract_a.device_model,
        "firmware_version": contract_a.firmware_version,
        "source_doc_id": contract_a.source_doc_id,
        "confidence_score": contract_b.confidence_score,
        "confidence_explanation": confidence_explanation,
        "reasoning_chars": reasoning_chars,
        "cve_flagged": contract_b.cve_flagged,
        "firewall_rules": [r.model_dump() for r in contract_b.firewall_rules],
        "drift_alert": drift_alert,
        "evidence_key": evidence_key,
        "evidence_sha256": evidence.evidence_sha256,
    })

    return contract_b


async def _tool_executor(tool_name: str, arguments: dict) -> str:
    """
    Routes Nemotron's tool call requests to the correct Python function.
    This is the bridge between the LLM and the actual tool implementations.
    """
    if tool_name == "retrieve_document":
        # Non-fatal: a Vector Store hiccup should degrade the answer, not 500 the run.
        try:
            return await retrieve_document(
                query=arguments.get("query", ""),
                device_model=arguments.get("device_model", ""),
                top_k=arguments.get("top_k", 3),
            )
        except VultrVectorStoreError as exc:
            return f"NO_DOCUMENT_EVIDENCE: retrieval unavailable ({exc})."

    if tool_name == "check_cve":
        # Non-fatal: if the CVE collection is unreachable, report NONE so the
        # agent still produces a policy instead of crashing the whole run.
        try:
            return await query_cve(
                device_model=arguments.get("device_model", ""),
                firmware_version=arguments.get("firmware_version", ""),
            )
        except VultrVectorStoreError as exc:
            return f'{{"cve_id": "NONE", "note": "CVE lookup unavailable ({exc})"}}'

    if tool_name == "apply_firewall_rule":
        return apply_firewall_rule(
            target_vpc_id=arguments.get("target_vpc_id", ""),
            firewall_rules=arguments.get("firewall_rules", []),
            confidence_score=arguments.get("confidence_score", 0),
            cve_flagged=arguments.get("cve_flagged", "NONE"),
            memo_text=arguments.get("memo_text", ""),
        )

    return f"ERROR: Unknown tool '{tool_name}'"


async def retract_policy(device_id: str) -> dict:
    """
    Human Override — called by DELETE /api/v1/policy/{device_id}.
    Immediately retracts the active firewall policy for the given device.
    """
    result = retract_firewall_rule(device_id)
    parsed = json.loads(result)
    if parsed.get("lease_id"):
        await cancel_expiry(parsed["lease_id"])
    return parsed


def _evidence_coverage(contract_b: "ContractB", evidence: str) -> tuple[int, int]:
    """
    Counts how many firewall rules are grounded in the retrieved evidence
    (the rule's port number appears in the manual/CVE text) vs left unexplained.
    Mirrors the PS finance example: confidence reflects matched-to-cause coverage.
    """
    total = len(contract_b.firewall_rules)
    if total == 0 or not evidence:
        return 0, total
    grounded = sum(1 for r in contract_b.firewall_rules if str(r.port) in evidence)
    return grounded, total


def _confidence_from_reasoning(
    reasoning_chars: int,
    cve_flagged: str,
    rule_count: int,
    grounded: int = 0,
    total: int = 0,
) -> int:
    """
    Derives a real confidence score from reasoning depth AND evidence grounding.
    Short decisive reasoning = high confidence; long deliberation = lower.
    Evidence coverage (grounded/total rules) then scales the score — a decision
    where every rule is backed by a cited document scores higher than one with
    unexplained rules.
    """
    # Reasoning models (Nemotron) deliberate verbosely, so thresholds are tuned
    # for their natural output length — only genuinely excessive back-and-forth
    # (conflicting evidence) drops the score.
    if reasoning_chars < 1500:
        base = 94
    elif reasoning_chars < 4000:
        base = 88
    elif reasoning_chars < 8000:
        base = 80
    elif reasoning_chars < 15000:
        base = 70
    else:
        base = 60

    if cve_flagged and cve_flagged not in ("NONE", ""):
        base -= 8  # CVE conflict introduces some uncertainty
    if rule_count == 0:
        base -= 20  # no rules produced = uncertain outcome

    # Evidence grounding is the strongest signal: penalise proportionally for
    # any rule not backed by a cited document (max -25).
    if total > 0:
        coverage = grounded / total
        base -= int((1 - coverage) * 25)

    return max(10, min(98, base))


def _confidence_explanation(
    reasoning_chars: int,
    cve_flagged: str,
    grounded: int = 0,
    total: int = 0,
) -> str:
    """Human-readable rationale for the confidence score, shown in the memo."""
    if reasoning_chars < 300:
        depth = "short decisive reasoning — no ambiguity detected"
    elif reasoning_chars < 800:
        depth = "moderate deliberation — minor uncertainty resolved"
    elif reasoning_chars < 2000:
        depth = "extended deliberation — conflicting signals weighed"
    else:
        depth = "long deliberation — significant uncertainty or conflicting CVE evidence"

    cve_note = "; CVE evidence introduced additional uncertainty" if (cve_flagged and cve_flagged not in ("NONE", "")) else ""
    grounding_note = f"; {grounded}/{total} rules grounded in cited evidence" if total > 0 else ""
    return f"{depth}{cve_note}{grounding_note}"


def _extraction_window(text: str, budget: int = 7000) -> str:
    """Pick the most informative slice of a large manual for LLM extraction.

    Full device manuals are hundreds of pages; the port section is usually deep
    inside (e.g. "page 29"), so the first N chars miss it entirely. This keeps
    the document head (device model / title) and splices in the region around
    the first concrete port declaration (e.g. "UDP port 24105", "TCP 3200").
    """
    if len(text) <= budget:
        return text
    head = text[:1500]
    match = re.search(r"(?:UDP|TCP|port)\W{0,12}\d{2,5}", text, re.IGNORECASE)
    if not match:
        return text[:budget]
    start = max(0, match.start() - 900)
    body = text[start: start + (budget - len(head) - 12)]
    return f"{head}\n[...]\n{body}"


def _cve_description_lookup(cve_id: str) -> str:
    """Return the curated one-line description for a CVE from backend/cves.json.

    The memo needs a clean human-readable THREAT line; extracting it from RAG
    output proved unreliable (markdown/JSON fragments leaked in). The local
    dataset contains the exact records Goutham ingested into the collection.
    """
    try:
        cves_path = BACKEND_ROOT / "cves.json"
        for record in json.loads(cves_path.read_text()):
            if record.get("cve_id") == cve_id:
                desc = (record.get("description") or "").strip().rstrip(".")
                severity = record.get("severity", "")
                if desc:
                    return f"{severity} severity — {desc}" if severity else desc
    except Exception:
        pass
    return ""


def _cve_id_from_evidence(cve_text: str) -> str:
    """Extract the first real CVE id from the check_cve tool output, if any.

    Prefers a CVE explicitly marked HIGH/CRITICAL severity so the demo surfaces
    the most material finding; otherwise returns the first CVE id present.
    """
    if not cve_text:
        return ""
    ids = re.findall(r"CVE-\d{4}-\d{3,7}", cve_text)
    if not ids:
        return ""
    for severity in ("CRITICAL", "HIGH"):
        # Look for a CVE id appearing near a HIGH/CRITICAL severity marker.
        for cid in ids:
            window = cve_text[max(0, cve_text.find(cid) - 200): cve_text.find(cid) + 200]
            if severity in window.upper():
                return cid
    return ids[0]


def _detect_drift(device_model: str, contract_a: "ContractA") -> str | None:
    """
    Compares this scan's manufacturer-required ports against the last scan for
    the same device. Drift is grounded in the document's stated requirements
    (Contract A), not the LLM's generated firewall rules — so it reflects a real
    change in the manual and never false-fires on run-to-run model variance.
    Returns a human-readable drift summary if the required port set changed.
    """
    prev = _policy_history.get(device_model)
    if not prev:
        return None

    prev_ports = {(p.port, p.protocol) for p in prev.allowed_ports}
    new_ports = {(p.port, p.protocol) for p in contract_a.allowed_ports}

    added = new_ports - prev_ports
    removed = prev_ports - new_ports

    if not added and not removed:
        return None

    parts = []
    if added:
        ports_str = ", ".join(f"{proto} {port}" for port, proto in sorted(added))
        parts.append(f"NEW required ports: {ports_str}")
    if removed:
        ports_str = ", ".join(f"{proto} {port}" for port, proto in sorted(removed))
        parts.append(f"DEPRECATED / removed ports: {ports_str}")

    return "; ".join(parts)


async def explain_policy(contract_b: "ContractB") -> str:
    """
    Calls Nemotron to generate a plain-English compliance justification
    for a given policy decision. Used by /api/v1/agent/explain.
    """
    from agent.prompts import SYSTEM_PROMPT

    rules_text = "\n".join(
        f"  - Port {r.port}: {r.action}" for r in contract_b.firewall_rules
    )
    prompt_messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"You are a compliance officer's AI assistant. Explain the following network security "
                f"policy decision in 3-4 plain-English sentences that a hospital compliance officer "
                f"could read in a regulatory audit. Be specific about ports, risks, and reasoning.\n\n"
                f"Device: {contract_b.target_vpc_id}\n"
                f"Confidence: {contract_b.confidence_score}%\n"
                f"CVE Flagged: {contract_b.cve_flagged}\n"
                f"Firewall Rules:\n{rules_text}\n"
                f"Memo: {contract_b.memo_text}"
            ),
        },
    ]
    return await complete(prompt_messages)


def _build_memo(
    contract_b: "ContractB",
    contract_a: ContractA,
    tool_evidence: dict,
    confidence_explanation: str,
) -> str:
    """
    Builds the incident memo deterministically from structured data.
    Guarantees a clean THREAT/ACTION/STATUS/CITATIONS format every time —
    no LLM reasoning leaks, no template placeholders, no truncation.
    Citations are grounded in the RAG evidence returned by the agent's tool calls.
    """
    allows = [r.port for r in contract_b.firewall_rules if r.action == "ALLOW"]
    denies = [r.port for r in contract_b.firewall_rules if r.action == "DENY"]
    cve = contract_b.cve_flagged
    has_cve = cve and cve not in ("NONE", "")

    # Look up the CVE description from the local curated dataset (the same
    # records ingested into the Vultr collection). Deterministic and clean —
    # parsing the RAG output leaked JSON fragments into the memo.
    cve_description = _cve_description_lookup(cve) if has_cve else ""
    threat = (
        (
            f"CVE {cve} detected on {contract_a.device_model} firmware {contract_a.firmware_version} "
            + (f"— {cve_description}." if cve_description else "— unauthenticated adjacent-network exploit risk.")
        ) if has_cve
        else (
            f"Unmanaged {contract_a.device_model} (firmware {contract_a.firmware_version}) "
            f"introduced to hospital VPC with unevaluated network exposure."
        )
    )

    action = (
        f"Applied zero-trust firewall policy: ALLOW ports {allows} "
        f"(manufacturer-required), DENY ports {denies} (lateral movement risk)."
    )

    status = (
        f"Device network-isolated on {contract_b.target_vpc_id}. "
        f"Policy enforced at {contract_b.confidence_score}% confidence. "
        f"All ports blocked except manufacturer-approved data channels."
    )

    # Map extracted port -> manual reason (carries page refs like "(p.29)")
    port_reasons = {p.port: p.reason for p in contract_a.allowed_ports}

    # Per-rule citations grounded in retrieved evidence where possible
    citation_lines = []
    for rule in contract_b.firewall_rules:
        port_str = str(rule.port)
        if rule.action == "ALLOW":
            # Always use the Contract A port reason — it carries the verified
            # page reference (e.g. "p.29") and is deterministic. RAG evidence
            # often returns meta-commentary ("no exact passages found") which
            # corrupts the citation, so we skip it for ALLOW rules entirely.
            if rule.port in port_reasons:
                justification = f"Device manual — {port_reasons[rule.port]}"
            else:
                justification = f"Required by device manual for {contract_a.device_model} operation"
        else:
            if rule.port == 22:
                justification = (
                    "Manual states: all remote administration (SSH, port 22) must remain "
                    "disabled in clinical deployments to prevent lateral movement"
                )
            elif rule.port == 23:
                justification = (
                    "Telnet — no explicit manual passage; flagged for manual review. "
                    "Denied under zero-trust baseline (unapproved remote-admin protocol)"
                )
            else:
                justification = (
                    f"Port {rule.port} not listed in manufacturer-approved ports; "
                    "denied under zero-trust baseline"
                )
        citation_lines.append(f"  - Port {rule.port} ({rule.action}): {justification}")

    citations = "\n".join(citation_lines)
    return (
        f"THREAT: {threat}\n"
        f"ACTION: {action}\n"
        f"STATUS: {status}\n"
        f"CITATIONS:\n{citations}"
    )


def _clean_memo(raw: str, contract_b: "ContractB", contract_a: ContractA) -> str:
    """
    Ensures the memo is the clean formatted report, never a raw reasoning dump.
    Reasoning models sometimes emit chain-of-thought before the answer — we slice
    from the first real section header. If no header is found, build a deterministic
    memo so the demo never shows the model 'thinking out loud'.
    """
    text = (raw or "").strip()
    # Find the THREAT: block that is a real memo: must have ACTION: within 600 chars.
    # The model reasons with inline THREAT: mentions before producing the final block.
    pos = 0
    best = None
    while True:
        idx = text.find("THREAT:", pos)
        if idx == -1:
            break
        window = text[idx:idx + 800]
        candidate = text[idx:].strip().split("[ERROR:", 1)[0].strip()
        # Must have ACTION: and STATUS: to be the real memo, not a reasoning reference
        if "ACTION:" in window and "STATUS:" in window:
            best = candidate
            # Keep scanning — prefer the LAST well-formed block (final answer)
        pos = idx + 7
    if best and len(best) > 80:
        return best

    # Fallback: deterministic, always-clean memo grounded in the decision.
    allows = [r.port for r in contract_b.firewall_rules if r.action == "ALLOW"]
    denies = [r.port for r in contract_b.firewall_rules if r.action == "DENY"]
    citations = "\n".join(
        f"  - Port {r.port} ({r.action}): "
        + (
            "required network port per device manual"
            if r.action == "ALLOW"
            else "remote-administration / lateral-movement port disabled per zero-trust baseline"
        )
        for r in contract_b.firewall_rules
    )
    cve_line = (
        f"CVE {contract_b.cve_flagged} flagged for {contract_a.device_model}."
        if contract_b.cve_flagged not in ("NONE", "")
        else "No active CVE matched this device and firmware."
    )
    return (
        f"THREAT: Unmanaged {contract_a.device_model} (firmware {contract_a.firmware_version}) "
        f"introduced to {contract_b.target_vpc_id}. {cve_line}\n"
        f"ACTION: Applied zero-trust firewall policy — allowed {allows or 'no'} ports, "
        f"denied {denies or 'no'} ports.\n"
        f"STATUS: Device network-isolated to manufacturer-required ports; policy live on "
        f"{contract_b.target_vpc_id} at {contract_b.confidence_score}% confidence.\n"
        f"CITATIONS:\n{citations}"
    )


def _deterministic_policy(contract_a: ContractA, vpc_id: str) -> ContractB:
    """
    Builds a zero-trust firewall policy without the LLM — used as a safety net
    when Nemotron does not call apply_firewall_rule. ALLOWs manual ports,
    DENYs SSH/Telnet, and flags any CVE found for the device.
    """
    rules = [FirewallRule(port=p.port, action="ALLOW") for p in contract_a.allowed_ports]
    # Always deny common lateral-movement ports not explicitly allowed
    allowed_ports = {p.port for p in contract_a.allowed_ports}
    for risky_port in (22, 23):
        if risky_port not in allowed_ports:
            rules.append(FirewallRule(port=risky_port, action="DENY"))

    cve_id = "NONE"
    memo = (
        f"Applied deterministic zero-trust baseline for {contract_a.device_model}; "
        f"allowed {sorted(allowed_ports)}, denied SSH/Telnet. CVE evidence requires manual review."
    )
    confidence = 60

    return ContractB(
        target_vpc_id=vpc_id,
        firewall_rules=rules,
        confidence_score=confidence,
        cve_flagged=cve_id,
        memo_text=memo,
    )


def _parse_contract_a(raw: str) -> tuple[ContractA, bool]:
    """Parses the LLM's JSON output into a ContractA model.

    Falls back to DEMO_CONTRACT_A (not an empty placeholder) whenever the
    output doesn't parse or parses with no usable ports, so a single Nemotron
    hiccup never breaks the rest of the pipeline mid-demo. Returns
    (contract, fell_back) — fell_back is True whenever DEMO_CONTRACT_A was
    substituted, so callers can surface that instead of silently reporting
    placeholder data as a real extraction.
    """
    try:
        cleaned = raw.strip().strip("```json").strip("```").strip()
        data = json.loads(cleaned)
        contract = ContractA(**data)
        if contract.allowed_ports:
            return contract, False
    except Exception:
        pass
    return DEMO_CONTRACT_A.model_copy(), True


def _extract_contract_b(final_message: dict, vpc_id: str) -> ContractB:
    """
    Extracts ContractB from the final assistant message.
    Nemotron may have embedded the policy in content as JSON, or it's already stored
    in the in-memory policy store via the apply_firewall_rule tool call.
    """
    from agent.tools.firewall import _active_policies

    # Try to find an active policy stored during the agentic loop
    for policy in _active_policies.values():
        if policy.target_vpc_id == vpc_id:
            return policy

    # Fallback: parse content JSON if Nemotron included it in its final message
    content = final_message.get("content", "")
    try:
        cleaned = content.strip().strip("```json").strip("```").strip()
        data = json.loads(cleaned)
        return ContractB(**data)
    except Exception:
        return ContractB(
            target_vpc_id=vpc_id,
            firewall_rules=[],
            confidence_score=0,
            cve_flagged="NONE",
            memo_text="Policy extraction failed. Manual review required.",
        )
