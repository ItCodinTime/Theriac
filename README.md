<div align="center">

# THERIAC

### The Zero-Trust Immune System for Hospital Networks

**An autonomous, document-grounded AI agent that reads medical device manuals, hunts vulnerabilities, and programs live firewalls — without ever touching the physical device.**

<br/>

[![Vultr](https://img.shields.io/badge/Powered%20by-Vultr-007BFC?style=for-the-badge&logo=vultr&logoColor=white)](https://www.vultr.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=next.js&logoColor=white)](https://nextjs.org/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

<br/>


*"A single retrieve-then-answer call is not enough. The keyword is agent."*

</div>

---

## The Problem

Hospitals run thousands of connected medical devices — patient monitors, infusion pumps, imaging machines — each with its own firmware, its own network requirements, and its own known vulnerabilities. A single compromised IntelliVue monitor is a lateral-movement launchpad into the entire clinical network.

Today, securing these devices is **manual, slow, and error-prone**: a human reads a 200-page PDF manual, cross-references CVE databases, and hand-writes firewall rules. It doesn't scale, and it doesn't happen in real time.

## The Solution

**THERIAC is an autonomous security agent that does the whole job itself.** Drop in a device manual and it will:

1. **Read** the manufacturer PDF and extract every network requirement
2. **Plan** its investigation, then **retrieve** grounding evidence — more than once, when it needs to
3. **Cross-check** known CVEs for that exact device and firmware version
4. **Decide** a zero-trust firewall policy, resolving conflicts between what the manual requires and what the CVEs forbid
5. **Enforce** it live on a Vultr Cloud Firewall — real ALLOW/DENY rules on a real VPC
6. **Report** an auditable incident memo with a per-rule citation trail and an explainable confidence score

> **The pitch:** an auto-generated, compliance-safe immune system that operates entirely at the network layer — no agents installed, no device firmware touched, fully HIPAA-aligned with zero data egress.

---

## What Makes THERIAC Win

| Capability | Why it matters | Where |
|---|---|---|
| **True multi-step agent** | Plans → retrieves → checks CVEs → re-retrieves on conflict → decides → enforces. Not a one-shot RAG call. | `agent/orchestrator.py` |
| **Per-rule citation trail** | Every ALLOW/DENY in the memo is grounded in a cited manual passage or CVE record. No fabrication. | `agent/prompts.py` |
| **Explainable confidence** | Score derived from reasoning depth and evidence coverage — e.g. `82% — 3/4 rules grounded in cited evidence`. | `orchestrator.py` |
| **Ontology-aware memory graph** | Supermemory tracks `device → firmware → port → CVE` edges and resolves manual-requires-vs-CVE-forbids conflicts as first-class facts — retrieval is a graph, not flat vector similarity. | `services/memory.py` |
| **Durable, restart-safe drift** | Per-device profiles persist in the local Supermemory graph, so "what changed since last scan" survives a backend restart — a continuous immune system, not a one-shot scan. | `orchestrator.py` |
| **Multi-device orchestration** | Secure an entire fleet concurrently in one call. | `POST /agent/multi-run` |
| **Full audit log** | Every autonomous decision is written to an append-only JSONL trail — every action is auditable. | `services/audit_log.py` |
| **Live firewall enforcement** | Real Vultr Cloud Firewall rules, live-tested against a real target VM. Safe-by-default mock mode. | `services/vultr_firewall.py` |
| **Compliance justification API** | Nemotron turns any decision into plain English a compliance officer can read in an audit. | `POST /agent/explain` |

---

## Architecture

```
PDF Manual
    |
    v
[Vultr Object Storage]
    |
    v
STEP 2: Extract (Vultr Serverless Inference / Nemotron)
    |
    +--> Contract A
    |
    v
STEP 5: Store + Graph (Supermemory · local, per-device space)
    |
    v
STEP MEMORY: Hybrid Search + Rerank (grounding evidence)
    |
    v
[Agentic Loop · Nemotron]
    |
    +--(tool)--> retrieve_document --> Supermemory (device space, reranked passages)
    +--(tool)--> check_cve         --> Supermemory (cve-knowledge space + graph edges)
    +--(tool)--> apply_firewall_rule --> Vultr Cloud Firewall (live ALLOW/DENY)
    |
    v
STEP 7: Incident Memo + Citation Trail + Confidence Score
    |
    +--> Next.js Command Center (live WebSocket stream)
    +--> Object-Locked Evidence + Audit Log + Kafka Events
```

### The 7-Step Loop

| # | Step | What happens |
|---|------|--------------|
| 1 | **Ingest** | PDF uploaded to Vultr Object Storage |
| 2 | **Extract** | Serverless Inference parses ports/protocols/firmware → Contract A, streamed live |
| 3 | **Cross-Check** | Agent grounds a CVE lookup in the local Supermemory `cve-knowledge` space (graph-linked to the device) |
| 4 | **Decide & Score** | Agent generates the zero-trust policy + explainable confidence → Contract B |
| 5 | **Store** | Manual + policy stored in the device's local Supermemory space, building the memory graph (optional Vultr archive mirror) |
| 6 | **Enforce** | Policy applied to a live Vultr Cloud Firewall |
| 7 | **Report** | Cited incident memo generated and sealed as tamper-evident evidence |

---

## Tech Stack

- **Backend Orchestration** — FastAPI (Python 3.12), async agentic tool-calling loop
- **AI Compute** — Vultr Serverless Inference (NVIDIA Nemotron) — *strictly no OpenAI, for the HIPAA-compliant zero-egress pitch*
- **Memory / RAG** — self-hosted **Supermemory** graph engine, running locally with on-box embeddings — *its extraction LLM is pointed at Vultr inference, so the memory graph never leaves the host*. Vultr Vector Store is retained as the optional sealed-evidence archive tier.
- **Enforcement** — Vultr Cloud Firewall APIs + Vultr VPCs
- **Evidence & Events** — Vultr Object Storage (Object Lock) + Vultr Managed Kafka
- **Identity** — Vultr IAM / OIDC operator identity in strict mode
- **Frontend** — Next.js, React, WebSockets (real-time agent reasoning stream)

> **The pitch:** sovereign reasoning on Vultr + an on-prem memory graph. Every intelligent decision runs on Vultr inference, while the memory of the entire hospital — manuals, CVEs, per-device profiles — lives inside the hospital boundary with zero data egress. A security product you could actually ship to a hospital on sovereign infrastructure. See [`infra/supermemory/`](infra/supermemory/).

---

## Quickstart

### Backend

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env      # fill in your Vultr keys
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Health check:

```bash
curl http://localhost:8000/healthz
# {"status":"ok","service":"theriac-backend"}
```

### Frontend

```bash
cd frontend
npm install
cp .env.example .env.local   # point NEXT_PUBLIC_API_URL at your backend
npm run dev                  # http://localhost:3000
```

Live Command Center: [https://theriac-eta.vercel.app/](https://theriac-eta.vercel.app/)

### Memory engine (Supermemory)

Boot the local memory graph before running the agent — it wires Supermemory's
extraction LLM to Vultr inference while keeping embeddings and retrieval on-box:

```bash
export $(grep -v '^#' backend/.env | xargs)      # load VULTR_* vars
infra/supermemory/run-supermemory.sh             # serves http://localhost:6767
# copy the printed API key into backend/.env as SUPERMEMORY_API_KEY

python backend/scripts/ingest_cve.py backend/cves.json   # seed the CVE space
```

See [`infra/supermemory/`](infra/supermemory/) for details.

### Run the agent

```bash
curl -X POST http://localhost:8000/api/v1/agent/run \
  -H "Content-Type: application/json" \
  -d '{"raw_pdf_text": "", "vpc_id": "vpc-medical-01"}'
```

An empty `raw_pdf_text` falls back to a built-in Philips IntelliVue demo excerpt, so the pipeline always has something to reason over.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/agent/run` | Run the full 7-step pipeline for one device → Contract B |
| `POST` | `/api/v1/agent/multi-run` | Run the pipeline across up to 10 devices concurrently |
| `POST` | `/api/v1/agent/explain` | Plain-English compliance justification for a given policy |
| `GET`  | `/api/v1/agent/audit` | Last N audit-log decisions |
| `POST` | `/api/v1/manuals/run` | Upload a PDF to Object Storage, then run the pipeline |
| `DELETE` | `/api/v1/policy/{device_id}` | Human Override — instantly retract an active policy |
| `WS`   | `/ws` | Live stream of agent reasoning, tool calls, and results |
| `GET`  | `/healthz` · `/readyz` | Liveness / readiness probes |

---

## API Contracts

These JSON schemas are the seams between every module. Do not break them.

### Contract A — Extraction Output to Vultr Vector Store

```json
{
  "device_model": "Philips_IntelliVue",
  "firmware_version": "B.01",
  "allowed_ports": [
    { "port": 24105, "protocol": "UDP", "reason": "Data Export Interface (main data channel)" }
  ],
  "source_doc_id": "vultr_vector_id_12345"
}
```

### Contract B — Agent Decision to Firewall API / Incident Memo

```json
{
  "target_vpc_id": "vpc-medical-01",
  "firewall_rules": [
    { "port": 24105, "action": "ALLOW" },
    { "port": 22, "action": "DENY" }
  ],
  "confidence_score": 96,
  "cve_flagged": "CVE-2023-XXXX",
  "memo_text": "Blocked lateral pivot on Port 22. Allowed Port 24105 per Vector ID: 12345."
}
```

---

## Repository Layout

```
Theriac/
├── backend/
│   ├── agent/
│   │   ├── orchestrator.py          # the 7-step agentic loop
│   │   ├── prompts.py               # system prompt, tool schemas, plan/memo templates
│   │   └── tools/firewall.py        # firewall tool wrapper + policy store
│   ├── api/
│   │   ├── routes/                  # agent, manuals, policy, health
│   │   └── websocket.py             # live reasoning stream
│   ├── services/
│   │   ├── vultr_inference.py       # Serverless Inference client + agentic loop
│   │   ├── memory.py                # memory facade: ingest, search, CVE, drift profiles
│   │   ├── supermemory.py           # local Supermemory client (graph + hybrid search)
│   │   ├── vultr_vector.py          # legacy Vector Store — optional archive tier
│   │   ├── vultr_firewall.py        # live Cloud Firewall executor (safe-by-default)
│   │   ├── vultr_object_storage.py  # Object-Locked evidence sealing
│   │   ├── vultr_events.py          # Managed Kafka event publishing
│   │   ├── audit_log.py             # append-only JSONL decision trail
│   │   └── policy_leases.py         # expiring ALLOW leases
│   ├── schemas/                     # Contract A, Contract B, control-plane models
│   └── tools/fw.py                  # CLI: safe plan / apply firewall operations
├── frontend/                        # Next.js Command Center (live terminal + memo UI)
├── docs/manuals/                    # real sourced Philips IntelliVue manual
└── infra/                           # target VM setup, firewall runbook, attack sim
```

---

## The Agent in Action

A real run streams something like this to the Command Center:

```
[STEP 2] Extracting network requirements from device manual...
[STEP 2 DONE] Device: Philips_IntelliVue | Firmware: B.01 | Ports: [24105, 24005]
[STEP 5] Chunking manual and storing Contract A in Vultr Vector Store...
[MEMORY] Retrieving authoritative evidence through Vultr RAG...

PLAN:
  1. Confirm port 24105 is required by the manual, not just mentioned
  2. Check CVEs for IntelliVue B.01
  3. Resolve any manual-vs-CVE conflict before deciding

[TOOL CALL -> retrieve_document({'query': 'UDP 24105 Data Export', ...})]
[TOOL CALL -> check_cve({'device_model': 'Philips_IntelliVue', ...})]
[TOOL CALL -> apply_firewall_rule({...})]

[CONFIDENCE] 88% — moderate deliberation; 2/2 rules grounded in cited evidence
[STEP 7] Generating incident memo with citation trail...
[EVIDENCE SEALED] Lease lease-a1b2c3; object evidence/2026/...
```

---

## Team

| Owner | Domain | Deliverable |
|-------|--------|-------------|
| **Brian** | Agent Orchestration | Serverless Inference agent loop, citation trail, confidence scoring, drift detection, audit log, multi-run + explain APIs |
| **Goutham** | The Memory Engine | Self-hosted Supermemory graph backbone — per-device spaces, hybrid search + rerank, durable drift profiles, CVE grounding (Vultr Vector Store archive tier) |
| **Zain** | Threat Execution & Adaptive Host Immunity | Live Vultr Cloud Firewall executor + attacker VM; AHI fingerprints attacks and uses Supermemory so the firewall gets better at recognizing / stopping similar threats over time |
| **Mohamed** | IIoT Target & Sourcing | Philips VM target, VPC networking, real manual sourcing (UDP 24105, p.29) |
| **Oleh** | The Command Center | Next.js UI, WebSocket terminal, Human Override, Incident Memo rendering |

---

<div align="center">

**THERIAC**

*Grounded in documents. Enforced on the network. Auditable end to end.*

</div>
