<div align="center">

# THERIAC

### The Zero-Trust Immune System for Hospital Networks

**An autonomous, document-grounded AI agent that reads medical device manuals, hunts vulnerabilities, and programs live firewalls — without ever touching the physical device.**

<br/>

[![Supermemory](https://img.shields.io/badge/Memory-Supermemory%20Local-0B0B0B?style=for-the-badge)](https://supermemory.ai/docs/self-hosting/overview)
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

> **The pitch:** an auto-generated, compliance-safe immune system that operates entirely at the network layer — no agents installed, no device firmware touched, fully HIPAA-aligned with **zero memory egress** via [Supermemory Local](https://supermemory.ai/docs/self-hosting/overview) on `localhost:6767`.

---

## What Makes THERIAC Win

| Capability | Why it matters | Where |
|---|---|---|
| **True multi-step agent** | Plans → retrieves → checks CVEs → re-retrieves on conflict → decides → enforces. Not a one-shot RAG call. | `agent/orchestrator.py` |
| **Per-rule citation trail** | Every ALLOW/DENY in the memo is grounded in a cited manual passage or CVE record. No fabrication. | `agent/prompts.py` |
| **Explainable confidence** | Score derived from reasoning depth and evidence coverage — e.g. `82% — 3/4 rules grounded in cited evidence`. | `orchestrator.py` |
| **Ontology-aware memory graph** | Supermemory Local tracks `device → firmware → port → CVE` edges and resolves manual-requires-vs-CVE-forbids conflicts as first-class facts — retrieval is a graph, not flat vector similarity. | `services/memory.py` · `localhost:6767` |
| **Attack memory that hardens policy** | Probe telemetry lands in per-device Supermemory spaces (`attacks:<device>`); the next scan recalls probed ports + CVE correlations and flips ALLOW→DENY. | `services/attack_memory.py` · `POST /api/v1/attacks` |
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
    +--(tool)--> retrieve_document     --> Supermemory (device space, reranked passages)
    +--(tool)--> check_cve             --> Supermemory (cve-knowledge space + graph edges)
    +--(tool)--> check_attack_history  --> Supermemory (attacks:<device> + CVE correlations)
    +--(tool)--> apply_firewall_rule   --> Vultr Cloud Firewall (live ALLOW/DENY)
    |
    v
STEP 7: Incident Memo + Citation Trail + Confidence Score
         (MEMORY: block cites Supermemory doc IDs / prior incidents)
    |
    +--> Next.js Command Center (live WebSocket stream)
    +--> Object-Locked Evidence + Audit Log + Kafka Events
    +--> Attack observe loop writes probes back into Supermemory
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

### 1. Supermemory Local (required)

Theriac's memory plane is **[Supermemory Local](https://supermemory.ai/docs/self-hosting/overview)** — one binary on your machine (`http://localhost:6767`). Embeddings, storage, and search stay on-box; only memory *extraction* calls Vultr inference.

```bash
export $(grep -v '^#' backend/.env | xargs)      # load VULTR_* vars for extraction LLM
infra/supermemory/run-supermemory.sh             # → http://localhost:6767
# copy the printed API key into backend/.env as SUPERMEMORY_API_KEY
# (leave blank for unauthenticated localhost dev)

python backend/scripts/ingest_cve.py backend/cves.json   # seed cve-knowledge
```

| Container tag | What lives there |
|---|---|
| `device:<slug>` | Manuals, enforcement outcomes, drift baselines |
| `cve-knowledge` | Shared CVE corpus |
| `attacks:<device>` | Probe / lateral-movement telemetry + CVE correlations |

See [`infra/supermemory/`](infra/supermemory/) for spaces, `/v4` graph vs `/v3` chunk search, and health probes.

### 2. Backend

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env      # fill in Vultr keys + SUPERMEMORY_BASE_URL=http://localhost:6767
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Health check (backend readiness also probes Supermemory):

```bash
curl http://localhost:8000/healthz
# {"status":"ok","service":"theriac-backend"}
curl http://localhost:8000/readyz
```

### 3. Frontend

```bash
cd frontend
npm install
cp .env.example .env.local   # point NEXT_PUBLIC_API_URL at your backend
npm run dev                  # http://localhost:3000
```

Live Command Center: [https://theriac-eta.vercel.app/](https://theriac-eta.vercel.app/)

### 4. Run the agent

```bash
curl -X POST http://localhost:8000/api/v1/agent/run \
  -H "Content-Type: application/json" \
  -d '{"raw_pdf_text": "", "vpc_id": "vpc-medical-01"}'
```

An empty `raw_pdf_text` falls back to a built-in Philips IntelliVue demo excerpt, so the pipeline always has something to reason over.

### 5. Attack memory demo (Supermemory loop)

Replay a probe into local memory, recall it, and show the next policy DENYing that port:

```bash
# backend + Supermemory must be up
python backend/scripts/demo_attack_loop.py --port 24005 --api http://localhost:8000
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/agent/run` | Run the full 7-step pipeline for one device → Contract B |
| `POST` | `/api/v1/agent/multi-run` | Run the pipeline across up to 10 devices concurrently |
| `POST` | `/api/v1/agent/explain` | Plain-English compliance justification for a given policy |
| `GET`  | `/api/v1/agent/audit` | Last N audit-log decisions |
| `POST` | `/api/v1/attacks` | Store attack / probe telemetry in Supermemory (`attacks:<device>`) |
| `GET`  | `/api/v1/attacks/{device}` | Recall probed ports, harden list, CVE correlations |
| `POST` | `/api/v1/attacks/observe` | Probe target ports, ingest results into Supermemory |
| `POST` | `/api/v1/attacks/hl7-logs` | Ingest HL7 listener probe logs into attack memory |
| `POST` | `/api/v1/manuals/run` | Upload a PDF to Object Storage, then run the pipeline |
| `DELETE` | `/api/v1/policy/{device_id}` | Human Override — instantly retract an active policy |
| `WS`   | `/ws` | Live stream of agent reasoning, tool calls, and results |
| `GET`  | `/healthz` · `/readyz` | Liveness / readiness (readyz requires Supermemory + inference) |

---

## API Contracts

These JSON schemas are the seams between every module. Do not break them.

### Contract A — Extraction Output (stored in Supermemory device space)

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
  "memo_text": "Blocked lateral pivot on Port 22. Allowed Port 24105 per Supermemory doc: …"
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
│   │   ├── routes/                  # agent, attacks, manuals, policy, health
│   │   └── websocket.py             # live reasoning stream
│   ├── services/
│   │   ├── vultr_inference.py       # Serverless Inference client + agentic loop
│   │   ├── memory.py                # memory facade: ingest, search, CVE, drift profiles
│   │   ├── supermemory.py           # local Supermemory client (graph + hybrid search)
│   │   ├── attack_memory.py         # probe ingest / recall / ALLOW→DENY harden
│   │   ├── attack_observer.py       # live observe → Supermemory write-back
│   │   ├── cve_attack_graph.py      # device → CVE → port correlations
│   │   ├── vultr_vector.py          # optional Vultr Vector Store archive tier
│   │   ├── vultr_firewall.py        # live Cloud Firewall executor (safe-by-default)
│   │   ├── vultr_object_storage.py  # Object-Locked evidence sealing
│   │   ├── vultr_events.py          # Managed Kafka event publishing
│   │   ├── audit_log.py             # append-only JSONL decision trail
│   │   └── policy_leases.py         # expiring ALLOW leases
│   ├── scripts/
│   │   ├── demo_attack_loop.py      # Supermemory attack → harden demo
│   │   └── ingest_cve.py            # seed cve-knowledge space
│   ├── schemas/                     # Contract A, Contract B, attack events
│   └── tools/fw.py                  # CLI: safe plan / apply firewall operations
├── frontend/                        # Next.js Command Center (live terminal + memo UI)
├── docs/manuals/                    # real sourced Philips IntelliVue manual
└── infra/
    ├── supermemory/                 # run-supermemory.sh + local memory docs
    └── zain/                        # attacker VM / firewall runbook
```

---

## The Agent in Action

A real run streams something like this to the Command Center:

```
[STEP 2] Extracting network requirements from device manual...
[STEP 2 DONE] Device: Philips_IntelliVue | Firmware: B.01 | Ports: [24105, 24005]
[STEP 5] Storing Contract A in Supermemory (device:philips_intellivue)...
[MEMORY] Hybrid search + rerank via Supermemory Local (localhost:6767)...

PLAN:
  1. Confirm port 24105 is required by the manual, not just mentioned
  2. Check CVEs for IntelliVue B.01
  3. Recall attack history for prior probes on this device
  4. Resolve any manual-vs-CVE conflict before deciding

[TOOL CALL -> retrieve_document({'query': 'UDP 24105 Data Export', ...})]
[TOOL CALL -> check_cve({'device_model': 'Philips_IntelliVue', ...})]
[TOOL CALL -> check_attack_history({'device_model': 'Philips_IntelliVue', ...})]
[TOOL CALL -> apply_firewall_rule({...})]

[CONFIDENCE] 88% — moderate deliberation; 2/2 rules grounded in cited evidence
MEMORY:
  docs: … · prior incidents: port 24005 probed → DENY (attacks:philips_intellivue)
[STEP 7] Generating incident memo with citation trail...
[EVIDENCE SEALED] Lease lease-a1b2c3; object evidence/2026/...
```

---

## Team

| Owner | Domain | Deliverable |
|-------|--------|-------------|
| **Brian** | Agent Orchestration | Serverless Inference agent loop, citation trail, confidence scoring, drift detection, audit log, multi-run + explain APIs |
| **Goutham** | The Memory Engine | Self-hosted **Supermemory Local** graph backbone — per-device spaces, hybrid search + rerank, durable drift profiles, CVE + attack memory (Vultr Vector Store as optional archive) |
| **Zain** | Threat Execution & Adaptive Host Immunity | Live Vultr Cloud Firewall executor + attacker VM; AHI fingerprints attacks and uses Supermemory so the firewall gets better at recognizing / stopping similar threats over time |
| **Mohamed** | IIoT Target & Sourcing | Philips VM target, VPC networking, real manual sourcing (UDP 24105, p.29) |
| **Oleh** | The Command Center | Next.js UI, WebSocket terminal, Human Override, Incident Memo rendering |

---

<div align="center">

**THERIAC**

*Grounded in documents. Remembered on Supermemory Local. Enforced on the network.*

<br/>

[Supermemory Local docs](https://supermemory.ai/docs/self-hosting/overview) · [Quickstart](https://supermemory.ai/docs/self-hosting/quickstart) · [`infra/supermemory/`](infra/supermemory/)

</div>
