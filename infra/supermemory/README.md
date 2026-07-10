# Supermemory — Theriac's local memory / RAG plane

Theriac's memory backbone is a **self-hosted [Supermemory](https://github.com/supermemoryai/supermemory) instance**: a single binary with an embedded graph engine and local embeddings, listening on `http://localhost:6767`. There is no Docker image to build and no database to provision.

## Why local

- **Zero data egress.** Manuals, CVE evidence, device profiles, and enforcement outcomes never leave the host. Embeddings and hybrid search run on-box. Only the memory-*extraction* LLM call is pointed at Vultr Serverless Inference — so Theriac keeps sovereign inference on Vultr while the entire memory graph stays inside the hospital boundary. This *strengthens* the HIPAA story.
- **Graph, not flat vectors.** Supermemory builds ontology-aware edges over `device → firmware → port → CVE`, handles contradictions (manual-requires-vs-CVE-forbids) as first-class facts, and maintains a durable per-device profile that makes policy-drift detection survive a backend restart.

## Run it (wired to Vultr inference)

```bash
export $(grep -v '^#' ../../backend/.env | xargs)   # load VULTR_* vars
./run-supermemory.sh
```

or manually:

```bash
OPENAI_BASE_URL="$VULTR_INFERENCE_BASE_URL" \
OPENAI_API_KEY="$VULTR_INFERENCE_API_KEY" \
OPENAI_MODEL="$VULTR_MAIN_MODEL" \
npx supermemory local          # or: curl -fsSL https://supermemory.ai/install | bash
```

The server prints an **API key** on first boot — copy it into `backend/.env` as `SUPERMEMORY_API_KEY` (or leave blank for unauthenticated localhost dev). It also serves generated OpenAPI docs at `http://localhost:6767` — the source of truth for exact request/response shapes.

## Spaces (container tags)

| Container tag        | Contents                                        |
|----------------------|-------------------------------------------------|
| `device:<slug>`      | Per-device manuals, enforcement outcomes, drift baselines |
| `cve-knowledge`      | The shared CVE corpus (`backend/cves.json`)     |

## Seed the CVE corpus

```bash
cd ../../backend
python scripts/ingest_cve.py cves.json           # → cve-knowledge space
python scripts/ingest_cve.py cves.json --also-vultr   # also mirror to Vultr archive
```

## Retrieval tiers & model choice

Supermemory exposes two search surfaces, and Theriac uses both:

- **`/v4/search`** queries the extracted **memory graph** (ontology-aware edges, contradictions). It only returns hits once the extraction LLM has distilled memories from a document.
- **`/v3/search`** does chunk-level semantic search over the raw embedded chunks. Embeddings are computed locally and always succeed, so this is Theriac's **retrieval floor**: `services/memory.py` calls `/v4/search` first and falls back to `/v3/search` when the graph has no memories yet.

**Model guidance:** the graph features (rich `/v4` retrieval, contradiction resolution) need an extraction model strong enough to emit structured memories. A tiny model (e.g. `llama3.2:1b`) computes embeddings fine but often extracts **0 memories**, so you get chunk-level retrieval only. Point `OPENAI_MODEL` at the Vultr Nemotron model (or a ≥7B local model) to light up the full graph. Verified end-to-end locally: ingestion, durable device profiles, drift detection, and `/v3` chunk retrieval all work even with the 1B model.

> **v0.0.3 note:** a background retry cron can mark freshly-processed documents `status: failed` ("no retry params key") even after embeddings are stored. This does not affect `/v3/search` (chunk retrieval) or the metadata-based device profiles, which is why Theriac's retrieval floor and drift baselines are resilient to it. v0.0.4 currently fails to boot on a fresh data dir — pin `0.0.3` until a fixed release lands.

## Health

`GET /readyz` on the backend now probes both Vultr Inference **and** this server; both must be live before the agent accepts traffic.
