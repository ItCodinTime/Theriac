#!/usr/bin/env bash
# Boot a local Supermemory server wired to Vultr Serverless Inference for memory
# extraction. Embeddings stay local — retrieval never leaves the host.
#
# Usage:  ./run-supermemory.sh
# Expects VULTR_INFERENCE_BASE_URL, VULTR_INFERENCE_API_KEY, VULTR_MAIN_MODEL in
# the environment (e.g. `export $(grep -v '^#' ../../backend/.env | xargs)`).
set -euo pipefail

: "${VULTR_INFERENCE_BASE_URL:?set VULTR_INFERENCE_BASE_URL (see backend/.env)}"
: "${VULTR_INFERENCE_API_KEY:?set VULTR_INFERENCE_API_KEY (see backend/.env)}"
: "${VULTR_MAIN_MODEL:?set VULTR_MAIN_MODEL (see backend/.env)}"

export OPENAI_BASE_URL="$VULTR_INFERENCE_BASE_URL"
export OPENAI_API_KEY="$VULTR_INFERENCE_API_KEY"
export OPENAI_MODEL="$VULTR_MAIN_MODEL"

echo "Starting Supermemory on http://localhost:6767"
echo "  extraction LLM -> $OPENAI_BASE_URL ($OPENAI_MODEL)"
echo "  embeddings     -> local (zero egress)"
echo "Copy the printed API key into backend/.env as SUPERMEMORY_API_KEY."

if command -v supermemory-server >/dev/null 2>&1; then
  exec supermemory-server
else
  exec npx supermemory local
fi
