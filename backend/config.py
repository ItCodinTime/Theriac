# Shared environment configuration for the Panacea backend.

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")


def _require(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


# Vultr Serverless Inference
VULTR_INFERENCE_API_KEY = _require("VULTR_INFERENCE_API_KEY")
VULTR_INFERENCE_BASE_URL = _require("VULTR_INFERENCE_BASE_URL")
VULTR_MAIN_MODEL = _require("VULTR_MAIN_MODEL")
VULTR_FALLBACK_MODEL = _require("VULTR_FALLBACK_MODEL")
VULTR_MAX_TOKENS = int(_require("VULTR_MAX_TOKENS"))
VULTR_TEMPERATURE = float(_require("VULTR_TEMPERATURE"))
VULTR_INFERENCE_TIMEOUT = float(_require("VULTR_INFERENCE_TIMEOUT"))

# Other Vultr services (used by vector store + firewall clients)
VULTR_API_KEY = os.getenv("VULTR_API_KEY", "")
VULTR_VECTOR_STORE_URL = os.getenv("VULTR_VECTOR_STORE_URL", "")
VULTR_VPC_ID = os.getenv("VULTR_VPC_ID", "vpc-medical-01")
VULTR_VECTOR_COLLECTION_ID = os.getenv("VULTR_VECTOR_COLLECTION_ID", "")
VULTR_VECTOR_COLLECTION_NAME = os.getenv("VULTR_VECTOR_COLLECTION_NAME", "panacea-manuals")

# Native data and control plane
VULTR_RAG_MODEL = os.getenv("VULTR_RAG_MODEL", "qwen2.5-32b-instruct")
VULTR_TOOL_MODEL = os.getenv("VULTR_TOOL_MODEL", VULTR_MAIN_MODEL)
VULTR_NATIVE_STRICT = os.getenv("VULTR_NATIVE_STRICT", "false").lower() == "true"
