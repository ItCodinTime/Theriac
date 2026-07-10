"""Dummy env defaults so importing agent.orchestrator doesn't require real Vultr credentials in tests."""

import os

os.environ.setdefault("VULTR_INFERENCE_API_KEY", "test-key")
os.environ.setdefault("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1")
os.environ.setdefault("VULTR_MAIN_MODEL", "test-model")
os.environ.setdefault("VULTR_FALLBACK_MODEL", "test-fallback-model")
os.environ.setdefault("VULTR_MAX_TOKENS", "1200")
os.environ.setdefault("VULTR_TEMPERATURE", "0.2")
os.environ.setdefault("VULTR_INFERENCE_TIMEOUT", "60")
