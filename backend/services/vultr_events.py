"""Managed Vultr Kafka publisher for PANACEA control-plane events."""

from __future__ import annotations

import json
import os
import ssl
from pathlib import Path
from typing import Any


class VultrEventBusError(RuntimeError):
    pass


async def publish_event(topic: str, key: str, payload: dict[str, Any]) -> bool:
    """Publish one JSON event to Vultr Managed Kafka.

    Returns False only when Kafka is intentionally not configured in non-strict
    development mode. There is no local event-bus fallback.
    """
    schema_files = {
        "contract-a.extracted": "contract-a.schema.json",
        "contract-b.enforced": "contract-b.schema.json",
    }
    if topic in schema_files:
        from jsonschema import validate

        schema_path = Path(__file__).resolve().parent.parent / "schemas/events" / schema_files[topic]
        validate(instance=payload, schema=json.loads(schema_path.read_text()))

    brokers = os.getenv("VULTR_KAFKA_BOOTSTRAP_SERVERS", "")
    strict = os.getenv("VULTR_NATIVE_STRICT", "false").lower() == "true"
    if not brokers:
        if strict:
            raise VultrEventBusError("VULTR_KAFKA_BOOTSTRAP_SERVERS is required in strict mode")
        return False

    try:
        from aiokafka import AIOKafkaProducer
    except ImportError as exc:
        raise VultrEventBusError("aiokafka is required for Vultr Managed Kafka") from exc

    security_protocol = os.getenv("VULTR_KAFKA_SECURITY_PROTOCOL", "SASL_SSL")
    ssl_context = None
    if security_protocol in {"SSL", "SASL_SSL"}:
        ssl_context = ssl.create_default_context(cafile=os.getenv("VULTR_KAFKA_CA_FILE") or None)

    producer = AIOKafkaProducer(
        bootstrap_servers=[item.strip() for item in brokers.split(",") if item.strip()],
        security_protocol=security_protocol,
        sasl_mechanism=os.getenv("VULTR_KAFKA_SASL_MECHANISM", "SCRAM-SHA-256"),
        sasl_plain_username=os.getenv("VULTR_KAFKA_USERNAME", ""),
        sasl_plain_password=os.getenv("VULTR_KAFKA_PASSWORD", ""),
        ssl_context=ssl_context,
        acks="all",
        enable_idempotence=True,
        value_serializer=lambda value: json.dumps(value, separators=(",", ":"), default=str).encode(),
        key_serializer=lambda value: value.encode(),
    )
    await producer.start()
    try:
        await producer.send_and_wait(topic, payload, key=key)
    finally:
        await producer.stop()
    return True
