"""Register Contract A/B JSON schemas in Vultr Managed Kafka Schema Registry."""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx


ROOT = Path(__file__).resolve().parent.parent
SUBJECTS = {
    "contract-a.extracted-value": ROOT / "schemas/events/contract-a.schema.json",
    "contract-b.enforced-value": ROOT / "schemas/events/contract-b.schema.json",
}


def main() -> None:
    url = os.environ["VULTR_SCHEMA_REGISTRY_URL"].rstrip("/")
    auth = (os.environ["VULTR_KAFKA_USERNAME"], os.environ["VULTR_KAFKA_PASSWORD"])
    with httpx.Client(timeout=20, auth=auth) as client:
        for subject, path in SUBJECTS.items():
            schema = json.loads(path.read_text())
            response = client.post(
                f"{url}/subjects/{subject}/versions",
                headers={"Content-Type": "application/vnd.schemaregistry.v1+json"},
                json={"schemaType": "JSON", "schema": json.dumps(schema)},
            )
            response.raise_for_status()
            print(json.dumps({"subject": subject, "result": response.json()}))


if __name__ == "__main__":
    main()
