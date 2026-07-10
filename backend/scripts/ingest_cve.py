"""Load a curated CVE JSON feed into the Supermemory CVE space.

Each record becomes a document in the shared ``cve-knowledge`` container tag;
Supermemory auto-links CVE → device edges in its memory graph, so the agent's
check_cve tool can retrieve grounded, reranked CVE evidence. Pass --also-vultr to
additionally mirror the feed into the legacy Vultr Vector Store archive tier.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from dotenv import load_dotenv

load_dotenv(BACKEND_ROOT / ".env")

from services.supermemory import CVE_CONTAINER_TAG, SupermemoryClient


async def ingest(path: Path, also_vultr: bool) -> None:
    records = json.loads(path.read_text())
    if not isinstance(records, list):
        raise ValueError("CVE input must be a JSON array")

    client = SupermemoryClient()
    for record in records:
        if not isinstance(record, dict) or not record.get("cve_id"):
            raise ValueError("Every CVE record must be an object containing cve_id")
        await client.add_document(
            json.dumps(record, sort_keys=True, separators=(",", ":")),
            container_tag=CVE_CONTAINER_TAG,
            metadata={
                "type": "cve",
                "cve_id": record["cve_id"],
                "device_model": record.get("device_model", "medical device"),
                "severity": record.get("severity", ""),
            },
        )

    result = {"container_tag": CVE_CONTAINER_TAG, "records_ingested": len(records)}

    if also_vultr:
        from services.vultr_vector import VultrVectorStore

        store = VultrVectorStore(
            collection_id=os.getenv("VULTR_CVE_COLLECTION_ID", ""),
            collection_name=os.getenv("VULTR_CVE_COLLECTION_NAME", "panacea-cves"),
        )
        collection_id = await store.ensure_collection()
        for record in records:
            await store.add_item(
                collection_id,
                json.dumps(record, sort_keys=True, separators=(",", ":")),
                f"{record['cve_id']} affecting {record.get('device_model', 'medical device')}",
            )
        result["vultr_collection_id"] = collection_id

    print(json.dumps(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("json_file", type=Path)
    parser.add_argument(
        "--also-vultr",
        action="store_true",
        help="Also mirror the feed into the legacy Vultr Vector Store archive.",
    )
    args = parser.parse_args()
    asyncio.run(ingest(args.json_file, args.also_vultr))
