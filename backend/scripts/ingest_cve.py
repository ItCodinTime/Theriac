"""Load a curated CVE JSON feed into a Vultr Vector Store collection."""

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

from services.vultr_vector import VultrVectorStore


async def ingest(path: Path) -> None:
    records = json.loads(path.read_text())
    if not isinstance(records, list):
        raise ValueError("CVE input must be a JSON array")
    store = VultrVectorStore(
        collection_id=os.getenv("VULTR_CVE_COLLECTION_ID", ""),
        collection_name=os.getenv("VULTR_CVE_COLLECTION_NAME", "panacea-cves"),
    )
    collection_id = await store.ensure_collection()
    for record in records:
        if not isinstance(record, dict) or not record.get("cve_id"):
            raise ValueError("Every CVE record must be an object containing cve_id")
        await store.add_item(
            collection_id,
            json.dumps(record, sort_keys=True, separators=(",", ":")),
            f"{record['cve_id']} affecting {record.get('device_model', 'medical device')}",
        )
    print(json.dumps({"collection_id": collection_id, "records_ingested": len(records)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("json_file", type=Path)
    asyncio.run(ingest(parser.parse_args().json_file))
