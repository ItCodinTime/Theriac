import asyncio
import json
import unittest

import httpx

from schemas.contract_a import AllowedPort, ContractA
from services.vultr_vector import VultrVectorStore, chunk_manual


class ChunkManualTests(unittest.TestCase):
    def test_chunks_long_text_with_bounds(self) -> None:
        text = "\n\n".join(f"Section {index}. " + ("network requirements " * 12) for index in range(12))

        chunks = chunk_manual(text, chunk_size=240, overlap=40)

        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(0 < len(chunk) <= 240 for chunk in chunks))
        self.assertIn("Section 0", chunks[0])
        self.assertTrue(any("Section 11" in chunk for chunk in chunks))

    def test_large_overlap_still_advances(self) -> None:
        chunks = chunk_manual("word " * 100, chunk_size=50, overlap=45)

        self.assertLess(len(chunks), 100)
        self.assertTrue(all(len(chunk) <= 50 for chunk in chunks))

    def test_rejects_empty_manual(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            chunk_manual("  \n ")


class VultrVectorStoreTests(unittest.TestCase):
    def test_ingests_contract_and_chunks_into_vultr(self) -> None:
        requests: list[httpx.Request] = []
        item_number = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal item_number
            requests.append(request)
            if request.method == "GET":
                return httpx.Response(200, json={"data": []})
            if request.url.path == "/v1/vector_store":
                return httpx.Response(201, json={"id": "collection-123"})
            item_number += 1
            return httpx.Response(201, json={"id": f"item-{item_number}"})

        async def run_test():
            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(transport=transport) as client:
                store = VultrVectorStore(
                    api_key="test-key",
                    collection_name="panacea-manuals",
                    client=client,
                )
                contract = ContractA(
                    device_model="Philips_IntelliVue",
                    firmware_version="B.01",
                    allowed_ports=[AllowedPort(port=3200, protocol="TCP", reason="HL7 Patient Data")],
                    source_doc_id="",
                )
                return await store.ingest_manual(
                    "Port 3200 carries HL7 data. " * 30,
                    contract,
                    chunk_size=180,
                    overlap=30,
                )

        result = asyncio.run(run_test())

        self.assertEqual(result.collection_id, "collection-123")
        self.assertEqual(result.source_doc_id, "item-1")
        self.assertEqual(result.chunk_count, len(result.item_ids))
        self.assertGreater(result.chunk_count, 1)

        item_requests = [request for request in requests if request.url.path.endswith("/items")]
        source_body = json.loads(item_requests[0].content)
        first_chunk_body = json.loads(item_requests[1].content)
        self.assertIn("manual source record", source_body["content"])
        self.assertIn('"source_doc_id":"item-1"', first_chunk_body["content"])
        self.assertIn('"port":3200', first_chunk_body["content"])
        self.assertNotIn("chroma", first_chunk_body["content"].lower())
        self.assertNotIn("qdrant", first_chunk_body["content"].lower())

    def test_ensure_collection_resolves_after_concurrent_duplicate_conflict(self) -> None:
        """Two concurrent device pipelines racing to create the same-named
        collection: the loser gets Vultr's 422 "duplicate" error instead of
        the winner's ID. ensure_collection() must re-resolve by name instead
        of surfacing that as a hard failure."""
        get_call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal get_call_count
            if request.method == "GET":
                get_call_count += 1
                if get_call_count == 1:
                    return httpx.Response(200, json={"data": []})
                return httpx.Response(
                    200, json={"data": [{"id": "winner-123", "name": "panacea-manuals"}]}
                )
            if request.method == "POST":
                return httpx.Response(
                    422, json={"message": "Duplicate collection name found, please provide a unique name"}
                )
            return httpx.Response(204)

        async def run_test():
            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(transport=transport) as client:
                store = VultrVectorStore(api_key="test-key", collection_name="panacea-manuals", client=client)
                return await store.ensure_collection()

        collection_id = asyncio.run(run_test())
        self.assertEqual(collection_id, "winner-123")


if __name__ == "__main__":
    unittest.main()
