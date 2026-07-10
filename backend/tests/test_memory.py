import asyncio
import json
import unittest
from unittest import mock

import httpx

import services.memory as memory
from schemas.contract_a import AllowedPort, ContractA
from services.supermemory import SupermemoryClient, device_container_tag


def _contract(firmware: str, ports: list[tuple[int, str]]) -> ContractA:
    return ContractA(
        device_model="Philips_IntelliVue",
        firmware_version=firmware,
        allowed_ports=[AllowedPort(port=p, protocol="UDP", reason=f"port {p}") for p, _ in ports],
        source_doc_id="",
    )


class SupermemoryClientTests(unittest.TestCase):
    def test_add_document_scopes_to_container_tag(self) -> None:
        captured: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(201, json={"id": "doc-1"})

        async def run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                store = SupermemoryClient(base_url="http://sm.test", client=client)
                return await store.add_document("manual body", container_tag="device:x")

        doc_id = asyncio.run(run())
        self.assertEqual(doc_id, "doc-1")
        body = json.loads(captured[0].content)
        self.assertEqual(body["containerTags"], ["device:x"])
        self.assertEqual(captured[0].url.path, "/v3/documents")

    def test_search_text_flattens_reranked_passages(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"results": [{"content": "UDP 24105 required"}, {"chunk": "SSH 22 forbidden"}]},
            )

        async def run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                store = SupermemoryClient(base_url="http://sm.test", client=client)
                return await store.search_text("q", container_tag="cve-knowledge")

        text = asyncio.run(run())
        self.assertIn("24105", text)
        self.assertIn("SSH 22 forbidden", text)

    def test_search_text_falls_back_to_v3_chunk_search(self) -> None:
        """When the graph search (/v4) has no memories, retrieval must fall back to
        chunk-level /v3/search and unwrap its nested 'chunks' shape."""
        paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            paths.append(request.url.path)
            if request.url.path == "/v4/search":
                return httpx.Response(200, json={"results": [], "total": 0})
            return httpx.Response(
                200,
                json={"results": [{"chunks": [{"content": "UDP port 24105 for Data Export", "score": 0.84}]}]},
            )

        async def run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                store = SupermemoryClient(base_url="http://sm.test", client=client)
                return await store.search_text("q", container_tag="device:x")

        text = asyncio.run(run())
        self.assertIn("24105", text)
        self.assertEqual(paths, ["/v4/search", "/v3/search"])


class MemoryFacadeTests(unittest.TestCase):
    """Drive the facade against an in-memory Supermemory stand-in so the durable
    drift baseline round-trip (the headline restart-safe fix) is exercised."""

    def _patched_client(self):
        docs: dict[str, list[dict]] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST" and request.url.path == "/v3/documents":
                body = json.loads(request.content)
                tag = body["containerTags"][0]
                docs.setdefault(tag, []).append(
                    {"content": body["content"], "metadata": body.get("metadata", {})}
                )
                return httpx.Response(200, json={"id": f"doc-{len(docs[tag])}", "status": "queued"})
            if request.method == "POST" and request.url.path == "/v3/documents/list":
                tag = json.loads(request.content)["containerTags"][0]
                return httpx.Response(200, json={"memories": docs.get(tag, [])})
            if request.url.path == "/v4/search":
                return httpx.Response(200, json={"results": [], "total": 0})
            return httpx.Response(200, json={})

        shared = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        factory = lambda **kw: SupermemoryClient(base_url="http://sm.test", client=shared)  # noqa: E731
        return shared, factory

    def test_ingest_manual_returns_device_tag_as_collection(self) -> None:
        shared, factory = self._patched_client()

        async def run():
            with mock.patch.object(memory, "SupermemoryClient", factory):
                return await memory.ingest_manual("manual body", _contract("L.0", [(24105, "UDP")]))

        result = asyncio.run(run())
        asyncio.run(shared.aclose())
        self.assertEqual(result.collection_id, device_container_tag("Philips_IntelliVue"))
        self.assertEqual(result.chunk_count, 1)

    def test_device_profile_round_trips_for_durable_drift(self) -> None:
        shared, factory = self._patched_client()

        async def run():
            with mock.patch.object(memory, "SupermemoryClient", factory):
                await memory.save_device_profile("Philips_IntelliVue", _contract("L.0", [(24105, "UDP"), (24005, "UDP")]))
                return await memory.load_device_profile("Philips_IntelliVue")

        loaded = asyncio.run(run())
        asyncio.run(shared.aclose())
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.firmware_version, "L.0")
        self.assertEqual({p.port for p in loaded.allowed_ports}, {24105, 24005})

    def test_load_device_profile_absent_returns_none(self) -> None:
        shared, factory = self._patched_client()

        async def run():
            with mock.patch.object(memory, "SupermemoryClient", factory):
                return await memory.load_device_profile("Unknown_Device")

        loaded = asyncio.run(run())
        asyncio.run(shared.aclose())
        self.assertIsNone(loaded)


if __name__ == "__main__":
    unittest.main()
