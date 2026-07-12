from __future__ import annotations

import asyncio
import json
import unittest

import httpx

from schemas.attack_event import AttackHistorySummary
from schemas.contract_a import AllowedPort, ContractA
from schemas.contract_b import ContractB, FirewallRule
from services.memory_ops import (
    device_timeline,
    inspect_space,
    record_policy_facts,
    record_policy_outcome,
    search_with_trace,
)
from services.supermemory import SupermemoryClient, device_container_tag


def _mock_client():
    docs: dict[str, list[dict]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v3/documents":
            body = json.loads(request.content)
            tag = body["containerTags"][0]
            item = {
                "id": f"{tag}-doc-{len(docs.get(tag, [])) + 1}",
                "content": body.get("content", ""),
                "metadata": body.get("metadata", {}),
            }
            docs.setdefault(tag, []).append(item)
            return httpx.Response(201, json={"id": item["id"]})
        if request.method == "POST" and request.url.path == "/v3/documents/list":
            tag = json.loads(request.content)["containerTags"][0]
            return httpx.Response(200, json={"memories": docs.get(tag, [])})
        if request.method == "POST" and request.url.path == "/v4/search":
            return httpx.Response(200, json={"results": []})
        if request.method == "POST" and request.url.path == "/v3/search":
            body = json.loads(request.content)
            tag = body["containerTags"][0]
            return httpx.Response(200, json={"results": docs.get(tag, [])})
        if request.method == "POST" and request.url.path == "/v4/profile":
            return httpx.Response(200, json={"profile": "profile text"})
        return httpx.Response(200, json={})

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sm = SupermemoryClient(base_url="http://sm.test", client=http_client)
    return sm, http_client, docs


def _contract_a() -> ContractA:
    return ContractA(
        device_model="Philips_IntelliVue",
        firmware_version="L.0",
        allowed_ports=[
            AllowedPort(port=24105, protocol="UDP", reason="main data channel"),
            AllowedPort(port=24005, protocol="UDP", reason="discovery"),
        ],
        source_doc_id="sm-manual-1",
    )


class MemoryOpsTests(unittest.TestCase):
    def test_search_with_trace_falls_back_to_chunks(self) -> None:
        sm, http_client, _docs = _mock_client()

        async def run():
            try:
                await sm.add_document(
                    "UDP 24105 required",
                    container_tag="device:philips_intellivue",
                    metadata={"type": "manual"},
                )
                return await search_with_trace(
                    "24105",
                    space="device:philips_intellivue",
                    client=sm,
                )
            finally:
                await http_client.aclose()

        result = asyncio.run(run())
        self.assertEqual(result["used_tier"], "chunks")
        self.assertEqual([step["endpoint"] for step in result["trace"]], ["/v4/search", "/v3/search"])
        self.assertTrue(result["results"])

    def test_inspect_space_counts_document_types(self) -> None:
        sm, http_client, _docs = _mock_client()

        async def run():
            try:
                await sm.add_document("manual", container_tag="device:x", metadata={"type": "manual"})
                await sm.add_document("outcome", container_tag="device:x", metadata={"type": "policy-outcome"})
                return await inspect_space("device:x", client=sm)
            finally:
                await http_client.aclose()

        result = asyncio.run(run())
        self.assertEqual(result["type_counts"]["manual"], 1)
        self.assertEqual(result["type_counts"]["policy-outcome"], 1)
        self.assertEqual(result["profile"], "profile text")

    def test_policy_facts_record_contradiction_and_timeline(self) -> None:
        sm, http_client, _docs = _mock_client()
        contract_a = _contract_a()
        contract_b = ContractB(
            target_vpc_id="vpc-medical-01",
            firewall_rules=[
                FirewallRule(port=24105, action="ALLOW"),
                FirewallRule(port=24005, action="DENY"),
            ],
            confidence_score=86,
            cve_flagged="CVE-2018-10597",
            memo_text="memo",
        )
        history = AttackHistorySummary(
            device_model="Philips_IntelliVue",
            space="attacks:philips_intellivue",
            probed_ports=[{"port": 24005, "count": 1, "weighted_count": 1.0, "related_cves": ["CVE-2018-10597"]}],
            harden_ports=[24005],
            related_cves=["CVE-2018-10597"],
        )

        async def run():
            try:
                fact_ids = await record_policy_facts(
                    contract_a=contract_a,
                    contract_b=contract_b,
                    cve_evidence="CVE-2018-10597 affects this family",
                    attack_history=history,
                    client=sm,
                )
                await record_policy_outcome(
                    device_model="Philips_IntelliVue",
                    lease_id="lease-1",
                    outcome="useful",
                    confidence_score=86,
                    client=sm,
                )
                timeline = await device_timeline("Philips_IntelliVue", client=sm)
                return fact_ids, timeline
            finally:
                await http_client.aclose()

        fact_ids, timeline = asyncio.run(run())
        self.assertTrue(fact_ids)
        self.assertTrue(any(event["metadata"].get("fact_type") == "contradiction" for event in timeline["events"]))
        self.assertTrue(any(event["type"] == "policy-outcome" for event in timeline["events"]))
        self.assertEqual(timeline["space"], device_container_tag("Philips_IntelliVue"))


if __name__ == "__main__":
    unittest.main()
