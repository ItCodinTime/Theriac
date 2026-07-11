"""Unit tests for attack-telemetry memory (ingest → recall → harden)."""

from __future__ import annotations

import asyncio
import json
import unittest

import httpx

from schemas.attack_event import AttackEvent, AttackHistorySummary
from schemas.contract_b import ContractB, FirewallRule
from services import attack_memory
from services.supermemory import SupermemoryClient, attack_container_tag


def _mock_client():
    docs: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v3/documents":
            body = json.loads(request.content)
            docs.append(body)
            return httpx.Response(201, json={"id": f"atk-{len(docs)}"})
        if request.method == "POST" and request.url.path in ("/v4/search", "/v3/search"):
            results = [{"content": d["content"], "id": f"atk-{i+1}"} for i, d in enumerate(docs)]
            return httpx.Response(200, json={"results": results})
        if request.method == "POST" and request.url.path == "/v3/documents/list":
            memories = []
            for i, d in enumerate(docs):
                memories.append(
                    {
                        "id": f"atk-{i+1}",
                        "content": d.get("content", ""),
                        "metadata": d.get("metadata", {}),
                    }
                )
            return httpx.Response(200, json={"memories": memories})
        return httpx.Response(200, json={})

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sm = SupermemoryClient(base_url="http://sm.test", client=http_client)
    return sm, http_client, docs


class AttackContainerTagTests(unittest.TestCase):
    def test_attack_space_slug(self) -> None:
        self.assertEqual(attack_container_tag("Philips_IntelliVue"), "attacks:philips_intellivue")


class AttackMemoryTests(unittest.TestCase):
    def test_ingest_and_query_hardens_probed_port(self) -> None:
        sm, http_client, docs = _mock_client()

        async def run():
            try:
                event = AttackEvent(
                    device_model="Philips_IntelliVue",
                    attempted_port=24005,
                    protocol="UDP",
                    source_ip="64.177.113.13",
                    reason="Replay probe against Data Export Interface",
                )
                stored = await attack_memory.ingest_attack_event(event, client=sm)
                history = await attack_memory.query_attack_history("Philips_IntelliVue", client=sm)
                return stored, history
            finally:
                await http_client.aclose()

        stored, history = asyncio.run(run())
        self.assertEqual(stored["space"], "attacks:philips_intellivue")
        self.assertTrue(docs)
        self.assertIn(24005, history.harden_ports)
        self.assertGreaterEqual(history.total_events, 1)
        self.assertIn("24005", history.narrative)

    def test_harden_policy_flips_allow_to_deny(self) -> None:
        policy = ContractB(
            target_vpc_id="vpc-medical-01",
            firewall_rules=[
                FirewallRule(port=24105, action="ALLOW"),
                FirewallRule(port=24005, action="ALLOW"),
                FirewallRule(port=22, action="DENY"),
            ],
            confidence_score=90,
            cve_flagged="NONE",
            memo_text="baseline",
        )
        history = AttackHistorySummary(
            device_model="Philips_IntelliVue",
            space="attacks:philips_intellivue",
            total_events=2,
            probed_ports=[{"port": 24005, "count": 2, "last_seen": "", "protocols": ["UDP"], "severities": ["high"]}],
            harden_ports=[24005],
            narrative="port 24005 probed 2×",
        )
        hardened, notes = attack_memory.harden_policy_from_attacks(policy, history)
        by_port = {r.port: r.action for r in hardened.firewall_rules}
        self.assertEqual(by_port[24005], "DENY")
        self.assertEqual(by_port[24105], "ALLOW")
        self.assertTrue(any("24005" in n for n in notes))

    def test_harden_adds_missing_probed_port(self) -> None:
        policy = ContractB(
            target_vpc_id="vpc-medical-01",
            firewall_rules=[FirewallRule(port=24105, action="ALLOW")],
            confidence_score=80,
            cve_flagged="NONE",
            memo_text="baseline",
        )
        history = AttackHistorySummary(
            device_model="Philips_IntelliVue",
            space="attacks:philips_intellivue",
            total_events=1,
            probed_ports=[{"port": 22, "count": 1, "last_seen": "", "protocols": ["TCP"], "severities": ["high"]}],
            harden_ports=[22],
            narrative="port 22 probed 1×",
        )
        hardened, notes = attack_memory.harden_policy_from_attacks(policy, history)
        by_port = {r.port: r.action for r in hardened.firewall_rules}
        self.assertEqual(by_port[22], "DENY")
        self.assertTrue(notes)


if __name__ == "__main__":
    unittest.main()
