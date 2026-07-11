"""Unit tests for attack telemetry completion: CVE graph, observer parse, harden+CVE."""

from __future__ import annotations

import asyncio
import json
import unittest

import httpx

from schemas.attack_event import AttackEvent, AttackHistorySummary
from schemas.contract_b import ContractB, FirewallRule
from services import attack_memory
from services.attack_observer import parse_hl7_log_line
from services.cve_attack_graph import correlate_cves_for_port, primary_cve_for_port
from services.supermemory import SupermemoryClient, attack_container_tag


def _mock_client():
    docs: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v3/documents":
            body = json.loads(request.content)
            docs.append(body)
            return httpx.Response(201, json={"id": f"atk-{len(docs)}"})
        if request.method == "POST" and request.url.path in ("/v4/search", "/v3/search"):
            results = [
                {"content": d["content"], "id": f"atk-{i+1}", "metadata": d.get("metadata", {})}
                for i, d in enumerate(docs)
                if (d.get("metadata") or {}).get("type") != "attack-cve-link"
                or True
            ]
            return httpx.Response(200, json={"results": results})
        if request.method == "POST" and request.url.path == "/v3/documents/list":
            memories = [
                {
                    "id": f"atk-{i+1}",
                    "content": d.get("content", ""),
                    "metadata": d.get("metadata", {}),
                }
                for i, d in enumerate(docs)
            ]
            return httpx.Response(200, json={"memories": memories})
        return httpx.Response(200, json={})

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sm = SupermemoryClient(base_url="http://sm.test", client=http_client)
    return sm, http_client, docs


class CveGraphTests(unittest.TestCase):
    def test_ssh_port_correlates_openssh_cve(self) -> None:
        cve = primary_cve_for_port("Philips_IntelliVue", 22)
        self.assertTrue(cve.startswith("CVE-"))
        hits = correlate_cves_for_port("Philips_IntelliVue", 22)
        self.assertTrue(any(h["cve_id"] == cve for h in hits))

    def test_clinical_port_correlates_intellivue_cve(self) -> None:
        hits = correlate_cves_for_port("Philips_IntelliVue", 24005)
        self.assertTrue(any(h["cve_id"] == "CVE-2018-10597" for h in hits))


class Hl7ParseTests(unittest.TestCase):
    def test_parse_hl7_connection_line(self) -> None:
        event = parse_hl7_log_line("Connection from ('64.177.113.13', 54321)")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.attempted_port, 3200)
        self.assertEqual(event.source_ip, "64.177.113.13")
        self.assertEqual(event.observation_source, "hl7_listener")


class AttackMemoryCorrelationTests(unittest.TestCase):
    def test_ingest_attaches_related_cve_and_edge(self) -> None:
        sm, http_client, docs = _mock_client()

        async def run():
            try:
                event = AttackEvent(
                    device_model="Philips_IntelliVue",
                    attempted_port=22,
                    protocol="TCP",
                    source_ip="64.177.113.13",
                    reason="SSH probe",
                    observation_source="attack_observer",
                )
                stored = await attack_memory.ingest_attack_event(event, client=sm)
                history = await attack_memory.query_attack_history("Philips_IntelliVue", client=sm)
                return stored, history, docs
            finally:
                await http_client.aclose()

        stored, history, docs = asyncio.run(run())
        self.assertTrue(stored.get("related_cve"))
        self.assertTrue(stored.get("correlation_doc_id"))
        self.assertIn(22, history.harden_ports)
        self.assertTrue(history.related_cves)
        self.assertTrue(any(d.get("metadata", {}).get("type") == "attack-cve-link" for d in docs))

    def test_harden_sets_cve_flagged_from_graph(self) -> None:
        policy = ContractB(
            target_vpc_id="vpc-medical-01",
            firewall_rules=[
                FirewallRule(port=24105, action="ALLOW"),
                FirewallRule(port=22, action="ALLOW"),
            ],
            confidence_score=80,
            cve_flagged="NONE",
            memo_text="baseline",
        )
        history = AttackHistorySummary(
            device_model="Philips_IntelliVue",
            space="attacks:philips_intellivue",
            total_events=1,
            probed_ports=[
                {
                    "port": 22,
                    "count": 1,
                    "last_seen": "",
                    "protocols": ["TCP"],
                    "severities": ["high"],
                    "related_cves": ["CVE-2018-15473"],
                }
            ],
            harden_ports=[22],
            related_cves=["CVE-2018-15473"],
            correlations=[],
            narrative="port 22 probed",
        )
        hardened, notes = attack_memory.harden_policy_from_attacks(policy, history)
        self.assertEqual({r.port: r.action for r in hardened.firewall_rules}[22], "DENY")
        self.assertEqual(hardened.cve_flagged, "CVE-2018-15473")
        self.assertTrue(notes)


class TagTests(unittest.TestCase):
    def test_attack_space(self) -> None:
        self.assertEqual(attack_container_tag("Philips_IntelliVue"), "attacks:philips_intellivue")


if __name__ == "__main__":
    unittest.main()
