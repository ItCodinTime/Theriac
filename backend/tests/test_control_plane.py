import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx

from schemas.contract_a import AllowedPort, ContractA
from schemas.contract_b import ContractB, FirewallRule
from schemas.control_plane import EvidenceBundle, EnforcementReceipt, PolicyLease, RuleChange
from services.vultr_firewall import VultrNATGatewayEnforcer
from services.vultr_object_storage import VultrObjectStorage


class FakeSocket:
    """Stands in for the attacker VM's TCP handshake against a probed port."""

    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False


def attacker_vm_probe(address: tuple[str, int], timeout: float | None = None) -> FakeSocket:
    """Simulates the attacker VM's view of the network: port 22 refuses the
    connection (lateral pivot blocked), port 3200 completes the handshake
    (HL7 traffic still flows)."""
    _, port = address
    if port == 22:
        raise OSError("Connection refused")
    return FakeSocket()


class NATGatewayEnforcerTests(unittest.TestCase):
    def test_allow_creates_forward_and_firewall_rule(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.method == "GET":
                return httpx.Response(200, json={"data": []})
            if request.url.path.endswith("/port-forwarding-rules"):
                return httpx.Response(201, json={"id": "forward-1"})
            if request.url.path.endswith("/firewall-rules"):
                return httpx.Response(201, json={"id": "firewall-1"})
            return httpx.Response(204)

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            enforcer = VultrNATGatewayEnforcer(
                api_key="key",
                gateway_id="gateway-1",
                device_ip="10.0.0.10",
                client=client,
            )
            result = enforcer.apply(
                ContractB(
                    target_vpc_id="vpc-1",
                    firewall_rules=[FirewallRule(port=3200, action="ALLOW")],
                    confidence_score=96,
                    cve_flagged="NONE",
                    memo_text="Allow documented HL7 traffic.",
                )
            )

        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["receipt"]["provider"], "vultr")
        posts = [request for request in requests if request.method == "POST"]
        self.assertEqual(len(posts), 2)
        forwarding = json.loads(posts[0].content)
        firewall = json.loads(posts[1].content)
        self.assertEqual(forwarding["internal_ip"], "10.0.0.10")
        self.assertEqual(forwarding["internal_port"], 3200)
        self.assertEqual(firewall["port"], "3200")
        self.assertIn("expires", firewall["notes"])

    def test_denies_port_22_allows_port_3200_verified_twice_from_attacker_vm(self) -> None:
        """Reproduces the live demo result: SSH (22) lateral pivot blocked,
        HL7 (3200) still reachable, confirmed by two independent enforcement
        + attacker-VM-probe passes against the same NAT Gateway state."""
        state = {
            "forwards": [],
            "firewall_rules": [{"id": "fw-22", "port": "22"}],
        }

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if request.method == "GET":
                if path.endswith("/port-forwarding-rules"):
                    return httpx.Response(200, json={"data": state["forwards"]})
                return httpx.Response(200, json={"data": state["firewall_rules"]})
            if request.method == "POST" and path.endswith("/port-forwarding-rules"):
                rule = {**json.loads(request.content), "id": "forward-3200"}
                state["forwards"].append(rule)
                return httpx.Response(201, json={"id": "forward-3200"})
            if request.method == "POST" and path.endswith("/firewall-rules"):
                rule = {**json.loads(request.content), "id": "fw-3200"}
                state["firewall_rules"].append(rule)
                return httpx.Response(201, json={"id": "fw-3200"})
            if request.method == "DELETE" and "/firewall-rules/" in path:
                rule_id = path.rsplit("/", 1)[-1]
                state["firewall_rules"] = [r for r in state["firewall_rules"] if r["id"] != rule_id]
                return httpx.Response(204)
            if request.method == "DELETE" and "/port-forwarding-rules/" in path:
                rule_id = path.rsplit("/", 1)[-1]
                state["forwards"] = [r for r in state["forwards"] if r["id"] != rule_id]
                return httpx.Response(204)
            raise AssertionError(f"unexpected request: {request.method} {path}")

        policy = ContractB(
            target_vpc_id="vpc-medical-01",
            firewall_rules=[
                FirewallRule(port=3200, action="ALLOW"),
                FirewallRule(port=22, action="DENY"),
            ],
            confidence_score=96,
            cve_flagged="CVE-2023-XXXX",
            memo_text="Blocked lateral pivot on Port 22. Allowed Port 3200 per Vector ID: 12345.",
        )

        with httpx.Client(transport=httpx.MockTransport(handler)) as client, \
            patch.dict("os.environ", {"VULTR_NETWORK_PROBE_HOST": "10.0.0.10"}), \
            patch("services.vultr_firewall.socket.create_connection", side_effect=attacker_vm_probe):
            enforcer = VultrNATGatewayEnforcer(
                api_key="key",
                gateway_id="gateway-1",
                device_ip="10.0.0.10",
                client=client,
            )

            for pass_number in (1, 2):
                result = enforcer.apply(policy)
                changes = {change["port"]: change for change in result["receipt"]["changes"]}

                self.assertEqual(changes[22]["action"], "DENY")
                self.assertEqual(changes[22]["probe_status"], "blocked", f"pass {pass_number}")
                self.assertEqual(changes[3200]["action"], "ALLOW")
                self.assertEqual(changes[3200]["probe_status"], "reachable", f"pass {pass_number}")

        # Port 22's firewall rule was actually removed, not just marked.
        self.assertTrue(all(r["id"] != "fw-22" for r in state["firewall_rules"]))
        # The 3200 forward/rule were created once and reused on the second pass.
        self.assertEqual(len(state["forwards"]), 1)
        self.assertEqual(len([r for r in state["firewall_rules"] if r["port"] == "3200"]), 1)


class FakeS3:
    def __init__(self) -> None:
        self.objects = {}

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise KeyError(Key)
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)]["Body"])}

    def put_object(self, **kwargs):
        self.objects[(kwargs["Bucket"], kwargs["Key"])] = kwargs
        return {"ETag": "test"}


class EvidenceTests(unittest.TestCase):
    def test_seals_hash_chained_evidence(self) -> None:
        contract_a = ContractA(
            device_model="Philips_IntelliVue",
            firmware_version="B.01",
            allowed_ports=[AllowedPort(port=3200, protocol="TCP", reason="HL7")],
            source_doc_id="vector-1",
        )
        contract_b = ContractB(
            target_vpc_id="vpc-1",
            firewall_rules=[FirewallRule(port=3200, action="ALLOW")],
            confidence_score=96,
            cve_flagged="NONE",
            memo_text="Allowed HL7.",
        )
        receipt = EnforcementReceipt(
            enforcement_plane="vultr_nat_gateway",
            vpc_id="vpc-1",
            gateway_id="gateway-1",
            device_ip="10.0.0.10",
            changes=[RuleChange(port=3200, action="ALLOW", status="active")],
        )
        lease = PolicyLease(
            lease_id="lease-1",
            source_doc_id="vector-1",
            policy=contract_b,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
            receipt=receipt,
        )
        bundle = EvidenceBundle(
            evidence_id="evidence-1",
            contract_a=contract_a,
            contract_b=contract_b,
            lease=lease,
            manual_sha256="abc",
            retrieved_context="Port 3200 is required for HL7.",
            model_id="vultr-model",
        )
        fake = FakeS3()
        with patch.dict("os.environ", {"VULTR_EVIDENCE_BUCKET": "evidence", "VULTR_EVIDENCE_RETENTION_DAYS": "0"}):
            key, evidence_hash = VultrObjectStorage(client=fake).seal_evidence(bundle)

        self.assertTrue(key.endswith("evidence-1.json"))
        self.assertEqual(len(evidence_hash), 64)
        self.assertEqual(fake.objects[("evidence", "evidence/HEAD")]["Body"].decode(), evidence_hash)
        sealed = json.loads(fake.objects[("evidence", key)]["Body"])
        self.assertEqual(sealed["evidence_sha256"], evidence_hash)


if __name__ == "__main__":
    unittest.main()
