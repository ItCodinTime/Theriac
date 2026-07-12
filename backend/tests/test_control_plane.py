"""Control-plane tests.

NAT-gateway enforcer tests were retired when enforcement moved to Vultr Cloud
Firewall groups (``services.vultr_firewall.apply_rules``). Evidence sealing
still lives here.
"""

import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from schemas.contract_a import AllowedPort, ContractA
from schemas.contract_b import ContractB, FirewallRule
from schemas.control_plane import EvidenceBundle, EnforcementReceipt, PolicyLease, RuleChange
from services.vultr_object_storage import VultrObjectStorage


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
