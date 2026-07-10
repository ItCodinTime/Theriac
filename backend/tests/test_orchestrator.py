import unittest

from agent.orchestrator import DEMO_CONTRACT_A, _parse_contract_a


class ParseContractATests(unittest.TestCase):
    def test_valid_json_with_ports_does_not_fall_back(self) -> None:
        raw = """```json
        {
          "device_model": "Philips_IntelliVue",
          "firmware_version": "B.01",
          "allowed_ports": [{"port": 3200, "protocol": "TCP", "reason": "HL7"}],
          "source_doc_id": ""
        }
        ```"""
        contract, fell_back = _parse_contract_a(raw)
        self.assertFalse(fell_back)
        self.assertEqual([p.port for p in contract.allowed_ports], [3200])

    def test_unparseable_output_falls_back_to_demo_device(self) -> None:
        contract, fell_back = _parse_contract_a("Nemotron rambled instead of returning JSON.")
        self.assertTrue(fell_back)
        self.assertEqual(contract.device_model, DEMO_CONTRACT_A.device_model)
        self.assertEqual(contract.allowed_ports, DEMO_CONTRACT_A.allowed_ports)

    def test_valid_json_with_no_ports_falls_back_to_demo_device(self) -> None:
        raw = """{"device_model": "Some_Device", "firmware_version": "1.0", "allowed_ports": [], "source_doc_id": ""}"""
        contract, fell_back = _parse_contract_a(raw)
        self.assertTrue(fell_back)
        self.assertEqual(contract.device_model, DEMO_CONTRACT_A.device_model)


if __name__ == "__main__":
    unittest.main()
