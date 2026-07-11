"""Unit tests for the Adaptive Host Immunity module.

Follows the existing test conventions:
    - unittest.TestCase
    - asyncio.run() for async service calls
    - httpx.MockTransport for Supermemory HTTP mocking
    - conftest.py provides dummy env vars
"""

import asyncio
import json
import unittest
from unittest import mock

import httpx

from schemas.immunity import (
    AnalystFeedback,
    ImmuneMemoryRecord,
    SecurityAlert,
)
from services.immunity import (
    IMMUNITY_CONTAINER_TAG,
    _search_similar,
    _store_memory,
    compute_confidence,
    evaluate_alert,
    generate_fingerprint,
    generate_recommendation,
    record_feedback,
)
from services.supermemory import SupermemoryClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _alert(**overrides) -> SecurityAlert:
    """Create a SecurityAlert with sensible defaults."""
    defaults = dict(
        alert_id="test-001",
        manufacturer="Philips",
        device_type="MRI",
        firmware_version="2.1",
        protocol="SMB",
        destination_port=445,
        mitre_technique="T1110",
        attack_category="Credential Attack",
        severity="high",
    )
    defaults.update(overrides)
    return SecurityAlert(**defaults)


def _memory_record(**overrides) -> ImmuneMemoryRecord:
    """Create an ImmuneMemoryRecord with sensible defaults."""
    defaults = dict(
        fingerprint="philips_mri_fw2_1_smb445_t1110_credential_attack",
        attack_type="Credential Attack",
        manufacturer="Philips",
        device_type="MRI",
        confidence=70.0,
        action_taken="blocked",
        false_positive=False,
        incident_summary="Previous credential attack on Philips MRI.",
    )
    defaults.update(overrides)
    return ImmuneMemoryRecord(**defaults)


def _mock_supermemory_client(stored_records: list[ImmuneMemoryRecord] | None = None):
    """Return a SupermemoryClient backed by an httpx.MockTransport.

    If `stored_records` is provided, search calls return their JSON representations.
    Both /v4/search and /v3/search return the same data so the fallback path
    also works correctly in tests.
    """
    docs: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v3/documents":
            body = json.loads(request.content)
            docs.append(body)
            return httpx.Response(201, json={"id": f"doc-{len(docs)}"})
        if request.method == "POST" and request.url.path in ("/v4/search", "/v3/search"):
            if stored_records:
                results = [{"content": r.model_dump_json()} for r in stored_records]
                return httpx.Response(200, json={"results": results})
            return httpx.Response(200, json={"results": []})
        if request.method == "POST" and request.url.path == "/v3/documents/list":
            return httpx.Response(200, json={"memories": docs})
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    return SupermemoryClient(base_url="http://sm.test", client=client), client, docs


def _mock_supermemory_client_with_fallback(
    stored_records: list[ImmuneMemoryRecord],
):
    """Mock that returns empty from /v4/search but data from /v3/search.

    Exercises the retrieval fallback path.
    """
    docs: list[dict] = []
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.method == "POST" and request.url.path == "/v3/documents":
            body = json.loads(request.content)
            docs.append(body)
            return httpx.Response(201, json={"id": f"doc-{len(docs)}"})
        if request.method == "POST" and request.url.path == "/v4/search":
            return httpx.Response(200, json={"results": []})
        if request.method == "POST" and request.url.path == "/v3/search":
            results = [{"content": r.model_dump_json()} for r in stored_records]
            return httpx.Response(200, json={"results": results})
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    return SupermemoryClient(base_url="http://sm.test", client=client), client, docs, paths


def _mock_supermemory_client_unavailable():
    """Mock that simulates Supermemory being completely down."""
    docs: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "service unavailable"})

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    return SupermemoryClient(base_url="http://sm.test", client=client, timeout=1), client, docs


# ===========================================================================
# Fingerprint Tests
# ===========================================================================
class FingerprintTests(unittest.TestCase):
    """Test immune fingerprint generation."""

    def test_basic_fingerprint(self) -> None:
        alert = _alert()
        fp = generate_fingerprint(alert)
        self.assertEqual(fp.fingerprint, "philips_mri_fw2_1_smb445_t1110_credential_attack")
        self.assertEqual(len(fp.components), 6)

    def test_fingerprint_is_ip_independent(self) -> None:
        """Same alert from different IPs must produce the same fingerprint."""
        fp1 = generate_fingerprint(_alert(source_ip="10.0.0.1"))
        fp2 = generate_fingerprint(_alert(source_ip="192.168.1.100"))
        self.assertEqual(fp1.fingerprint, fp2.fingerprint)

    def test_fingerprint_stability(self) -> None:
        """Identical inputs must always produce the exact same slug."""
        for _ in range(5):
            fp = generate_fingerprint(_alert())
            self.assertEqual(fp.fingerprint, "philips_mri_fw2_1_smb445_t1110_credential_attack")

    def test_fingerprint_with_missing_fields(self) -> None:
        """Missing optional fields should be excluded, not produce empty segments."""
        alert = SecurityAlert(manufacturer="Siemens", severity="low")
        fp = generate_fingerprint(alert)
        self.assertEqual(fp.fingerprint, "siemens")
        self.assertNotIn("__", fp.fingerprint)

    def test_fingerprint_normalizes_case_and_symbols(self) -> None:
        alert = _alert(manufacturer="GE Healthcare", attack_category="Brute-Force (SSH)")
        fp = generate_fingerprint(alert)
        self.assertNotIn(" ", fp.fingerprint)
        self.assertNotIn("(", fp.fingerprint)
        self.assertEqual(fp.fingerprint, fp.fingerprint.lower())

    def test_fingerprint_empty_alert(self) -> None:
        fp = generate_fingerprint(SecurityAlert())
        self.assertEqual(fp.fingerprint, "unknown")

    def test_fingerprint_includes_vulnerability(self) -> None:
        """Vulnerability field should be included in the fingerprint."""
        alert = _alert(vulnerability="CVE-2023-12345")
        fp = generate_fingerprint(alert)
        self.assertIn("cve_2023_12345", fp.fingerprint)

    def test_fingerprint_includes_behavioral_sequence(self) -> None:
        """Behavioral sequence should be included in the fingerprint."""
        alert = _alert(behavioral_sequence="scan_exploit_persist")
        fp = generate_fingerprint(alert)
        self.assertIn("scan_exploit_persist", fp.fingerprint)

    def test_fingerprint_includes_asset_role(self) -> None:
        """Asset role should be included in the fingerprint."""
        alert = _alert(asset_role="clinical")
        fp = generate_fingerprint(alert)
        self.assertIn("clinical", fp.fingerprint)


# ===========================================================================
# Confidence Scoring Tests
# ===========================================================================
class ConfidenceTests(unittest.TestCase):
    """Test the confidence scoring formula."""

    def test_base_score_by_severity(self) -> None:
        for severity, expected in [("critical", 85), ("high", 70), ("medium", 50), ("low", 30)]:
            score, _ = compute_confidence(severity, [])
            self.assertEqual(score, expected, f"Severity '{severity}' should yield {expected}")

    def test_confirmed_incidents_boost_confidence(self) -> None:
        """Previously confirmed true-positive records should increase confidence."""
        confirmed = [_memory_record(action_taken="blocked", false_positive=False)]
        score, reasoning = compute_confidence("medium", confirmed)
        # base 50 + 10 confirmed + 5 recurrence = 65
        self.assertEqual(score, 65)
        self.assertIn("confirmed", reasoning.lower())

    def test_confirmed_boost_capped(self) -> None:
        """Confirmed boost must not exceed the cap (30)."""
        many_confirmed = [_memory_record(action_taken=f"action-{i}", false_positive=False) for i in range(10)]
        score, _ = compute_confidence("medium", many_confirmed)
        # base 50 + cap 30 confirmed + cap 15 recurrence = 95
        self.assertEqual(score, 95)

    def test_false_positives_reduce_confidence(self) -> None:
        """False-positive records should penalize confidence."""
        fps = [_memory_record(false_positive=True, action_taken="")]
        score, reasoning = compute_confidence("high", fps)
        # base 70 + 0 confirmed + 5 recurrence - 15 FP = 60
        self.assertEqual(score, 60)
        self.assertIn("false-positive", reasoning.lower())

    def test_false_positive_penalty_capped(self) -> None:
        """FP penalty must not exceed the cap (30)."""
        many_fps = [_memory_record(false_positive=True) for _ in range(10)]
        score, _ = compute_confidence("high", many_fps)
        # base 70 + 0 confirmed + 15 recurrence (capped) - 30 FP (capped) = 55
        self.assertEqual(score, 55)

    def test_confidence_clamped_to_0_100(self) -> None:
        """Score should never go below 0 or above 100."""
        many_fps = [_memory_record(false_positive=True) for _ in range(20)]
        score, _ = compute_confidence("low", many_fps)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_mixed_history(self) -> None:
        """Mix of confirmed and false-positive records."""
        records = [
            _memory_record(action_taken="blocked", false_positive=False),
            _memory_record(action_taken="blocked", false_positive=False),
            _memory_record(false_positive=True, action_taken=""),
        ]
        score, _ = compute_confidence("high", records)
        # base 70 + 20 confirmed + 15 recurrence - 15 FP = 90
        self.assertEqual(score, 90)

    def test_unknown_severity_defaults_to_medium(self) -> None:
        """Unknown severity should fall back to base 50."""
        score, _ = compute_confidence("unknown", [])
        self.assertEqual(score, 50)


# ===========================================================================
# Recommendation Tests
# ===========================================================================
class RecommendationTests(unittest.TestCase):
    """Test recommendation generation."""

    def test_high_confidence_with_precedent_blocks(self) -> None:
        rec = generate_recommendation(
            _alert(severity="critical"),
            confidence=90,
            similar_records=[_memory_record(action_taken="blocked")],
        )
        self.assertIn("BLOCK IMMEDIATELY", rec)

    def test_all_false_positives_recommends_monitor(self) -> None:
        rec = generate_recommendation(
            _alert(),
            confidence=40,
            similar_records=[_memory_record(false_positive=True, action_taken="")],
        )
        self.assertIn("MONITOR", rec)
        self.assertIn("false positive", rec.lower())

    def test_high_confidence_no_precedent_blocks(self) -> None:
        rec = generate_recommendation(_alert(), confidence=85, similar_records=[])
        self.assertIn("BLOCK", rec)

    def test_medium_confidence_investigates(self) -> None:
        rec = generate_recommendation(_alert(), confidence=55, similar_records=[])
        self.assertIn("INVESTIGATE", rec)

    def test_low_confidence_logs(self) -> None:
        rec = generate_recommendation(_alert(severity="low"), confidence=25, similar_records=[])
        self.assertIn("LOG", rec)

    def test_mixed_records_mentions_false_positives(self) -> None:
        """When both confirmed and FP records exist, recommendation should note FPs."""
        records = [
            _memory_record(action_taken="blocked", false_positive=False),
            _memory_record(false_positive=True, action_taken=""),
        ]
        rec = generate_recommendation(_alert(), confidence=85, similar_records=records)
        self.assertIn("BLOCK IMMEDIATELY", rec)
        self.assertIn("false-positive", rec.lower())

    def test_medium_confidence_with_fp_history_warns(self) -> None:
        """Medium confidence with FP history should include a caution note.

        When both confirmed and FP records exist at medium confidence, the
        MONITOR path is skipped (because confirmed records exist) and the
        INVESTIGATE path should fire with a caution about FP history.
        """
        records = [
            _memory_record(false_positive=True, action_taken=""),
            _memory_record(false_positive=False, action_taken="blocked"),
        ]
        # confidence=55 => INVESTIGATE path (not >=80 so not BLOCK), FP history should be mentioned
        rec = generate_recommendation(_alert(), confidence=55, similar_records=records)
        self.assertIn("INVESTIGATE", rec)
        self.assertIn("false-positive", rec.lower())


# ===========================================================================
# Memory Search Tests
# ===========================================================================
class MemorySearchTests(unittest.TestCase):
    """Test searching and storing immune memory via mock Supermemory."""

    def test_search_returns_parsed_records(self) -> None:
        stored = [_memory_record(incident_summary="Previous attack on Philips MRI")]
        sm, http_client, _ = _mock_supermemory_client(stored_records=stored)

        async def run():
            try:
                return await _search_similar("philips_mri", client=sm)
            finally:
                await http_client.aclose()

        results = asyncio.run(run())
        self.assertEqual(len(results), 1)
        self.assertIn("Philips", results[0].incident_summary)

    def test_search_empty_returns_empty(self) -> None:
        sm, http_client, _ = _mock_supermemory_client(stored_records=None)

        async def run():
            try:
                return await _search_similar("nonexistent", client=sm)
            finally:
                await http_client.aclose()

        results = asyncio.run(run())
        self.assertEqual(results, [])

    def test_search_falls_back_to_v3_when_v4_empty(self) -> None:
        """When /v4/search returns nothing, should fall back to /v3/search."""
        stored = [_memory_record(incident_summary="Found via chunk search")]
        sm, http_client, _, paths = _mock_supermemory_client_with_fallback(stored)

        async def run():
            try:
                return await _search_similar("test_fp", client=sm)
            finally:
                await http_client.aclose()

        results = asyncio.run(run())
        self.assertEqual(len(results), 1)
        self.assertIn("Found via chunk search", results[0].incident_summary)
        self.assertIn("/v4/search", paths)
        self.assertIn("/v3/search", paths)

    def test_store_memory_writes_document(self) -> None:
        sm, http_client, docs = _mock_supermemory_client()

        async def run():
            try:
                return await _store_memory(_memory_record(), client=sm)
            finally:
                await http_client.aclose()

        doc_id = asyncio.run(run())
        self.assertEqual(doc_id, "doc-1")
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["containerTags"], [IMMUNITY_CONTAINER_TAG])

    def test_store_memory_includes_fingerprint_metadata(self) -> None:
        sm, http_client, docs = _mock_supermemory_client()

        async def run():
            try:
                return await _store_memory(
                    _memory_record(fingerprint="test_fp", attack_type="Scan"),
                    client=sm,
                )
            finally:
                await http_client.aclose()

        asyncio.run(run())
        metadata = docs[0].get("metadata", {})
        self.assertEqual(metadata["fingerprint"], "test_fp")
        self.assertEqual(metadata["type"], "immune-memory")


# ===========================================================================
# False-Positive Recall Tests
# ===========================================================================
class FalsePositiveRecallTests(unittest.TestCase):
    """Test that false-positive history is recalled and affects evaluation."""

    def test_false_positive_detected_in_evaluation(self) -> None:
        """An alert matching a known false-positive should flag it."""
        fp_record = _memory_record(false_positive=True, action_taken="ignored")
        sm, http_client, _ = _mock_supermemory_client(stored_records=[fp_record])

        async def run():
            try:
                return await evaluate_alert(_alert(), client=sm)
            finally:
                await http_client.aclose()

        with mock.patch("services.immunity.append_audit_entry"):
            result = asyncio.run(run())

        self.assertTrue(result.false_positive_history)
        self.assertIn("false-positive", result.reasoning.lower())

    def test_analyst_feedback_stored(self) -> None:
        """Analyst feedback should be persisted to Supermemory."""
        sm, http_client, docs = _mock_supermemory_client()
        feedback = AnalystFeedback(
            fingerprint="test_fp",
            is_false_positive=True,
            feedback_text="Benign scanner activity",
            action_taken="ignored",
        )

        async def run():
            try:
                return await record_feedback(feedback, client=sm)
            finally:
                await http_client.aclose()

        with mock.patch("services.immunity.append_audit_entry"):
            record = asyncio.run(run())

        self.assertTrue(record.false_positive)
        self.assertEqual(record.fingerprint, "test_fp")
        self.assertEqual(len(docs), 1)

    def test_analyst_confirmation_stored_with_action(self) -> None:
        """Confirmed incident feedback should store action_taken."""
        sm, http_client, docs = _mock_supermemory_client()
        feedback = AnalystFeedback(
            fingerprint="test_fp",
            is_false_positive=False,
            feedback_text="Confirmed credential brute-force",
            action_taken="blocked",
        )

        async def run():
            try:
                return await record_feedback(feedback, client=sm)
            finally:
                await http_client.aclose()

        with mock.patch("services.immunity.append_audit_entry"):
            record = asyncio.run(run())

        self.assertFalse(record.false_positive)
        self.assertEqual(record.action_taken, "blocked")
        stored_content = json.loads(docs[0]["content"])
        self.assertEqual(stored_content["action_taken"], "blocked")


# ===========================================================================
# Graceful Degradation Tests
# ===========================================================================
class GracefulDegradationTests(unittest.TestCase):
    """Test that the system degrades gracefully when Supermemory is unavailable."""

    def test_evaluate_alert_when_supermemory_down(self) -> None:
        """Evaluation should succeed even if Supermemory is completely down."""
        sm, http_client, _ = _mock_supermemory_client_unavailable()

        async def run():
            try:
                return await evaluate_alert(_alert(), client=sm)
            finally:
                await http_client.aclose()

        with mock.patch("services.immunity.append_audit_entry"):
            result = asyncio.run(run())

        # Should return a valid evaluation with baseline confidence.
        self.assertEqual(result.confidence, 70)  # base for "high"
        self.assertFalse(result.is_known_pattern)
        self.assertIn("unavailable", result.reasoning.lower())


# ===========================================================================
# Full Evaluation Pipeline Tests
# ===========================================================================
class EvaluationPipelineTests(unittest.TestCase):
    """Integration-style tests for the full evaluate_alert pipeline."""

    def test_novel_alert_evaluation(self) -> None:
        """A brand-new alert with no history should produce a baseline evaluation."""
        sm, http_client, docs = _mock_supermemory_client(stored_records=None)

        async def run():
            try:
                return await evaluate_alert(_alert(), client=sm)
            finally:
                await http_client.aclose()

        with mock.patch("services.immunity.append_audit_entry"):
            result = asyncio.run(run())

        self.assertFalse(result.is_known_pattern)
        self.assertFalse(result.false_positive_history)
        self.assertEqual(result.confidence, 70)  # base for "high" severity
        self.assertIn("philips", result.fingerprint.fingerprint)
        # Should have stored a new memory.
        self.assertEqual(len(docs), 1)

    def test_known_pattern_evaluation(self) -> None:
        """An alert matching confirmed history should boost confidence."""
        prior = _memory_record(action_taken="blocked", false_positive=False)
        sm, http_client, _ = _mock_supermemory_client(stored_records=[prior])

        async def run():
            try:
                return await evaluate_alert(_alert(), client=sm)
            finally:
                await http_client.aclose()

        with mock.patch("services.immunity.append_audit_entry"):
            result = asyncio.run(run())

        self.assertTrue(result.is_known_pattern)
        self.assertGreater(result.confidence, 70)  # boosted above base
        self.assertEqual(len(result.similar_incidents), 1)

    def test_evaluation_response_shape(self) -> None:
        """Ensure the response contains all required fields."""
        sm, http_client, _ = _mock_supermemory_client()

        async def run():
            try:
                return await evaluate_alert(_alert(), client=sm)
            finally:
                await http_client.aclose()

        with mock.patch("services.immunity.append_audit_entry"):
            result = asyncio.run(run())

        # All fields in ImmunityEvaluation should be present.
        self.assertIsNotNone(result.fingerprint)
        self.assertIsInstance(result.similar_incidents, list)
        self.assertIsInstance(result.confidence, float)
        self.assertIsInstance(result.recommendation, str)
        self.assertIsInstance(result.reasoning, str)
        self.assertIsInstance(result.is_known_pattern, bool)
        self.assertIsInstance(result.false_positive_history, bool)

    def test_evaluation_stores_with_evaluation_type(self) -> None:
        """Stored evaluation records should be typed as 'immune-evaluation'."""
        sm, http_client, docs = _mock_supermemory_client()

        async def run():
            try:
                return await evaluate_alert(_alert(), client=sm)
            finally:
                await http_client.aclose()

        with mock.patch("services.immunity.append_audit_entry"):
            asyncio.run(run())

        metadata = docs[0].get("metadata", {})
        self.assertEqual(metadata["type"], "immune-evaluation")

    def test_feedback_stores_with_feedback_type(self) -> None:
        """Stored feedback records should be typed as 'immune-feedback'."""
        sm, http_client, docs = _mock_supermemory_client()
        feedback = AnalystFeedback(
            fingerprint="test_fp", is_false_positive=True, action_taken="ignored"
        )

        async def run():
            try:
                return await record_feedback(feedback, client=sm)
            finally:
                await http_client.aclose()

        with mock.patch("services.immunity.append_audit_entry"):
            asyncio.run(run())

        metadata = docs[0].get("metadata", {})
        self.assertEqual(metadata["type"], "immune-feedback")


# ===========================================================================
# Edge Case Tests
# ===========================================================================
class EdgeCaseTests(unittest.TestCase):
    """Test edge cases and malformed inputs."""

    def test_alert_with_all_empty_fields(self) -> None:
        """Completely empty alert should not crash."""
        fp = generate_fingerprint(SecurityAlert())
        self.assertEqual(fp.fingerprint, "unknown")

    def test_very_long_fields_truncated(self) -> None:
        """Very long field values should not cause memory issues."""
        alert = _alert(raw_summary="A" * 100000)
        fp = generate_fingerprint(alert)
        self.assertIsNotNone(fp.fingerprint)

    def test_special_characters_in_fields(self) -> None:
        """Special characters should be normalized safely."""
        alert = _alert(
            manufacturer="<script>alert('xss')</script>",
            attack_category="'; DROP TABLE --",
        )
        fp = generate_fingerprint(alert)
        self.assertNotIn("<", fp.fingerprint)
        self.assertNotIn("'", fp.fingerprint)
        self.assertNotIn(";", fp.fingerprint)

    def test_unicode_in_fields(self) -> None:
        """Unicode characters should be handled."""
        alert = _alert(manufacturer="Siemens™", device_type="CT-Scanner®")
        fp = generate_fingerprint(alert)
        self.assertIsNotNone(fp.fingerprint)
        self.assertEqual(fp.fingerprint, fp.fingerprint.lower())


if __name__ == "__main__":
    unittest.main()
