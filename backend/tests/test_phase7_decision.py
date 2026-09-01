"""
test_phase7_decision.py

Tests for the SentinelAI Phase 7 Decision & Response Recommendation Engine.

Coverage:
1. DecisionEngine converts threat classification to safe decisions
2. Decision mapping (LOW→ALLOW, MEDIUM→ALERT, HIGH→ESCALATE)
3. Recommendations are deterministic and explainable
4. No destructive actions are performed
5. API endpoint includes decision field
6. Phase 1-6 behavior is not regressed
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.models.security_decision import Decision, RecommendedAction, SecurityDecision
from app.services.decision_engine import DecisionEngine
from app.main import app

client = TestClient(app)


# ======================================================================
# Test Fixtures and Helpers
# ======================================================================


def make_event(
    path: str,
    event_type: str = "created",
    event_id: str = "phase7-test-event",
) -> dict:
    """Create a valid raw filesystem event for testing."""
    return {
        "event_id": event_id,
        "event_type": event_type,
        "path": path,
        "timestamp": "2026-09-01T00:00:00+00:00",
        "is_directory": False,
        "destination_path": None,
    }


# ======================================================================
# Test 1 — DecisionEngine handles LOW threat level
# ======================================================================


def test_decision_engine_low_threat():
    """
    LOW threat level should produce ALLOW decision.
    """
    decision = DecisionEngine.make_decision(
        event_id="evt-low",
        threat_score=15,
        threat_level="LOW",
    )

    assert decision is not None
    assert decision.event_id == "evt-low"
    assert decision.threat_score == 15
    assert decision.threat_level == "LOW"
    assert decision.decision == Decision.ALLOW.value
    assert decision.recommended_action == RecommendedAction.NONE.value
    assert decision.automated_action is False
    assert "LOW" in decision.decision_reason


def test_decision_engine_low_boundary():
    """
    Test threat scores at LOW boundaries (0-30).
    """
    for score in [0, 1, 15, 30]:
        decision = DecisionEngine.make_decision(
            event_id=f"evt-low-{score}",
            threat_score=score,
            threat_level="LOW",
        )
        assert decision is not None
        assert decision.decision == Decision.ALLOW.value
        assert decision.recommended_action == RecommendedAction.NONE.value


# ======================================================================
# Test 2 — DecisionEngine handles MEDIUM threat level
# ======================================================================


def test_decision_engine_medium_threat():
    """
    MEDIUM threat level should produce ALERT decision with MONITOR recommendation.
    """
    decision = DecisionEngine.make_decision(
        event_id="evt-medium",
        threat_score=50,
        threat_level="MEDIUM",
    )

    assert decision is not None
    assert decision.threat_score == 50
    assert decision.threat_level == "MEDIUM"
    assert decision.decision == Decision.ALERT.value
    assert decision.recommended_action == RecommendedAction.MONITOR.value
    assert decision.automated_action is False
    assert "MEDIUM" in decision.decision_reason


def test_decision_engine_medium_boundary():
    """
    Test threat scores at MEDIUM boundaries (31-60).
    """
    for score in [31, 45, 60]:
        decision = DecisionEngine.make_decision(
            event_id=f"evt-med-{score}",
            threat_score=score,
            threat_level="MEDIUM",
        )
        assert decision is not None
        assert decision.decision == Decision.ALERT.value
        assert decision.recommended_action == RecommendedAction.MONITOR.value


# ======================================================================
# Test 3 — DecisionEngine handles HIGH threat level
# ======================================================================


def test_decision_engine_high_threat():
    """
    HIGH threat level should produce ESCALATE decision with REVIEW recommendation.
    """
    decision = DecisionEngine.make_decision(
        event_id="evt-high",
        threat_score=75,
        threat_level="HIGH",
    )

    assert decision is not None
    assert decision.threat_score == 75
    assert decision.threat_level == "HIGH"
    assert decision.decision == Decision.ESCALATE.value
    assert decision.recommended_action == RecommendedAction.REVIEW.value
    assert decision.automated_action is False
    assert "HIGH" in decision.decision_reason


def test_decision_engine_high_boundary():
    """
    Test threat scores at HIGH boundaries (61-85).
    """
    for score in [61, 75, 85]:
        decision = DecisionEngine.make_decision(
            event_id=f"evt-high-{score}",
            threat_score=score,
            threat_level="HIGH",
        )
        assert decision is not None
        assert decision.decision == Decision.ESCALATE.value
        assert decision.recommended_action == RecommendedAction.REVIEW.value


# ======================================================================
# Test 4 — DecisionEngine handles CRITICAL threat level
# ======================================================================


def test_decision_engine_critical_threat():
    """
    CRITICAL threat level should produce ESCALATE decision with REVIEW recommendation.
    """
    decision = DecisionEngine.make_decision(
        event_id="evt-critical",
        threat_score=95,
        threat_level="CRITICAL",
    )

    assert decision is not None
    assert decision.threat_score == 95
    assert decision.threat_level == "CRITICAL"
    assert decision.decision == Decision.ESCALATE.value
    assert decision.recommended_action == RecommendedAction.REVIEW.value
    assert decision.automated_action is False
    assert "CRITICAL" in decision.decision_reason


def test_decision_engine_critical_boundary():
    """
    Test threat scores at CRITICAL boundaries (86-100).
    """
    for score in [86, 95, 100]:
        decision = DecisionEngine.make_decision(
            event_id=f"evt-crit-{score}",
            threat_score=score,
            threat_level="CRITICAL",
        )
        assert decision is not None
        assert decision.decision == Decision.ESCALATE.value
        assert decision.recommended_action == RecommendedAction.REVIEW.value


# ======================================================================
# Test 5 — Decision explanation is meaningful
# ======================================================================


def test_decision_reason_is_meaningful():
    """
    Each decision should include a meaningful, non-empty reason.
    """
    threats = [
        ("LOW", 10),
        ("MEDIUM", 45),
        ("HIGH", 70),
        ("CRITICAL", 90),
    ]

    for level, score in threats:
        decision = DecisionEngine.make_decision(
            event_id=f"evt-reason-{level}",
            threat_score=score,
            threat_level=level,
        )
        assert decision is not None
        assert decision.decision_reason
        assert len(decision.decision_reason) > 10
        assert level in decision.decision_reason


# ======================================================================
# Test 6 — No destructive actions are performed
# ======================================================================


def test_decision_engine_no_destructive_actions():
    """
    Verify that decisions never enable destructive actions.
    automated_action must always be False in Phase 7.
    """
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        decision = DecisionEngine.make_decision(
            event_id=f"evt-safe-{level}",
            threat_score=50,
            threat_level=level,
        )
        assert decision is not None
        assert decision.automated_action is False


# ======================================================================
# Test 7 — SecurityAgent integration via API
# ======================================================================


def test_api_includes_decision_field():
    """
    The /api/security/analyze endpoint should include a decision field.
    """
    response = client.post(
        "/api/security/analyze",
        json=make_event("C:/sandbox/phase7_test.exe", event_type="created", event_id="api-test-001"),
    )

    assert response.status_code == 200
    payload = response.json()

    # Verify decision field exists
    assert "decision" in payload
    decision = payload["decision"]

    # Verify decision structure
    assert "event_id" in decision
    assert "threat_score" in decision
    assert "threat_level" in decision
    assert "decision" in decision
    assert "recommended_action" in decision
    assert "automated_action" in decision
    assert "decision_reason" in decision
    assert "decision_timestamp" in decision

    # Verify decision values
    assert decision["event_id"] == "api-test-001"
    assert decision["automated_action"] is False


# ======================================================================
# Test 8 — API decision matches threat level
# ======================================================================


def test_api_decision_matches_threat_level():
    """
    Verify the decision mapping through the API.
    """
    # Test with HIGH threat (should trigger ESCALATE)
    response = client.post(
        "/api/security/analyze",
        json=make_event("C:/sandbox/malware.exe", event_type="created", event_id="api-threat-high"),
    )

    assert response.status_code == 200
    payload = response.json()

    # .exe files typically have high threat scores
    if payload["threat_level"] in {"HIGH", "CRITICAL"}:
        assert payload["decision"]["decision"] == "ESCALATE"
        assert payload["decision"]["recommended_action"] == "REVIEW"

    # Test with LOW threat (should trigger ALLOW)
    response = client.post(
        "/api/security/analyze",
        json=make_event("C:/sandbox/document.txt", event_type="created", event_id="api-threat-low"),
    )

    assert response.status_code == 200
    payload = response.json()

    if payload["threat_level"] == "LOW":
        assert payload["decision"]["decision"] == "ALLOW"
        assert payload["decision"]["recommended_action"] == "NONE"


# ======================================================================
# Test 9 — API preserves Phase 6 fields (backward compatibility)
# ======================================================================


def test_api_backward_compatibility():
    """
    The API response must include all Phase 6 fields for backward compatibility.
    """
    response = client.post(
        "/api/security/analyze",
        json=make_event("C:/sandbox/compat_test.exe", event_type="created", event_id="compat-001"),
    )

    assert response.status_code == 200
    payload = response.json()

    # Phase 6 fields must be present
    assert "id" in payload
    assert "event_id" in payload
    assert "security_event" in payload
    assert "investigation" in payload
    assert "analysis" in payload
    assert "suspicion_score" in payload
    assert "threat_score" in payload
    assert "threat_level" in payload
    assert "findings" in payload
    assert "reasons" in payload
    assert "processing_timestamp" in payload

    # Phase 7 field must be present
    assert "decision" in payload


# ======================================================================
# Test 10 — Invalid threat levels handled safely
# ======================================================================


def test_decision_engine_rejects_invalid_threat_level():
    """
    Invalid threat levels should be rejected safely.
    """
    result = DecisionEngine.make_decision(
        event_id="evt-invalid",
        threat_score=50,
        threat_level="INVALID",
    )

    assert result is None


def test_decision_engine_rejects_invalid_score():
    """
    Invalid threat scores should be rejected safely.
    """
    result = DecisionEngine.make_decision(
        event_id="evt-bad-score",
        threat_score="not-a-number",
        threat_level="HIGH",
    )

    assert result is None


def test_decision_engine_rejects_missing_event_id():
    """
    Missing event IDs should be rejected safely.
    """
    result = DecisionEngine.make_decision(
        event_id=None,
        threat_score=50,
        threat_level="HIGH",
    )

    assert result is None


# ======================================================================
# Test 11 — SecurityDecision model properties
# ======================================================================


def test_security_decision_to_dict():
    """
    SecurityDecision should have a proper to_dict() method.
    """
    decision = SecurityDecision.create(
        event_id="evt-dict",
        threat_score=75,
        threat_level="HIGH",
        decision=Decision.ESCALATE.value,
        recommended_action=RecommendedAction.REVIEW.value,
        decision_reason="Test reason",
    )

    d = decision.to_dict()

    assert isinstance(d, dict)
    assert d["event_id"] == "evt-dict"
    assert d["threat_score"] == 75
    assert d["threat_level"] == "HIGH"
    assert d["decision"] == "ESCALATE"
    assert d["recommended_action"] == "REVIEW"
    assert d["automated_action"] is False


def test_security_decision_timestamp():
    """
    SecurityDecision should have a valid timestamp.
    """
    decision = SecurityDecision.create(
        event_id="evt-ts",
        threat_score=50,
        threat_level="MEDIUM",
        decision=Decision.ALERT.value,
        recommended_action=RecommendedAction.MONITOR.value,
        decision_reason="Test",
    )

    assert decision.decision_timestamp
    assert "T" in decision.decision_timestamp  # ISO format check
    assert "Z" in decision.decision_timestamp or "+" in decision.decision_timestamp  # timezone


# ======================================================================
# Test 12 — Decision clamping of threat scores
# ======================================================================


def test_decision_engine_clamps_negative_score():
    """
    Negative threat scores should be clamped to 0.
    """
    decision = DecisionEngine.make_decision(
        event_id="evt-neg",
        threat_score=-50,
        threat_level="LOW",
    )

    assert decision is not None
    assert decision.threat_score == 0


def test_decision_engine_clamps_high_score():
    """
    Scores above 100 should be clamped to 100.
    """
    decision = DecisionEngine.make_decision(
        event_id="evt-over",
        threat_score=150,
        threat_level="CRITICAL",
    )

    assert decision is not None
    assert decision.threat_score == 100


# ======================================================================
# Test 13 — Full integration with real execution scenario
# ======================================================================


def test_full_integration_executable_event(tmp_path):
    """
    Full end-to-end test with a real .exe file event.
    Mimics the Phase 7 manual test scenario.
    """
    file_path = tmp_path / "phase7-test.exe"
    file_path.write_text("fake executable")

    response = client.post(
        "/api/security/analyze",
        json={
            "event_id": "phase7-manual-test-001",
            "event_type": "created",
            "path": str(file_path),
            "timestamp": "2026-09-01T13:00:00+05:30",
            "is_directory": False,
            "destination_path": None,
        },
    )

    assert response.status_code == 200
    payload = response.json()

    # Verify analysis
    assert payload["event_id"] == "phase7-manual-test-001"
    assert payload["security_event"]["extension"] == ".exe"

    # Verify threat classification
    assert 0 <= payload["threat_score"] <= 100
    assert payload["threat_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    # Verify decision
    assert "decision" in payload
    decision = payload["decision"]
    assert decision["automated_action"] is False

    # HIGH threat .exe should escalate
    if payload["threat_level"] in {"HIGH", "CRITICAL"}:
        assert decision["decision"] == "ESCALATE"
        assert decision["recommended_action"] == "REVIEW"


# ======================================================================
# Test 14 — Case-insensitive threat level handling
# ======================================================================


def test_decision_engine_case_insensitive():
    """
    Threat levels should be case-insensitive.
    """
    for variant in ["low", "Low", "LOW", "lOw"]:
        decision = DecisionEngine.make_decision(
            event_id=f"evt-case-{variant}",
            threat_score=15,
            threat_level=variant,
        )
        assert decision is not None
        assert decision.threat_level == "LOW"
        assert decision.decision == "ALLOW"
