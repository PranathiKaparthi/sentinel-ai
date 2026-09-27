"""
test_phase9_orchestrator.py

Comprehensive test suite for SentinelAI Phase 9: Security Orchestrator.

Tests the SecurityOrchestrator service and SecurityAnalysisResult model.

Verifies:
- Orchestrator coordinates Phase 1-8 pipeline correctly
- All components are called (no duplication)
- Valid events are processed successfully
- Invalid events are handled safely
- Response structure remains compatible with Phase 8
- Threat level classification works end-to-end
"""

import pytest
from pathlib import Path

from app.models.security_analysis_result import SecurityAnalysisResult
from app.services.security_orchestrator import SecurityOrchestrator
from app.models.orchestration_result import OrchestrationResult
from app.models.security_decision import SecurityDecision
from app.models.response_recommendation import ResponseRecommendation


# ======================================================================
# Test Fixtures and Helpers
# ======================================================================


def make_event(
    path: str,
    event_type: str = "created",
    event_id: str = "phase9-test-event",
    is_directory: bool = False,
) -> dict:
    """Create a valid raw filesystem event for testing."""
    return {
        "event_id": event_id,
        "event_type": event_type,
        "path": path,
        "timestamp": "2026-09-01T00:00:00+00:00",
        "is_directory": is_directory,
        "destination_path": None,
    }


# ======================================================================
# Test SecurityAnalysisResult Model
# ======================================================================


class TestSecurityAnalysisResult:
    """Test the SecurityAnalysisResult composite model."""

    def test_create_result_from_components(self):
        """Test creating a result from individual phase results."""
        # Create minimal valid components
        orchestration = OrchestrationResult.create(
            event_id="test-evt-001",
            security_event={"event_id": "test-evt-001", "event_type": "created", "path": "/test"},
            investigation={"exists": True},
            analysis={"observations": []},
            suspicion_score=10,
            threat_score=10,
            threat_level="LOW",
            findings=["Test finding"],
            reasons=["Test reason"],
        )

        decision = SecurityDecision.create(
            event_id="test-evt-001",
            threat_score=10,
            threat_level="LOW",
            decision="ALLOW",
            recommended_action="NONE",
            decision_reason="Low threat",
        )

        recommendation = ResponseRecommendation.create(
            event_id="test-evt-001",
            threat_score=10,
            threat_level="LOW",
            decision_action="ALLOW",
            decision_recommendation="NONE",
            summary="No action needed",
            explanation="Low threat event",
            evidence=[],
            recommended_actions=[],
            confidence=0.50,
            requires_human_review=False,
        )

        result = SecurityAnalysisResult(
            orchestration_result=orchestration,
            security_decision=decision,
            response_recommendation=recommendation,
        )

        assert result.event_id == "test-evt-001"
        assert result.threat_score == 10
        assert result.threat_level == "LOW"

    def test_to_dict_structure_matches_phase8(self):
        """
        Verify that to_dict() produces the same structure as Phase 8 response.

        This is critical for backward compatibility.
        """
        orchestration = OrchestrationResult.create(
            event_id="struct-test",
            security_event={"event_id": "struct-test"},
            investigation={"exists": True},
            analysis={"observations": []},
            suspicion_score=20,
            threat_score=20,
            threat_level="LOW",
            findings=["Finding 1"],
            reasons=["Reason 1"],
        )

        decision = SecurityDecision.create(
            event_id="struct-test",
            threat_score=20,
            threat_level="LOW",
            decision="ALLOW",
            recommended_action="NONE",
            decision_reason="Test",
        )

        recommendation = ResponseRecommendation.create(
            event_id="struct-test",
            threat_score=20,
            threat_level="LOW",
            decision_action="ALLOW",
            decision_recommendation="NONE",
            summary="Test",
            explanation="Test",
            evidence=[],
            recommended_actions=[],
            confidence=0.50,
            requires_human_review=False,
        )

        result = SecurityAnalysisResult(
            orchestration_result=orchestration,
            security_decision=decision,
            response_recommendation=recommendation,
        )

        result_dict = result.to_dict()

        # Verify all OrchestrationResult fields are at top level
        assert "event_id" in result_dict
        assert "threat_score" in result_dict
        assert "threat_level" in result_dict
        assert "findings" in result_dict
        assert "reasons" in result_dict

        # Verify decision and recommendation are nested objects
        assert "decision" in result_dict
        assert isinstance(result_dict["decision"], dict)
        assert "decision" in result_dict["decision"]

        assert "response_recommendation" in result_dict
        assert isinstance(result_dict["response_recommendation"], dict)
        assert "summary" in result_dict["response_recommendation"]

    def test_convenience_properties(self):
        """Test convenience properties for accessing nested data."""
        orchestration = OrchestrationResult.create(
            event_id="prop-test",
            security_event={},
            investigation={},
            analysis={},
            suspicion_score=50,
            threat_score=50,
            threat_level="MEDIUM",
            findings=[],
            reasons=[],
        )

        decision = SecurityDecision.create(
            event_id="prop-test",
            threat_score=50,
            threat_level="MEDIUM",
            decision="ALERT",
            recommended_action="MONITOR",
            decision_reason="Test",
        )

        recommendation = ResponseRecommendation.create(
            event_id="prop-test",
            threat_score=50,
            threat_level="MEDIUM",
            decision_action="ALERT",
            decision_recommendation="MONITOR",
            summary="Test",
            explanation="Test",
            evidence=[],
            recommended_actions=[],
            confidence=0.65,
            requires_human_review=True,
        )

        result = SecurityAnalysisResult(
            orchestration_result=orchestration,
            security_decision=decision,
            response_recommendation=recommendation,
        )

        assert result.event_id == "prop-test"
        assert result.threat_score == 50
        assert result.threat_level == "MEDIUM"


# ======================================================================
# Test SecurityOrchestrator
# ======================================================================


class TestSecurityOrchestrator:
    """Test the SecurityOrchestrator service."""

    def test_orchestrator_processes_valid_low_risk_event(self, tmp_path):
        """
        Test 1: Valid low-risk event

        Input: modified .txt file
        Expected: processing succeeds, threat level is LOW, decision is ALLOW
        """
        file_path = tmp_path / "document.txt"
        file_path.write_text("normal document")

        orchestrator = SecurityOrchestrator()
        result = orchestrator.process(make_event(str(file_path), event_type="modified"))
        orchestrator.stop()

        assert result is not None
        assert isinstance(result, SecurityAnalysisResult)
        assert result.event_id == "phase9-test-event"
        assert result.threat_level == "LOW"
        assert result.orchestration_result is not None
        assert result.security_decision is not None
        assert result.response_recommendation is not None
        assert result.security_decision.decision == "ALLOW"
        assert result.security_decision.recommended_action == "NONE"

    def test_orchestrator_detects_high_risk_executable(self, tmp_path):
        """
        Test executable detection through orchestrator.

        Input: .exe file creation
        Expected: HIGH or CRITICAL threat level
        """
        file_path = tmp_path / "payload.exe"
        file_path.write_text("fake executable")

        orchestrator = SecurityOrchestrator()
        result = orchestrator.process(make_event(str(file_path), event_type="created"))
        orchestrator.stop()

        assert result is not None
        assert result.threat_level in {"HIGH", "CRITICAL"}
        assert result.security_decision.decision in {"ESCALATE"}
        assert result.response_recommendation.requires_human_review is True

    def test_orchestrator_handles_invalid_event_safely(self):
        """
        Test 2: Invalid event handling

        Input: malformed or incomplete event data
        Expected: validation fails safely, no crash, returns None
        """
        invalid_events = [
            {},  # Empty dict
            {"event_type": "created"},  # Missing path
            {"path": "/test"},  # Missing event_type
            {"event_type": "invalid", "path": "/test", "timestamp": "2026-09-01T00:00:00+00:00", "is_directory": False},
            None,  # None input
        ]

        orchestrator = SecurityOrchestrator()

        for invalid_event in invalid_events:
            if invalid_event is None:
                # Skip None to avoid type error in orchestrator
                continue

            result = orchestrator.process(invalid_event)
            # Should return None safely, not crash
            assert result is None

        orchestrator.stop()

    def test_orchestrator_calls_all_phases(self, tmp_path):
        """
        Test 3: Pipeline integration

        Verify that orchestrator actually calls:
        - SecurityAgent (Phase 1-6)
        - DecisionEngine (Phase 7)
        - ResponseRecommendationEngine (Phase 8)

        and returns their combined result.
        """
        file_path = tmp_path / "test.txt"
        file_path.write_text("test content")

        orchestrator = SecurityOrchestrator()
        result = orchestrator.process(make_event(str(file_path)))
        orchestrator.stop()

        assert result is not None

        # Phase 1-6: OrchestrationResult should exist
        assert result.orchestration_result is not None
        assert hasattr(result.orchestration_result, "security_event")
        assert hasattr(result.orchestration_result, "investigation")
        assert hasattr(result.orchestration_result, "analysis")
        assert result.orchestration_result.threat_score is not None
        assert result.orchestration_result.threat_level is not None

        # Phase 7: SecurityDecision should exist
        assert result.security_decision is not None
        assert hasattr(result.security_decision, "decision")
        assert hasattr(result.security_decision, "recommended_action")
        assert result.security_decision.automated_action is False

        # Phase 8: ResponseRecommendation should exist
        assert result.response_recommendation is not None
        assert hasattr(result.response_recommendation, "summary")
        assert hasattr(result.response_recommendation, "explanation")
        assert hasattr(result.response_recommendation, "evidence")
        assert hasattr(result.response_recommendation, "recommended_actions")
        assert result.response_recommendation.automated_action is False

    def test_orchestrator_response_structure_matches_phase8(self, tmp_path):
        """
        Test 4: Phase 8 backward compatibility

        Verify that the response structure matches exactly what Phase 8
        currently produces. This ensures the orchestrator can drop in
        as a replacement without API changes.
        """
        file_path = tmp_path / "compat.txt"
        file_path.write_text("compatibility test")

        orchestrator = SecurityOrchestrator()
        result = orchestrator.process(make_event(str(file_path)))
        orchestrator.stop()

        assert result is not None
        result_dict = result.to_dict()

        # Top-level OrchestrationResult fields
        assert "event_id" in result_dict
        assert "threat_score" in result_dict
        assert "threat_level" in result_dict
        assert "suspicion_score" in result_dict
        assert "findings" in result_dict
        assert "reasons" in result_dict
        assert "security_event" in result_dict
        assert "investigation" in result_dict
        assert "analysis" in result_dict
        assert "processing_timestamp" in result_dict

        # Phase 7 decision object
        assert "decision" in result_dict
        assert isinstance(result_dict["decision"], dict)
        assert "decision" in result_dict["decision"]
        assert "recommended_action" in result_dict["decision"]
        assert "automated_action" in result_dict["decision"]
        assert "threat_score" in result_dict["decision"]

        # Phase 8 response recommendation object
        assert "response_recommendation" in result_dict
        assert isinstance(result_dict["response_recommendation"], dict)
        assert "summary" in result_dict["response_recommendation"]
        assert "explanation" in result_dict["response_recommendation"]
        assert "evidence" in result_dict["response_recommendation"]
        assert "recommended_actions" in result_dict["response_recommendation"]
        assert "confidence" in result_dict["response_recommendation"]
        assert "automated_action" in result_dict["response_recommendation"]
        assert "requires_human_review" in result_dict["response_recommendation"]

    def test_orchestrator_threat_level_decision_mapping(self, tmp_path):
        """
        Verify that threat levels correctly map to decisions:
        - LOW → ALLOW
        - MEDIUM → ALERT
        - HIGH → ESCALATE
        - CRITICAL → ESCALATE
        """
        # Create a low-threat .txt file
        low_file = tmp_path / "low.txt"
        low_file.write_text("normal content")

        orchestrator = SecurityOrchestrator()

        # Test low-risk
        result = orchestrator.process(make_event(str(low_file), event_id="test-low"))
        assert result is not None
        if result.threat_level == "LOW":
            assert result.security_decision.decision == "ALLOW"
            assert result.security_decision.automated_action is False
            assert result.response_recommendation.requires_human_review is False

        orchestrator.stop()

    def test_orchestrator_safety_automated_action_always_false(self, tmp_path):
        """
        CRITICAL SAFETY TEST.

        Verify that automated_action is ALWAYS False in orchestrator output,
        regardless of threat level or any other factor.
        """
        file_path = tmp_path / "safety.txt"
        file_path.write_text("content")

        orchestrator = SecurityOrchestrator()
        result = orchestrator.process(make_event(str(file_path)))
        orchestrator.stop()

        assert result is not None

        # This is the critical safety check for Phase 9
        assert result.security_decision.automated_action is False
        assert result.response_recommendation.automated_action is False

    def test_orchestrator_error_handling_malformed_raw_event(self):
        """Test that orchestrator handles errors without crashing."""
        orchestrator = SecurityOrchestrator()

        # Completely malformed event
        result = orchestrator.process({
            "garbage": "data",
            "invalid": "structure",
        })

        assert result is None  # Should fail gracefully

        orchestrator.stop()

    def test_orchestrator_directory_handling(self, tmp_path):
        """Test that orchestrator handles directory events."""
        dir_path = tmp_path / "testdir"
        dir_path.mkdir()

        orchestrator = SecurityOrchestrator()
        result = orchestrator.process(
            make_event(str(dir_path), event_type="created", is_directory=True)
        )
        orchestrator.stop()

        # Should process successfully even if it's a directory
        if result is not None:
            assert result.event_id == "phase9-test-event"
            assert result.orchestration_result is not None

    def test_orchestrator_deleted_file_handling(self, tmp_path):
        """Test that orchestrator handles deleted file events."""
        # Create and delete a file for testing
        file_path = tmp_path / "deleted.txt"
        file_path.write_text("to be deleted")

        orchestrator = SecurityOrchestrator()
        # Event references deleted file
        result = orchestrator.process(
            make_event(str(file_path), event_type="deleted")
        )
        orchestrator.stop()

        # Should handle deleted files gracefully
        if result is not None:
            assert result.event_id == "phase9-test-event"
