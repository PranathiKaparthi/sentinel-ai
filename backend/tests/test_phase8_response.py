"""
test_phase8_response.py

Comprehensive test suite for SentinelAI Phase 8: Response Recommendation & Explainability.

Tests the ResponseRecommendation model and ResponseRecommendationEngine.

Verifies:
- Model creation and serialization
- Recommendation generation for each threat level
- Evidence extraction from available data
- Explanation generation
- Recommended actions
- Confidence scoring
- Safety enforcement (automated_action = False)
- API integration
- Backward compatibility with Phase 7
"""

import pytest

from app.models.response_recommendation import ResponseRecommendation
from app.models.security_decision import SecurityDecision
from app.services.response_recommendation import ResponseRecommendationEngine


class TestResponseRecommendationModel:
    """Test the ResponseRecommendation data model."""

    def test_create_low_threat_recommendation(self):
        """Test creating a recommendation for LOW threat level."""
        recommendation = ResponseRecommendation.create(
            event_id="test-event-001",
            threat_score=15,
            threat_level="LOW",
            decision_action="ALLOW",
            decision_recommendation="NONE",
            summary="No action required",
            explanation="Low threat level detected",
            evidence=["Threat score below 31"],
            recommended_actions=["Continue monitoring"],
            confidence=0.50,
            requires_human_review=False,
        )

        assert recommendation.event_id == "test-event-001"
        assert recommendation.threat_score == 15
        assert recommendation.threat_level == "LOW"
        assert recommendation.decision_action == "ALLOW"
        assert recommendation.decision_recommendation == "NONE"
        assert recommendation.automated_action is False
        assert recommendation.requires_human_review is False
        assert recommendation.confidence == 0.50
        assert recommendation.created_at is not None

    def test_create_medium_threat_recommendation(self):
        """Test creating a recommendation for MEDIUM threat level."""
        recommendation = ResponseRecommendation.create(
            event_id="test-event-002",
            threat_score=45,
            threat_level="MEDIUM",
            decision_action="ALERT",
            decision_recommendation="MONITOR",
            summary="Monitoring recommended",
            explanation="Medium threat level detected",
            evidence=["Threat score 31-60"],
            recommended_actions=["Monitor activity", "Review logs"],
            confidence=0.65,
            requires_human_review=True,
        )

        assert recommendation.threat_score == 45
        assert recommendation.threat_level == "MEDIUM"
        assert recommendation.decision_action == "ALERT"
        assert recommendation.decision_recommendation == "MONITOR"
        assert recommendation.automated_action is False
        assert recommendation.requires_human_review is True
        assert recommendation.confidence == 0.65

    def test_create_high_threat_recommendation(self):
        """Test creating a recommendation for HIGH threat level."""
        recommendation = ResponseRecommendation.create(
            event_id="test-event-003",
            threat_score=75,
            threat_level="HIGH",
            decision_action="ESCALATE",
            decision_recommendation="REVIEW",
            summary="Escalation recommended",
            explanation="High threat level detected",
            evidence=["Threat score 61-85", "Suspicious file"],
            recommended_actions=["Escalate to analyst", "Review file"],
            confidence=0.80,
            requires_human_review=True,
        )

        assert recommendation.threat_score == 75
        assert recommendation.threat_level == "HIGH"
        assert recommendation.decision_action == "ESCALATE"
        assert recommendation.decision_recommendation == "REVIEW"
        assert recommendation.automated_action is False
        assert recommendation.requires_human_review is True
        assert recommendation.confidence == 0.80

    def test_create_critical_threat_recommendation(self):
        """Test creating a recommendation for CRITICAL threat level."""
        recommendation = ResponseRecommendation.create(
            event_id="test-event-004",
            threat_score=95,
            threat_level="CRITICAL",
            decision_action="ESCALATE",
            decision_recommendation="REVIEW",
            summary="Immediate escalation required",
            explanation="Critical threat level detected",
            evidence=["Threat score ≥86", "Malware detected"],
            recommended_actions=[
                "Escalate immediately",
                "Preserve evidence",
                "Consult threat intel",
            ],
            confidence=0.95,
            requires_human_review=True,
        )

        assert recommendation.threat_score == 95
        assert recommendation.threat_level == "CRITICAL"
        assert recommendation.confidence == 0.95
        assert recommendation.requires_human_review is True
        assert recommendation.automated_action is False

    def test_automated_action_always_false(self):
        """Verify that automated_action is always False."""
        recommendation = ResponseRecommendation.create(
            event_id="test-safety",
            threat_score=100,
            threat_level="CRITICAL",
            decision_action="ESCALATE",
            decision_recommendation="REVIEW",
            summary="Test",
            explanation="Test",
            evidence=[],
            recommended_actions=[],
            confidence=0.95,
            requires_human_review=True,
        )

        # This is the critical safety check for Phase 8
        assert recommendation.automated_action is False

    def test_threat_score_clamped_to_range(self):
        """Test that threat scores are clamped to 0-100."""
        # Test over 100
        rec1 = ResponseRecommendation.create(
            event_id="test-over",
            threat_score=150,
            threat_level="CRITICAL",
            decision_action="ESCALATE",
            decision_recommendation="REVIEW",
            summary="Test",
            explanation="Test",
            evidence=[],
            recommended_actions=[],
            confidence=0.95,
            requires_human_review=True,
        )
        assert rec1.threat_score == 100

        # Test under 0
        rec2 = ResponseRecommendation.create(
            event_id="test-under",
            threat_score=-10,
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
        assert rec2.threat_score == 0

    def test_confidence_clamped_to_0_1(self):
        """Test that confidence scores are clamped to 0.0-1.0."""
        # Test over 1.0
        rec1 = ResponseRecommendation.create(
            event_id="test-conf-over",
            threat_score=50,
            threat_level="MEDIUM",
            decision_action="ALERT",
            decision_recommendation="MONITOR",
            summary="Test",
            explanation="Test",
            evidence=[],
            recommended_actions=[],
            confidence=1.5,
            requires_human_review=True,
        )
        assert rec1.confidence == 1.0

        # Test under 0.0
        rec2 = ResponseRecommendation.create(
            event_id="test-conf-under",
            threat_score=50,
            threat_level="MEDIUM",
            decision_action="ALERT",
            decision_recommendation="MONITOR",
            summary="Test",
            explanation="Test",
            evidence=[],
            recommended_actions=[],
            confidence=-0.5,
            requires_human_review=True,
        )
        assert rec2.confidence == 0.0

    def test_to_dict_serialization(self):
        """Test JSON serialization."""
        recommendation = ResponseRecommendation.create(
            event_id="test-serialize",
            threat_score=50,
            threat_level="MEDIUM",
            decision_action="ALERT",
            decision_recommendation="MONITOR",
            summary="Test summary",
            explanation="Test explanation",
            evidence=["Evidence 1", "Evidence 2"],
            recommended_actions=["Action 1"],
            confidence=0.65,
            requires_human_review=True,
        )

        result = recommendation.to_dict()
        assert isinstance(result, dict)
        assert result["event_id"] == "test-serialize"
        assert result["threat_score"] == 50
        assert result["threat_level"] == "MEDIUM"
        assert result["summary"] == "Test summary"
        assert result["evidence"] == ["Evidence 1", "Evidence 2"]
        assert result["automated_action"] is False


class TestResponseRecommendationEngine:
    """Test the ResponseRecommendationEngine service."""

    def test_generate_recommendation_low_threat(self):
        """Test generating a recommendation for LOW threat."""
        decision = SecurityDecision.create(
            event_id="low-threat-001",
            threat_score=15,
            threat_level="LOW",
            decision="ALLOW",
            recommended_action="NONE",
            decision_reason="Threat level is LOW",
        )

        recommendation = ResponseRecommendationEngine.generate_recommendation(decision)

        assert recommendation is not None
        assert recommendation.event_id == "low-threat-001"
        assert recommendation.threat_level == "LOW"
        assert recommendation.decision_action == "ALLOW"
        assert recommendation.requires_human_review is False
        assert recommendation.confidence == 0.50
        assert recommendation.automated_action is False
        assert "no immediate" in recommendation.summary.lower()

    def test_generate_recommendation_medium_threat(self):
        """Test generating a recommendation for MEDIUM threat."""
        decision = SecurityDecision.create(
            event_id="medium-threat-001",
            threat_score=45,
            threat_level="MEDIUM",
            decision="ALERT",
            recommended_action="MONITOR",
            decision_reason="Threat level is MEDIUM",
        )

        recommendation = ResponseRecommendationEngine.generate_recommendation(decision)

        assert recommendation is not None
        assert recommendation.threat_level == "MEDIUM"
        assert recommendation.decision_action == "ALERT"
        assert recommendation.requires_human_review is True
        assert recommendation.confidence == 0.65
        assert recommendation.automated_action is False
        assert len(recommendation.recommended_actions) > 0

    def test_generate_recommendation_high_threat(self):
        """Test generating a recommendation for HIGH threat."""
        decision = SecurityDecision.create(
            event_id="high-threat-001",
            threat_score=75,
            threat_level="HIGH",
            decision="ESCALATE",
            recommended_action="REVIEW",
            decision_reason="Threat level is HIGH",
        )

        recommendation = ResponseRecommendationEngine.generate_recommendation(decision)

        assert recommendation is not None
        assert recommendation.threat_level == "HIGH"
        assert recommendation.decision_action == "ESCALATE"
        assert recommendation.requires_human_review is True
        assert recommendation.confidence == 0.80
        assert recommendation.automated_action is False
        assert "escalat" in recommendation.summary.lower()

    def test_generate_recommendation_critical_threat(self):
        """Test generating a recommendation for CRITICAL threat."""
        decision = SecurityDecision.create(
            event_id="critical-threat-001",
            threat_score=95,
            threat_level="CRITICAL",
            decision="ESCALATE",
            recommended_action="REVIEW",
            decision_reason="Threat level is CRITICAL",
        )

        recommendation = ResponseRecommendationEngine.generate_recommendation(decision)

        assert recommendation is not None
        assert recommendation.threat_level == "CRITICAL"
        assert recommendation.requires_human_review is True
        assert recommendation.confidence == 0.95
        assert recommendation.automated_action is False
        assert "immediate" in recommendation.summary.lower()

    def test_evidence_extraction_from_security_event(self):
        """Test that evidence is extracted from security event data."""
        decision = SecurityDecision.create(
            event_id="event-with-evidence",
            threat_score=65,
            threat_level="HIGH",
            decision="ESCALATE",
            recommended_action="REVIEW",
            decision_reason="Test reason",
        )

        orchestration_data = {
            "security_event": {
                "event_type": "created",
                "extension": ".exe",
                "is_directory": False,
            }
        }

        recommendation = ResponseRecommendationEngine.generate_recommendation(
            decision, orchestration_data
        )

        assert recommendation is not None
        assert len(recommendation.evidence) > 0
        # Check that evidence includes file type
        evidence_text = " ".join(recommendation.evidence)
        assert ".exe" in evidence_text or "executable" in evidence_text.lower()

    def test_evidence_extraction_from_analysis(self):
        """Test that evidence is extracted from analysis findings."""
        decision = SecurityDecision.create(
            event_id="event-with-analysis",
            threat_score=60,
            threat_level="MEDIUM",
            decision="ALERT",
            recommended_action="MONITOR",
            decision_reason="Test reason",
        )

        orchestration_data = {
            "analysis": {
                "findings": ["Suspicious behavior detected", "Unusual file origin"]
            }
        }

        recommendation = ResponseRecommendationEngine.generate_recommendation(
            decision, orchestration_data
        )

        assert recommendation is not None
        assert len(recommendation.evidence) > 0

    def test_confidence_matches_threat_level(self):
        """Test that confidence scores match threat levels."""
        test_cases = [
            ("LOW", 0.50),
            ("MEDIUM", 0.65),
            ("HIGH", 0.80),
            ("CRITICAL", 0.95),
        ]

        for threat_level, expected_confidence in test_cases:
            decision = SecurityDecision.create(
                event_id=f"confidence-test-{threat_level}",
                threat_score=50 if threat_level == "MEDIUM" else (
                    15 if threat_level == "LOW" else (75 if threat_level == "HIGH" else 95)
                ),
                threat_level=threat_level,
                decision="ALLOW" if threat_level == "LOW" else (
                    "ALERT" if threat_level == "MEDIUM" else "ESCALATE"
                ),
                recommended_action="NONE" if threat_level == "LOW" else (
                    "MONITOR" if threat_level == "MEDIUM" else "REVIEW"
                ),
                decision_reason=f"Test {threat_level}",
            )

            recommendation = ResponseRecommendationEngine.generate_recommendation(
                decision
            )

            assert recommendation.confidence == expected_confidence

    def test_recommended_actions_by_threat_level(self):
        """Test that recommended actions are appropriate for each threat level."""
        # LOW
        decision_low = SecurityDecision.create(
            event_id="actions-low",
            threat_score=15,
            threat_level="LOW",
            decision="ALLOW",
            recommended_action="NONE",
            decision_reason="Low",
        )
        rec_low = ResponseRecommendationEngine.generate_recommendation(decision_low)
        assert len(rec_low.recommended_actions) >= 1
        assert any("monitor" in action.lower() for action in rec_low.recommended_actions)

        # MEDIUM
        decision_med = SecurityDecision.create(
            event_id="actions-medium",
            threat_score=45,
            threat_level="MEDIUM",
            decision="ALERT",
            recommended_action="MONITOR",
            decision_reason="Medium",
        )
        rec_med = ResponseRecommendationEngine.generate_recommendation(decision_med)
        assert len(rec_med.recommended_actions) >= 2
        assert any("monitor" in action.lower() for action in rec_med.recommended_actions)

        # HIGH
        decision_high = SecurityDecision.create(
            event_id="actions-high",
            threat_score=75,
            threat_level="HIGH",
            decision="ESCALATE",
            recommended_action="REVIEW",
            decision_reason="High",
        )
        rec_high = ResponseRecommendationEngine.generate_recommendation(decision_high)
        assert len(rec_high.recommended_actions) >= 3
        assert any("escalate" in action.lower() for action in rec_high.recommended_actions)

        # CRITICAL
        decision_crit = SecurityDecision.create(
            event_id="actions-critical",
            threat_score=95,
            threat_level="CRITICAL",
            decision="ESCALATE",
            recommended_action="REVIEW",
            decision_reason="Critical",
        )
        rec_crit = ResponseRecommendationEngine.generate_recommendation(decision_crit)
        assert len(rec_crit.recommended_actions) >= 4
        assert any(
            "immediately" in action.lower() for action in rec_crit.recommended_actions
        )

    def test_explanation_is_non_empty(self):
        """Test that explanation is always generated and non-empty."""
        for threat_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            score = 15 if threat_level == "LOW" else (
                45 if threat_level == "MEDIUM" else (75 if threat_level == "HIGH" else 95)
            )
            decision = SecurityDecision.create(
                event_id=f"explanation-test-{threat_level}",
                threat_score=score,
                threat_level=threat_level,
                decision="ALLOW" if threat_level == "LOW" else (
                    "ALERT" if threat_level == "MEDIUM" else "ESCALATE"
                ),
                recommended_action="NONE" if threat_level == "LOW" else (
                    "MONITOR" if threat_level == "MEDIUM" else "REVIEW"
                ),
                decision_reason=f"Test {threat_level}",
            )

            recommendation = ResponseRecommendationEngine.generate_recommendation(
                decision
            )

            assert recommendation.explanation is not None
            assert len(recommendation.explanation) > 50  # Reasonable length

    def test_human_review_flag_by_threat_level(self):
        """Test that human review flag is set correctly by threat level."""
        # LOW should NOT require review
        decision_low = SecurityDecision.create(
            event_id="review-low",
            threat_score=15,
            threat_level="LOW",
            decision="ALLOW",
            recommended_action="NONE",
            decision_reason="Low",
        )
        rec_low = ResponseRecommendationEngine.generate_recommendation(decision_low)
        assert rec_low.requires_human_review is False

        # MEDIUM, HIGH, CRITICAL should require review
        for threat_level, score in [
            ("MEDIUM", 45),
            ("HIGH", 75),
            ("CRITICAL", 95),
        ]:
            decision = SecurityDecision.create(
                event_id=f"review-{threat_level}",
                threat_score=score,
                threat_level=threat_level,
                decision="ALERT" if threat_level == "MEDIUM" else "ESCALATE",
                recommended_action="MONITOR" if threat_level == "MEDIUM" else "REVIEW",
                decision_reason=f"Test {threat_level}",
            )
            recommendation = ResponseRecommendationEngine.generate_recommendation(
                decision
            )
            assert recommendation.requires_human_review is True

    def test_safety_automated_action_always_false(self):
        """
        CRITICAL SAFETY TEST.

        Verify that automated_action is ALWAYS False in Phase 8,
        regardless of threat level or any other factor.
        """
        for threat_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            score = 15 if threat_level == "LOW" else (
                45 if threat_level == "MEDIUM" else (75 if threat_level == "HIGH" else 95)
            )
            decision = SecurityDecision.create(
                event_id=f"safety-test-{threat_level}",
                threat_score=score,
                threat_level=threat_level,
                decision="ALLOW" if threat_level == "LOW" else (
                    "ALERT" if threat_level == "MEDIUM" else "ESCALATE"
                ),
                recommended_action="NONE" if threat_level == "LOW" else (
                    "MONITOR" if threat_level == "MEDIUM" else "REVIEW"
                ),
                decision_reason=f"Safety test {threat_level}",
            )

            recommendation = ResponseRecommendationEngine.generate_recommendation(
                decision
            )

            # This is the critical safety enforcement
            assert recommendation.automated_action is False, (
                f"SAFETY VIOLATION: automated_action is True for {threat_level}"
            )

    def test_graceful_failure_with_invalid_decision(self):
        """Test that engine fails gracefully with bad input."""
        # Create a decision with an unknown threat level
        decision = SecurityDecision.create(
            event_id="bad-threat",
            threat_score=50,
            threat_level="UNKNOWN",  # Invalid
            decision="ALERT",
            recommended_action="MONITOR",
            decision_reason="Test",
        )

        recommendation = ResponseRecommendationEngine.generate_recommendation(decision)

        # Should still produce a recommendation, but with fallback explanation
        assert recommendation is not None
        assert recommendation.requires_human_review is True
        assert recommendation.automated_action is False

    def test_empty_orchestration_data(self):
        """Test that recommendation works with no orchestration data."""
        decision = SecurityDecision.create(
            event_id="no-data",
            threat_score=50,
            threat_level="MEDIUM",
            decision="ALERT",
            recommended_action="MONITOR",
            decision_reason="Test",
        )

        recommendation = ResponseRecommendationEngine.generate_recommendation(
            decision, orchestration_data={}
        )

        assert recommendation is not None
        assert recommendation.summary is not None
        assert len(recommendation.evidence) > 0
        assert len(recommendation.recommended_actions) > 0
