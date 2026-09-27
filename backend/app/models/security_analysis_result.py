"""
security_analysis_result.py

SecurityAnalysisResult model for SentinelAI Phase 9.

This is a composite result that combines:
- OrchestrationResult (Phase 1-5 analysis)
- SecurityDecision (Phase 7 decision)
- ResponseRecommendation (Phase 8 explanation)

The result is designed to be the single output of SecurityOrchestrator
and produces the same JSON structure as the current /api/security/analyze
endpoint to maintain backward compatibility.

This model does NOT change the API response structure.
"""

from __future__ import annotations

from typing import Any, Optional

from app.models.orchestration_result import OrchestrationResult
from app.models.security_decision import SecurityDecision
from app.models.response_recommendation import ResponseRecommendation


class SecurityAnalysisResult:
    """
    Composite result from the complete security analysis pipeline.

    This class wraps the three Phase 7, 8 outputs together and provides
    a single entry point for the security orchestrator.

    When serialized to dict, produces identical JSON to the current
    /api/security/analyze response for backward compatibility.
    """

    def __init__(
        self,
        *,
        orchestration_result: OrchestrationResult,
        security_decision: SecurityDecision,
        response_recommendation: ResponseRecommendation,
    ):
        """
        Initialize a SecurityAnalysisResult.

        Args:
            orchestration_result: Phase 1-5 analysis result
            security_decision: Phase 7 decision
            response_recommendation: Phase 8 recommendation
        """
        self.orchestration_result = orchestration_result
        self.security_decision = security_decision
        self.response_recommendation = response_recommendation

    @property
    def event_id(self) -> str:
        """Convenience property to access event_id."""
        return self.orchestration_result.event_id

    @property
    def threat_score(self) -> int:
        """Convenience property to access threat_score."""
        return self.orchestration_result.threat_score

    @property
    def threat_level(self) -> str:
        """Convenience property to access threat_level."""
        return self.orchestration_result.threat_level

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to JSON-serializable dictionary.

        Produces identical structure to current /api/security/analyze response:
        - All OrchestrationResult fields at top level
        - "decision" object
        - "response_recommendation" object

        This maintains perfect backward compatibility with Phase 8.
        """
        response = self.orchestration_result.to_dict()
        response["decision"] = self.security_decision.to_dict()
        response["response_recommendation"] = self.response_recommendation.to_dict()
        return response
