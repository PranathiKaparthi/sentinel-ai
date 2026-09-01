"""
response_recommendation.py

ResponseRecommendation model for SentinelAI Phase 8.

Converts a SecurityDecision into a structured, human-readable response
recommendation with explanation, evidence, and next steps.

This is an explainability layer: it takes the decision and makes it
understandable to a human security analyst.

This is a safe, recommendation-only layer.
It does NOT perform any filesystem modifications, process termination,
or other destructive actions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class ResponseRecommendation:
    """
    Human-readable response recommendation based on a SecurityDecision.

    This recommendation is EXPLANATION-ONLY.
    It translates a decision into analyst-friendly guidance.

    Fields:
        event_id: The security event ID (from SecurityDecision)
        threat_score: Numeric threat score 0-100
        threat_level: Threat level (LOW, MEDIUM, HIGH, CRITICAL)

        decision_action: The decision action (ALLOW, ALERT, ESCALATE)
        decision_recommendation: The recommended action (NONE, MONITOR, REVIEW)

        summary: One-line summary of the recommendation
        explanation: Multi-sentence, human-readable explanation

        evidence: List of factual evidence supporting the recommendation
        recommended_actions: List of suggested next steps for an analyst

        confidence: Confidence score (0.0-1.0) in the recommendation
        automated_action: Always False - this is recommendation-only
        requires_human_review: Whether human review is strongly recommended

        created_at: ISO-8601 timestamp when recommendation was generated
    """

    event_id: str
    threat_score: int
    threat_level: str

    decision_action: str
    decision_recommendation: str

    summary: str
    explanation: str

    evidence: list[str]
    recommended_actions: list[str]

    confidence: float
    automated_action: bool
    requires_human_review: bool

    created_at: str

    @classmethod
    def create(
        cls,
        *,
        event_id: str,
        threat_score: int,
        threat_level: str,
        decision_action: str,
        decision_recommendation: str,
        summary: str,
        explanation: str,
        evidence: list[str],
        recommended_actions: list[str],
        confidence: float,
        requires_human_review: bool,
    ) -> "ResponseRecommendation":
        """
        Create a ResponseRecommendation with current timestamp.

        Args:
            event_id: The security event ID
            threat_score: Numeric threat score (0-100)
            threat_level: Threat level (LOW, MEDIUM, HIGH, CRITICAL)
            decision_action: Decision action (ALLOW, ALERT, ESCALATE)
            decision_recommendation: Recommended action (NONE, MONITOR, REVIEW)
            summary: One-line summary
            explanation: Detailed explanation
            evidence: List of evidence strings
            recommended_actions: List of recommended actions
            confidence: Confidence score (0.0-1.0)
            requires_human_review: Whether human review is recommended

        Returns:
            ResponseRecommendation instance.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        return cls(
            event_id=event_id,
            threat_score=max(0, min(100, int(threat_score))),
            threat_level=threat_level.upper() if threat_level else "LOW",
            decision_action=decision_action,
            decision_recommendation=decision_recommendation,
            summary=summary,
            explanation=explanation,
            evidence=list(evidence or []),
            recommended_actions=list(recommended_actions or []),
            confidence=max(0.0, min(1.0, float(confidence))),
            automated_action=False,  # Phase 8 is ALWAYS recommendation-only
            requires_human_review=requires_human_review,
            created_at=timestamp,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)
