"""
decision_engine.py

DecisionEngine service for SentinelAI Phase 7.

Converts threat classification into a structured decision and recommendation.

This is a deterministic, rule-based decision layer.
It does NOT perform destructive actions.
"""

from __future__ import annotations

from typing import Optional

from app.models.security_decision import Decision, RecommendedAction, SecurityDecision
from app.utils.logger import get_logger

logger = get_logger("SentinelAI.DecisionEngine")


class DecisionEngine:
    """
    Converts threat classification into safe security decisions.

    Decision Mapping:

    LOW (0-30)
        ↓
    ALLOW
        ↓
    NONE (no action needed)

    MEDIUM (31-60)
        ↓
    ALERT
        ↓
    MONITOR (continued observation)

    HIGH (61-85)
        ↓
    ESCALATE
        ↓
    REVIEW (security team review)

    CRITICAL (86-100)
        ↓
    ESCALATE
        ↓
    REVIEW (security team review)

    All decisions are recommendations only.
    automated_action is always False in Phase 7.
    """

    @staticmethod
    def make_decision(
        event_id: str,
        threat_score: int,
        threat_level: str,
    ) -> Optional[SecurityDecision]:
        """
        Make a security decision based on threat classification.

        Args:
            event_id: The security event ID
            threat_score: Threat score (0-100)
            threat_level: Threat level (LOW, MEDIUM, HIGH, CRITICAL)

        Returns:
            SecurityDecision with recommendation, or None if inputs are invalid.
        """
        try:
            return DecisionEngine._make_decision(event_id, threat_score, threat_level)
        except Exception:
            logger.exception(
                "DecisionEngine failed for event %s with score %s / %s",
                event_id,
                threat_score,
                threat_level,
            )
            return None

    @staticmethod
    def _make_decision(
        event_id: str,
        threat_score: int,
        threat_level: str,
    ) -> SecurityDecision:
        """Perform the actual decision logic."""

        if event_id is None or not isinstance(event_id, str):
            raise ValueError("event_id is required")

        if threat_score is None:
            raise ValueError("threat_score is required")

        if threat_level is None or not isinstance(threat_level, str):
            raise ValueError("threat_level is required")

        # Clamp and normalize threat score
        try:
            numeric_score = int(float(threat_score))
        except (TypeError, ValueError):
            raise ValueError(f"Invalid threat_score: {threat_score}")

        numeric_score = max(0, min(100, numeric_score))

        # Normalize threat level
        normalized_level = threat_level.upper().strip()
        if normalized_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError(f"Invalid threat_level: {threat_level}")

        # Determine decision based on threat level
        if normalized_level == "LOW":
            decision = Decision.ALLOW.value
            recommended_action = RecommendedAction.NONE.value
            reason = "Threat level is LOW; no immediate response is required."

        elif normalized_level == "MEDIUM":
            decision = Decision.ALERT.value
            recommended_action = RecommendedAction.MONITOR.value
            reason = "Threat level is MEDIUM; continued monitoring is recommended."

        elif normalized_level in {"HIGH", "CRITICAL"}:
            decision = Decision.ESCALATE.value
            recommended_action = RecommendedAction.REVIEW.value
            reason = f"Threat level is {normalized_level}; the event should be escalated for security review."

        else:
            # Defensive fallback (should not reach here)
            decision = Decision.ALLOW.value
            recommended_action = RecommendedAction.NONE.value
            reason = "Threat level is unknown; defaulting to ALLOW."

        return SecurityDecision.create(
            event_id=event_id,
            threat_score=numeric_score,
            threat_level=normalized_level,
            decision=decision,
            recommended_action=recommended_action,
            decision_reason=reason,
        )
