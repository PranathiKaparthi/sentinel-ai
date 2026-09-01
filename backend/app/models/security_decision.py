"""
security_decision.py

SecurityDecision model for SentinelAI Phase 7.

Represents the decision and recommendation based on threat classification.

This is a safe, non-destructive recommendation layer.
It does NOT perform any filesystem modifications, process termination,
or other destructive actions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Decision(str, Enum):
    """Possible security decisions."""

    ALLOW = "ALLOW"
    ALERT = "ALERT"
    ESCALATE = "ESCALATE"


class RecommendedAction(str, Enum):
    """Possible recommended security actions."""

    NONE = "NONE"
    MONITOR = "MONITOR"
    REVIEW = "REVIEW"


@dataclass
class SecurityDecision:
    """
    Safe security decision based on threat classification.

    This decision is a RECOMMENDATION only.
    No destructive or irreversible actions are performed.
    """

    event_id: str
    threat_score: int
    threat_level: str
    decision: str
    recommended_action: str
    automated_action: bool
    decision_reason: str
    decision_timestamp: str

    @classmethod
    def create(
        cls,
        *,
        event_id: str,
        threat_score: int,
        threat_level: str,
        decision: str,
        recommended_action: str,
        decision_reason: str,
    ) -> "SecurityDecision":
        """Create a SecurityDecision with current timestamp and no automation."""
        timestamp = datetime.now(timezone.utc).isoformat()
        return cls(
            event_id=event_id,
            threat_score=max(0, min(100, int(threat_score))),
            threat_level=threat_level.upper() if threat_level else "LOW",
            decision=decision,
            recommended_action=recommended_action,
            automated_action=False,  # Phase 7 is recommendation-only
            decision_reason=decision_reason,
            decision_timestamp=timestamp,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)
