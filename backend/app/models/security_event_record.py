"""
security_event_record.py

SecurityEventRecord model for SentinelAI Phase 10 persistence.

Represents a persisted security event analysis result in the database.
Includes all metadata, scores, decisions, and recommendations for audit
and history purposes.

Does NOT include file contents, only metadata and analysis results.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional
import json

from app.models.security_analysis_result import SecurityAnalysisResult


@dataclass
class SecurityEventRecord:
    """
    A persisted security event record.

    Contains the complete analysis result including metadata, investigation
    findings, threat scoring, decision, and recommendation.

    Fields:
        id: Database primary key (auto-increment)
        event_id: Unique identifier for the event (unique constraint)
        event_type: Type of filesystem event (created, modified, deleted, moved)
        path: File/directory path
        timestamp: Original event timestamp
        is_directory: Whether the event target is a directory
        destination_path: For moved events, the destination path
        file_name: Extracted file name
        extension: File extension (lowercased)
        parent_directory: Parent directory path
        file_size: File size in bytes (if available)
        suspicion_score: Phase 4 suspicion score (0-100)
        threat_score: Threat score (0-100)
        threat_level: Threat classification (LOW, MEDIUM, HIGH, CRITICAL)
        decision: Security decision (ALLOW, ALERT, ESCALATE)
        recommended_action: Recommended action (NONE, MONITOR, REVIEW)
        automated_action: Whether automatic action was taken (always False)
        requires_human_review: Whether human review is recommended
        confidence: Confidence in the recommendation (0.0-1.0)
        decision_reason: Reason for the decision
        summary: One-line summary of recommendation
        explanation: Detailed explanation
        evidence: List of evidence (JSON serialized)
        recommended_actions: List of recommended actions (JSON serialized)
        created_at: Record creation timestamp
        updated_at: Last update timestamp
    """

    id: Optional[int] = None
    event_id: str = ""
    event_type: str = ""
    path: str = ""
    timestamp: str = ""
    is_directory: bool = False
    destination_path: Optional[str] = None
    file_name: str = ""
    extension: str = ""
    parent_directory: str = ""
    file_size: Optional[int] = None
    suspicion_score: int = 0
    threat_score: int = 0
    threat_level: str = "LOW"
    decision: str = "ALLOW"
    recommended_action: str = "NONE"
    automated_action: bool = False
    requires_human_review: bool = False
    confidence: float = 0.5
    decision_reason: str = ""
    summary: str = ""
    explanation: str = ""
    evidence: str = ""  # JSON serialized
    recommended_actions: str = ""  # JSON serialized
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_analysis_result(
        cls,
        analysis_result: SecurityAnalysisResult,
    ) -> SecurityEventRecord:
        """
        Create a SecurityEventRecord from a SecurityAnalysisResult.

        Extracts all relevant fields and formats them for database storage.

        Args:
            analysis_result: The SecurityAnalysisResult from orchestrator

        Returns:
            SecurityEventRecord ready for database persistence
        """
        now = datetime.now(timezone.utc).isoformat()

        orchestration = analysis_result.orchestration_result
        decision = analysis_result.security_decision
        recommendation = analysis_result.response_recommendation
        security_event = orchestration.security_event

        return cls(
            event_id=orchestration.event_id,
            event_type=security_event.get("event_type", ""),
            path=security_event.get("path", ""),
            timestamp=security_event.get("timestamp", ""),
            is_directory=security_event.get("is_directory", False),
            destination_path=security_event.get("destination_path"),
            file_name=security_event.get("file_name", ""),
            extension=security_event.get("extension", ""),
            parent_directory=security_event.get("parent_directory", ""),
            file_size=security_event.get("file_size"),
            suspicion_score=orchestration.suspicion_score,
            threat_score=orchestration.threat_score,
            threat_level=orchestration.threat_level,
            decision=decision.decision,
            recommended_action=decision.recommended_action,
            automated_action=decision.automated_action,
            requires_human_review=recommendation.requires_human_review,
            confidence=recommendation.confidence,
            decision_reason=decision.decision_reason,
            summary=recommendation.summary,
            explanation=recommendation.explanation,
            evidence=json.dumps(recommendation.evidence),
            recommended_actions=json.dumps(recommendation.recommended_actions),
            created_at=now,
            updated_at=now,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to JSON-serializable dictionary.

        Includes all fields and deserializes JSON fields.
        """
        result = asdict(self)
        # Deserialize JSON fields for API responses
        try:
            result["evidence"] = json.loads(self.evidence) if self.evidence else []
        except (json.JSONDecodeError, TypeError):
            result["evidence"] = []

        try:
            result["recommended_actions"] = (
                json.loads(self.recommended_actions)
                if self.recommended_actions
                else []
            )
        except (json.JSONDecodeError, TypeError):
            result["recommended_actions"] = []

        return result
