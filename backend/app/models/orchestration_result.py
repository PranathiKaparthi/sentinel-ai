from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class OrchestrationResult:
    """Complete Phase 5 orchestration result built from the existing Phase 3 and Phase 4 pipeline."""

    id: str
    event_id: str
    security_event: dict[str, Any]
    investigation: dict[str, Any]
    analysis: dict[str, Any]
    suspicion_score: int
    threat_score: int
    threat_level: str
    findings: list[str]
    reasons: list[str]
    processing_timestamp: str

    @classmethod
    def create(
        cls,
        *,
        event_id: str,
        security_event: dict[str, Any],
        investigation: dict[str, Any],
        analysis: dict[str, Any],
        suspicion_score: int,
        threat_score: int,
        threat_level: str,
        findings: list[str],
        reasons: list[str],
    ) -> "OrchestrationResult":
        timestamp = datetime.now(timezone.utc).isoformat()
        result_id = event_id or timestamp
        return cls(
            id=result_id,
            event_id=event_id,
            security_event=security_event,
            investigation=investigation,
            analysis=analysis,
            suspicion_score=max(0, min(100, int(suspicion_score))),
            threat_score=max(0, min(100, int(threat_score))),
            threat_level=threat_level.upper() if threat_level else "LOW",
            findings=list(findings or []),
            reasons=list(reasons or []),
            processing_timestamp=timestamp,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
