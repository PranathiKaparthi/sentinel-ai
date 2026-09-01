"""
AnalysisAgent for SentinelAI Phase 4.

This is a deterministic, read-only analysis layer placed on top of the
existing Phase 3 investigation and analysis flow:

SecurityEvent -> Investigator -> InvestigationResult -> Analyzer -> AnalysisResult -> AnalysisAgent

The agent does not execute files, modify the filesystem, or perform a
response/remediation action. It simply evaluates known metadata already
available from the repository's Phase 3 pipeline and produces a bounded,
explainable score.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.investigation_result import InvestigationResult
from app.models.security_event import SecurityEvent
from app.services.analyzer import AnalysisResult


_SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".com",
    ".ps1",
    ".scr",
    ".vbs",
    ".js",
    ".jar",
    ".hta",
    ".wsf",
    ".reg",
    ".lnk",
    ".pif",
}


class AnalysisAgentResult(BaseModel):
    """Deterministic Phase 4 scoring result."""

    id: str = ""
    event_id: str
    suspicion_score: int = Field(default=0)
    findings: list[str] = Field(default_factory=list)
    threat_score: int = Field(default=0)
    threat_level: str = "LOW"
    reasons: list[str] = Field(default_factory=list)
    analysis_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @field_validator("suspicion_score", "threat_score", mode="before")
    @classmethod
    def _clamp_score(cls, value: Any) -> int:
        if value is None:
            return 0
        try:
            numeric = int(float(value))
        except (TypeError, ValueError):
            return 0
        return max(0, min(100, numeric))

    @field_validator("threat_level", mode="before")
    @classmethod
    def _normalize_threat_level(cls, value: Any) -> str:
        if value is None:
            return "LOW"
        normalized = str(value).upper()
        if normalized in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            return normalized
        return "LOW"

    @model_validator(mode="after")
    def _normalize(self) -> "AnalysisAgentResult":
        if not self.id:
            self.id = self.event_id

        self.suspicion_score = max(0, min(100, int(self.suspicion_score)))
        self.threat_score = max(0, min(100, int(self.threat_score)))
        self.threat_level = AnalysisAgent.score_to_threat_level(
            self.threat_score
        )

        if not self.findings:
            self.findings = ["No suspicious indicators detected."]
        if not self.reasons:
            self.reasons = list(self.findings)

        return self


class AnalysisHistoryStore:
    """In-memory bounded store for Phase 4 result history."""

    def __init__(self, max_items: int = 100):
        self._max_items = max_items
        self._items: "OrderedDict[str, AnalysisAgentResult]" = OrderedDict()

    def add(self, result: AnalysisAgentResult) -> AnalysisAgentResult:
        key = result.id or result.event_id
        self._items[key] = result
        if len(self._items) > self._max_items:
            self._items.popitem(last=False)
        return result

    def list(self) -> list[dict]:
        return [item.model_dump() for item in self._items.values()]

    def get(self, result_id: str) -> Optional[AnalysisAgentResult]:
        return self._items.get(result_id)


_history_store = AnalysisHistoryStore()


class AnalysisAgent:
    """Deterministic Phase 4 scoring agent built atop Phase 3 evidence."""

    @staticmethod
    def analyze(
        event: SecurityEvent | dict,
        investigation: InvestigationResult | dict | None = None,
        analysis: AnalysisResult | dict | None = None,
    ) -> Optional[AnalysisAgentResult]:
        """Assess a Phase 3 event and return a bounded Phase 4 score."""
        try:
            return AnalysisAgent._analyze(event, investigation, analysis)
        except Exception:
            return None

    @staticmethod
    def _analyze(
        event: SecurityEvent | dict,
        investigation: InvestigationResult | dict | None = None,
        analysis: AnalysisResult | dict | None = None,
    ) -> AnalysisAgentResult:
        if event is None:
            raise ValueError("event is required")

        if isinstance(event, dict):
            event = SecurityEvent(**event)

        if investigation is not None and isinstance(investigation, dict):
            investigation = InvestigationResult(**investigation)

        if analysis is not None and isinstance(analysis, dict):
            analysis = AnalysisResult(**analysis)

        findings: list[str] = []
        reasons: list[str] = []
        suspicion_score = 0

        event_type = (event.event_type or "").lower()
        extension = (event.extension or "").lower()

        if event_type == "moved":
            suspicion_score += 10
            findings.append("Filesystem move event observed.")
            reasons.append("Move events can indicate staging or persistence activity.")
        elif event_type == "deleted":
            suspicion_score += 15
            findings.append("Filesystem deletion event observed.")
            reasons.append("Deletion can be part of cleanup, staging, or tampering.")
        elif event_type == "created":
            suspicion_score += 5
            findings.append("Filesystem creation event observed.")
            reasons.append("Creation events are normal, but can also be used for staging payloads.")
        elif event_type == "modified":
            suspicion_score += 8
            findings.append("Filesystem modification event observed.")
            reasons.append("Modification events can indicate tampering or a payload update.")

        if extension in _SUSPICIOUS_EXTENSIONS:
            suspicion_score += 70
            findings.append(f"Suspicious extension detected: {extension}")
            reasons.append(
                f"The file extension {extension} is commonly associated with executable or script payloads."
            )

        if investigation is not None:
            if investigation.exists is False:
                suspicion_score += 10
                findings.append("Observed path no longer exists.")
                reasons.append("A missing file may indicate a short-lived staged or tampered artifact.")

            if investigation.is_directory:
                suspicion_score += 5
                findings.append("Path is a directory.")
                reasons.append("Directories are not executable payloads by themselves, but directory events can still be relevant.")

            if investigation.current_file_size is not None:
                if investigation.current_file_size > 10 * 1024 * 1024:
                    suspicion_score += 20
                    findings.append("Large file size observed.")
                    reasons.append("A large file may indicate a staged malware payload or archive.")

        if analysis is not None and isinstance(analysis, AnalysisResult):
            if analysis.observations:
                observation_text = "\n".join(analysis.observations)
                if "Destination path:" in observation_text:
                    suspicion_score += 15
                    findings.append("Move destination was recorded.")
                    reasons.append("A destination path suggests staging or persistence activity.")

        suspicion_score = max(0, min(100, suspicion_score))
        threat_score = suspicion_score
        threat_level = AnalysisAgent.score_to_threat_level(threat_score)

        findings = list(dict.fromkeys(findings))
        reasons = list(dict.fromkeys(reasons))

        result = AnalysisAgentResult(
            id=event.event_id or str(datetime.now(timezone.utc).timestamp()),
            event_id=event.event_id,
            suspicion_score=suspicion_score,
            findings=findings,
            threat_score=threat_score,
            threat_level=threat_level,
            reasons=reasons,
        )

        _history_store.add(result)
        return result

    @staticmethod
    def score_to_threat_level(score: Any) -> str:
        """Convert a bounded 0..100 score to a deterministic threat label."""
        try:
            numeric = int(float(score))
        except (TypeError, ValueError):
            numeric = 0

        numeric = max(0, min(100, numeric))

        if 0 <= numeric <= 30:
            return "LOW"
        if 31 <= numeric <= 60:
            return "MEDIUM"
        if 61 <= numeric <= 85:
            return "HIGH"
        return "CRITICAL"

    @staticmethod
    def list_history() -> list[dict]:
        return _history_store.list()

    @staticmethod
    def get_history_item(result_id: str) -> Optional[AnalysisAgentResult]:
        return _history_store.get(result_id)
