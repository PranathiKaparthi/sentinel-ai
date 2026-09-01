"""
response_recommendation.py

ResponseRecommendationEngine service for SentinelAI Phase 8.

Converts a SecurityDecision into a human-readable ResponseRecommendation
with explanation, evidence summary, and recommended next steps.

This is an explainability layer that bridges the gap between automated
security analysis and human decision-making.
"""

from __future__ import annotations

from typing import Any, Optional

from app.models.response_recommendation import ResponseRecommendation
from app.models.security_decision import SecurityDecision
from app.utils.logger import get_logger

logger = get_logger("SentinelAI.ResponseRecommendationEngine")


class ResponseRecommendationEngine:
    """
    Converts a SecurityDecision into a human-readable recommendation.

    This engine generates:
    - Summary: One-line summary
    - Explanation: Detailed reasoning
    - Evidence: List of supporting facts from the analysis
    - Recommended Actions: Next steps for a security analyst
    - Confidence: Deterministic confidence based on threat level
    - Human Review Flag: Whether escalation to analyst is recommended

    All recommendations are safe and non-destructive.
    automated_action is always False.
    """

    @staticmethod
    def generate_recommendation(
        security_decision: SecurityDecision,
        orchestration_data: Optional[dict[str, Any]] = None,
    ) -> Optional[ResponseRecommendation]:
        """
        Generate a human-readable recommendation from a security decision.

        Args:
            security_decision: The SecurityDecision from Phase 7
            orchestration_data: Optional analysis/investigation data for evidence

        Returns:
            ResponseRecommendation, or None if generation fails safely.
        """
        try:
            return ResponseRecommendationEngine._generate_recommendation(
                security_decision, orchestration_data or {}
            )
        except Exception:
            logger.exception(
                "ResponseRecommendationEngine failed for event %s",
                security_decision.event_id,
            )
            return None

    @staticmethod
    def _generate_recommendation(
        security_decision: SecurityDecision,
        orchestration_data: dict[str, Any],
    ) -> ResponseRecommendation:
        """Perform the actual recommendation generation logic."""

        threat_level = security_decision.threat_level.upper()
        threat_score = security_decision.threat_score
        decision_action = security_decision.decision
        recommended_action = security_decision.recommended_action

        # Extract evidence from orchestration data
        evidence = ResponseRecommendationEngine._extract_evidence(
            security_decision, orchestration_data
        )

        # Generate threat-level-specific content
        if threat_level == "LOW":
            summary = "No immediate security action required."
            explanation = (
                f"A security event was detected with a low threat level "
                f"(score: {threat_score}). The automated security analysis "
                f"determined this activity does not pose an immediate risk. "
                f"No action is recommended at this time, but continued monitoring "
                f"is advised."
            )
            actions = [
                "Continue monitoring the event.",
                "Review related events if new suspicious activity occurs.",
            ]
            confidence = 0.50
            requires_review = False

        elif threat_level == "MEDIUM":
            summary = "Monitoring recommended; escalate if pattern continues."
            explanation = (
                f"A security event was detected with a medium threat level "
                f"(score: {threat_score}). The automated security analysis "
                f"identified potentially suspicious characteristics that warrant "
                f"attention. Human review is recommended to determine if this "
                f"activity is legitimate or requires further investigation."
            )
            actions = [
                "Monitor for additional suspicious activity.",
                "Review the associated file if the activity persists.",
                "Consider escalating if similar events cluster together.",
            ]
            confidence = 0.65
            requires_review = True

        elif threat_level == "HIGH":
            summary = "Escalation to security analyst recommended."
            explanation = (
                f"A high-risk security event was detected (score: {threat_score}). "
                f"The automated security analysis identified multiple suspicious "
                f"indicators that suggest a genuine security concern. Immediate "
                f"human review is strongly recommended before taking any "
                f"containment action."
            )
            actions = [
                "Escalate to a security analyst immediately.",
                "Review the file origin, creation date, and associated activity.",
                "Inspect related events to identify potential lateral movement.",
                "Validate threat indicators before taking any containment action.",
            ]
            confidence = 0.80
            requires_review = True

        elif threat_level == "CRITICAL":
            summary = "Immediate security analyst review required."
            explanation = (
                f"A critical-risk security event was detected (score: {threat_score}). "
                f"The automated security analysis has identified indicators of a "
                f"severe threat that requires immediate attention. This may indicate "
                f"active malware, privilege escalation, or data exfiltration activity. "
                f"Immediate human review is mandatory before any response action."
            )
            actions = [
                "Escalate immediately to a security analyst.",
                "Review all related events and investigation findings.",
                "Preserve evidence for forensic analysis.",
                "Consult threat intelligence before taking action.",
                "Validate the threat using multiple detection methods.",
            ]
            confidence = 0.95
            requires_review = True

        else:
            # Defensive fallback
            summary = "Unable to classify threat level."
            explanation = (
                f"The threat level '{threat_level}' is not recognized. "
                f"Please review the event manually."
            )
            actions = ["Review event manually."]
            confidence = 0.30
            requires_review = True

        return ResponseRecommendation.create(
            event_id=security_decision.event_id,
            threat_score=security_decision.threat_score,
            threat_level=security_decision.threat_level,
            decision_action=decision_action,
            decision_recommendation=recommended_action,
            summary=summary,
            explanation=explanation,
            evidence=evidence,
            recommended_actions=actions,
            confidence=confidence,
            requires_human_review=requires_review,
        )

    @staticmethod
    def _extract_evidence(
        security_decision: SecurityDecision,
        orchestration_data: dict[str, Any],
    ) -> list[str]:
        """
        Extract factual evidence from decision and orchestration data.

        Evidence should come from:
        - Security event characteristics (file type, location, etc.)
        - Analysis findings
        - Investigation results

        Only include evidence that can be verified from available data.
        """
        evidence: list[str] = []

        # Threat score milestone
        threat_score = security_decision.threat_score
        if threat_score >= 86:
            evidence.append("Threat score exceeds critical threshold (≥86)")
        elif threat_score >= 61:
            evidence.append("Threat score exceeds high-risk threshold (≥61)")
        elif threat_score >= 31:
            evidence.append("Threat score exceeds medium-risk threshold (≥31)")

        # Extract security event characteristics if available
        security_event = orchestration_data.get("security_event", {})
        if security_event:
            event_type = security_event.get("event_type", "").upper()
            if event_type:
                evidence.append(f"Filesystem event type: {event_type}")

            extension = security_event.get("extension", "")
            if extension:
                if extension.lower() in {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1"}:
                    evidence.append(
                        f"Executable file type detected: {extension}"
                    )
                else:
                    evidence.append(f"File type: {extension}")

            is_directory = security_event.get("is_directory", False)
            if is_directory:
                evidence.append("Event targets a directory")

        # Extract analysis findings if available
        analysis = orchestration_data.get("analysis", {})
        if analysis:
            findings = analysis.get("findings", [])
            if findings:
                # Include first 2-3 findings as evidence
                for finding in findings[:3]:
                    if finding and len(finding) < 120:
                        evidence.append(finding)

        # Extract investigation findings if available
        investigation = orchestration_data.get("investigation", {})
        if investigation:
            findings = investigation.get("findings", [])
            if findings:
                # Include first finding as evidence
                if findings and len(findings[0]) < 120:
                    evidence.append(findings[0])

        # Add reason from decision if available
        decision_reason = security_decision.decision_reason
        if decision_reason and len(decision_reason) < 150:
            evidence.append(f"Decision rationale: {decision_reason}")

        # If no evidence was extracted, add a generic statement
        if not evidence:
            evidence.append("Automated security analysis performed on event")

        return evidence
