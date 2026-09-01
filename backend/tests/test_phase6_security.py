"""
test_phase6_security.py

Tests for the SentinelAI Phase 6 SecurityAgent and security analysis endpoint.

Coverage:
1. SecurityAgent coordinates the complete security analysis pipeline
2. Threat classification works correctly
3. Invalid/malformed events are handled safely
4. API endpoint functions properly
5. Phase 1-5 behavior is not regressed
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.agents.security_agent import SecurityAgent
from app.main import app

client = TestClient(app)


# ======================================================================
# Test Fixtures and Helpers
# ======================================================================


def make_event(
    path: str,
    event_type: str = "created",
    event_id: str = "phase6-security-event",
) -> dict:
    """Create a valid raw filesystem event for testing."""
    return {
        "event_id": event_id,
        "event_type": event_type,
        "path": path,
        "timestamp": "2026-09-01T00:00:00+00:00",
        "is_directory": False,
        "destination_path": None,
    }


# ======================================================================
# Test 1 — SecurityAgent processes normal benign event
# ======================================================================


def test_security_agent_normal_benign_event(tmp_path):
    """
    A normal, benign file event should be processed without error.
    """
    file_path = tmp_path / "document.txt"
    file_path.write_text("normal document content")

    agent = SecurityAgent()
    agent.start()

    result = agent.analyze(make_event(str(file_path), event_type="created"))

    assert result is not None
    assert result.event_id == "phase6-security-event"
    assert result.security_event["path"] == str(file_path)
    assert result.investigation is not None
    assert result.analysis is not None
    assert 0 <= result.suspicion_score <= 100
    assert result.threat_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result.findings is not None
    assert result.reasons is not None

    agent.stop()


# ======================================================================
# Test 2 — SecurityAgent detects suspicious executable
# ======================================================================


def test_security_agent_detects_suspicious_executable(tmp_path):
    """
    An executable file should be flagged with higher threat classification.
    This validates the scoring and threat level classification.
    """
    file_path = tmp_path / "payload.exe"
    file_path.write_text("fake executable")

    agent = SecurityAgent()
    agent.start()

    result = agent.analyze(make_event(str(file_path), event_type="created"))

    assert result is not None
    assert result.event_id == "phase6-security-event"
    assert result.threat_level in {"HIGH", "CRITICAL"}
    assert result.suspicion_score > 50
    assert result.threat_score > 50
    assert any("exe" in finding.lower() or "extension" in finding.lower() for finding in result.findings)

    agent.stop()


# ======================================================================
# Test 3 — SecurityAgent handles invalid event safely
# ======================================================================


def test_security_agent_rejects_invalid_event():
    """
    Invalid events should be handled safely without raising exceptions.
    """
    agent = SecurityAgent()
    agent.start()

    result = agent.analyze({"event_type": "invalid", "path": None})

    assert result is None

    agent.stop()


# ======================================================================
# Test 4 — SecurityAgent handles missing path safely
# ======================================================================


def test_security_agent_rejects_missing_path():
    """
    Events with missing paths should be rejected safely.
    """
    agent = SecurityAgent()
    agent.start()

    result = agent.analyze(
        {
            "event_type": "created",
            "path": "",
            "timestamp": "2026-09-01T00:00:00+00:00",
            "is_directory": False,
        }
    )

    assert result is None

    agent.stop()


# ======================================================================
# Test 5 — SecurityAgent orchestration flow
# ======================================================================


def test_security_agent_orchestration_flow(tmp_path):
    """
    Verify that SecurityAgent actually coordinates all pipeline stages:
    EventProcessor -> Investigator -> Analyzer -> AnalysisAgent -> Result
    """
    file_path = tmp_path / "orchestration_test.ps1"
    file_path.write_text("powershell script")

    agent = SecurityAgent()
    agent.start()

    result = agent.analyze(make_event(str(file_path), event_type="created"))

    # All pipeline stages must be present
    assert result is not None
    assert "security_event" in result.to_dict()
    assert "investigation" in result.to_dict()
    assert "analysis" in result.to_dict()

    # SecurityEvent must have been normalized
    assert result.security_event["event_id"] == "phase6-security-event"
    assert result.security_event["event_type"] == "created"
    assert result.security_event["path"] == str(file_path)
    assert result.security_event["file_name"] == "orchestration_test.ps1"
    assert result.security_event["extension"] == ".ps1"

    # Investigation must have been performed
    assert result.investigation["event_id"] == "phase6-security-event"
    assert "exists" in result.investigation
    assert "is_directory" in result.investigation
    assert "investigation_timestamp" in result.investigation

    # Analysis must have been performed
    assert result.analysis["event_id"] == "phase6-security-event"
    assert "observations" in result.analysis
    assert "analysis_timestamp" in result.analysis

    # Threat assessment must have been computed
    assert result.threat_score >= 0
    assert result.threat_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    agent.stop()


# ======================================================================
# Test 6 — API endpoint basic functionality
# ======================================================================


def test_security_api_endpoint_valid_event():
    """
    The /api/security/analyze endpoint should accept valid events
    and return proper results.
    """
    response = client.post(
        "/api/security/analyze",
        json=make_event("C:/sandbox/api_test.dll", event_type="created"),
    )

    assert response.status_code == 200
    payload = response.json()

    # Complete result structure
    assert "event_id" in payload
    assert "security_event" in payload
    assert "investigation" in payload
    assert "analysis" in payload
    assert "suspicion_score" in payload
    assert "threat_score" in payload
    assert "threat_level" in payload
    assert "findings" in payload
    assert "reasons" in payload
    assert "processing_timestamp" in payload

    # Values are reasonable
    assert payload["event_id"] == "phase6-security-event"
    assert 0 <= payload["suspicion_score"] <= 100
    assert 0 <= payload["threat_score"] <= 100
    assert payload["threat_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert isinstance(payload["findings"], list)
    assert isinstance(payload["reasons"], list)


# ======================================================================
# Test 7 — API endpoint rejects invalid event
# ======================================================================


def test_security_api_endpoint_invalid_event():
    """
    The /api/security/analyze endpoint should reject malformed input.
    """
    response = client.post(
        "/api/security/analyze",
        json={"event_type": "invalid", "path": None},
    )

    assert response.status_code == 400
    assert "detail" in response.json()


# ======================================================================
# Test 8 — SecurityAgent lifecycle management
# ======================================================================


def test_security_agent_lifecycle():
    """
    SecurityAgent should properly support start/stop lifecycle.
    """
    agent = SecurityAgent()

    # Initially stopped
    assert not agent.is_running()

    # Start the agent
    agent.start()
    assert agent.is_running()

    # Stop the agent
    agent.stop()
    assert not agent.is_running()


# ======================================================================
# Test 9 — SecurityAgent requires running status
# ======================================================================


def test_security_agent_analyze_when_stopped():
    """
    Attempting to analyze when the agent is stopped should return None.
    """
    agent = SecurityAgent()
    # Don't start the agent

    result = agent.analyze(make_event("C:/test/file.txt"))

    assert result is None


# ======================================================================
# Test 10 — Threat classification accuracy
# ======================================================================


def test_threat_classification_boundaries():
    """
    Verify threat level classification follows expected thresholds.
    """
    # LOW: .txt file
    response_txt = client.post(
        "/api/security/analyze",
        json=make_event("C:/sandbox/document.txt", event_type="created", event_id="evt-txt"),
    )
    assert response_txt.status_code == 200
    assert response_txt.json()["threat_level"] == "LOW"

    # HIGH/CRITICAL: .exe file
    response_exe = client.post(
        "/api/security/analyze",
        json=make_event("C:/sandbox/malware.exe", event_type="created", event_id="evt-exe"),
    )
    assert response_exe.status_code == 200
    assert response_exe.json()["threat_level"] in {"HIGH", "CRITICAL"}

    # .ps1 script (suspicious)
    response_ps1 = client.post(
        "/api/security/analyze",
        json=make_event("C:/sandbox/script.ps1", event_type="created", event_id="evt-ps1"),
    )
    assert response_ps1.status_code == 200
    ps1_level = response_ps1.json()["threat_level"]
    assert ps1_level in {"MEDIUM", "HIGH", "CRITICAL"}


# ======================================================================
# Test 11 — Deleted file handling
# ======================================================================


def test_security_agent_handles_deleted_file(tmp_path):
    """
    Deleted files should be handled safely without crashing.
    """
    file_path = tmp_path / "deleted.exe"
    file_path.write_text("will be deleted")

    # Now delete it
    file_path.unlink()
    assert not file_path.exists()

    agent = SecurityAgent()
    agent.start()

    result = agent.analyze(make_event(str(file_path), event_type="deleted"))

    assert result is not None
    assert result.investigation["exists"] is False
    assert result.threat_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    agent.stop()


# ======================================================================
# Test 12 — Directory event handling
# ======================================================================


def test_security_agent_handles_directory_event(tmp_path):
    """
    Directory events should be processed without error.
    """
    dir_path = tmp_path / "test_directory"
    dir_path.mkdir()

    agent = SecurityAgent()
    agent.start()

    event = make_event(str(dir_path), event_type="created", event_id="evt-dir")
    event["is_directory"] = True

    result = agent.analyze(event)

    assert result is not None
    assert result.investigation["is_directory"] is True

    agent.stop()


# ======================================================================
# Test 13 — Root endpoint shows security endpoint
# ======================================================================


def test_root_endpoint_lists_security():
    """
    The root endpoint should advertise the /api/security/analyze endpoint.
    """
    response = client.get("/")

    assert response.status_code == 200
    data = response.json()
    assert "security" in data
    assert data["security"] == "/api/security/analyze"


# ======================================================================
# Test 14 — API endpoint via TestClient works correctly
# ======================================================================


def test_security_api_with_testclient(tmp_path):
    """
    End-to-end test using FastAPI TestClient.
    """
    file_path = tmp_path / "e2e_test.exe"
    file_path.write_text("test executable")

    response = client.post(
        "/api/security/analyze",
        json={
            "event_id": "e2e-test",
            "event_type": "created",
            "path": str(file_path),
            "timestamp": "2026-09-01T12:00:00+00:00",
            "is_directory": False,
            "destination_path": None,
        },
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["event_id"] == "e2e-test"
    assert payload["threat_level"] in {"HIGH", "CRITICAL"}
    assert len(payload["findings"]) > 0
    assert len(payload["reasons"]) > 0
