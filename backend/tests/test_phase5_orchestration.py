from pathlib import Path

from fastapi.testclient import TestClient

from app.agents.orchestrator_agent import OrchestratorAgent
from app.main import app

client = TestClient(app)


def make_event(path: str, event_type: str = "created") -> dict:
    path_obj = Path(path)
    return {
        "event_id": "phase5-orchestration-event",
        "event_type": event_type,
        "path": str(path_obj),
        "timestamp": "2026-08-27T00:00:00+00:00",
        "is_directory": False,
        "destination_path": None,
    }


def test_orchestrator_agent_runs_complete_pipeline(tmp_path):
    file_path = tmp_path / "payload.exe"
    file_path.write_text("fake payload", encoding="utf-8")

    result = OrchestratorAgent.process(make_event(str(file_path), event_type="created"))

    assert result is not None
    assert result.event_id == "phase5-orchestration-event"
    assert result.security_event["event_id"] == "phase5-orchestration-event"
    assert result.investigation["event_id"] == "phase5-orchestration-event"
    assert result.analysis["event_id"] == "phase5-orchestration-event"
    assert 0 <= result.suspicion_score <= 100
    assert 0 <= result.threat_score <= 100
    assert result.threat_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result.findings
    assert result.reasons


def test_pipeline_api_returns_orchestrated_result():
    response = client.post(
        "/api/pipeline/process",
        json=make_event("C:/sandbox/phase5_test.dll", event_type="created"),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["event_id"] == "phase5-orchestration-event"
    assert "security_event" in payload
    assert "investigation" in payload
    assert "analysis" in payload
    assert "suspicion_score" in payload
    assert "threat_score" in payload
    assert "threat_level" in payload


def test_pipeline_api_rejects_invalid_event():
    response = client.post(
        "/api/pipeline/process",
        json={"event_type": "invalid", "path": "C:/bad/file.txt", "timestamp": "2026-08-27T00:00:00+00:00"},
    )

    assert response.status_code == 400
