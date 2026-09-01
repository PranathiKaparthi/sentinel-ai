from pathlib import Path

from fastapi.testclient import TestClient

from app.agents.analysis_agent import AnalysisAgent, AnalysisAgentResult
from app.main import app
from app.models.investigation_result import InvestigationResult
from app.models.security_event import SecurityEvent
from app.services.analyzer import Analyzer

client = TestClient(app)


def make_event(path: str, event_type: str = "created") -> SecurityEvent:
    path_obj = Path(path)
    return SecurityEvent(
        event_type=event_type,
        path=str(path_obj),
        timestamp="2026-08-27T00:00:00+00:00",
        is_directory=False,
        destination_path=None,
        event_id="phase4-test-event",
        file_name=path_obj.name,
        extension=path_obj.suffix.lower(),
        parent_directory=str(path_obj.parent),
        file_size=10,
    )


def make_investigation(event: SecurityEvent, *, exists: bool = True, is_directory: bool = False, size: int | None = 10) -> InvestigationResult:
    return InvestigationResult.create(
        event_id=event.event_id,
        event_type=event.event_type,
        path=event.path,
        exists=exists,
        is_directory=is_directory,
        current_file_size=size,
        file_name=event.file_name,
        extension=event.extension,
        parent_directory=event.parent_directory,
    )


def test_analysis_agent_suspicious_event():
    event = make_event("C:/sandbox/payload.exe")
    investigation = make_investigation(event)
    analysis = Analyzer.analyze(event, investigation)

    result = AnalysisAgent.analyze(event, investigation, analysis)

    assert result is not None
    assert result.event_id == event.event_id
    assert 0 <= result.suspicion_score <= 100
    assert 0 <= result.threat_score <= 100
    assert result.threat_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result.findings
    assert result.reasons
    assert result.suspicion_score >= result.threat_score or result.suspicion_score == result.threat_score


def test_analysis_agent_benign_event():
    event = make_event("C:/sandbox/readme.txt")
    investigation = make_investigation(event)
    analysis = Analyzer.analyze(event, investigation)

    result = AnalysisAgent.analyze(event, investigation, analysis)

    assert result is not None
    assert result.threat_level == "LOW"
    assert result.suspicion_score <= 30
    assert result.threat_score <= 30


def test_analysis_agent_threshold_boundaries():
    assert AnalysisAgent.score_to_threat_level(0) == "LOW"
    assert AnalysisAgent.score_to_threat_level(30) == "LOW"
    assert AnalysisAgent.score_to_threat_level(31) == "MEDIUM"
    assert AnalysisAgent.score_to_threat_level(60) == "MEDIUM"
    assert AnalysisAgent.score_to_threat_level(61) == "HIGH"
    assert AnalysisAgent.score_to_threat_level(85) == "HIGH"
    assert AnalysisAgent.score_to_threat_level(86) == "CRITICAL"
    assert AnalysisAgent.score_to_threat_level(100) == "CRITICAL"


def test_analysis_agent_clamps_invalid_scores():
    result = AnalysisAgentResult.model_validate(
        {
            "event_id": "evt-1",
            "suspicion_score": -10,
            "findings": ["low confidence"],
            "threat_score": 150,
            "threat_level": "INVALID",
            "reasons": ["score was out of range"],
        }
    )

    assert 0 <= result.suspicion_score <= 100
    assert 0 <= result.threat_score <= 100
    assert result.threat_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_phase3_to_phase4_integration():
    event = make_event("C:/sandbox/malware.ps1")
    investigation = make_investigation(event)
    analysis = Analyzer.analyze(event, investigation)

    result = AnalysisAgent.analyze(event, investigation, analysis)

    assert result is not None
    assert result.event_id == event.event_id
    assert result.findings
    assert result.reasons
    assert result.threat_level in {"HIGH", "CRITICAL"}


def test_phase4_assess_api_valid_request():
    payload = {
        "event_type": "created",
        "path": "C:/sandbox/agent_test.exe",
        "timestamp": "2026-08-27T00:00:00+00:00",
        "is_directory": False,
        "destination_path": None,
        "event_id": "phase4-api-valid",
        "file_name": "agent_test.exe",
        "extension": ".exe",
        "parent_directory": "C:/sandbox",
        "file_size": 4096,
    }

    response = client.post("/api/analysis/assess", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["event_id"] == "phase4-api-valid"
    assert 0 <= data["suspicion_score"] <= 100
    assert 0 <= data["threat_score"] <= 100
    assert data["threat_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert isinstance(data["findings"], list)
    assert isinstance(data["reasons"], list)


def test_phase4_assess_api_invalid_request():
    response = client.post(
        "/api/analysis/assess",
        json={"event_type": "created", "path": "nope"},
    )

    assert response.status_code == 400


def test_phase4_history_list_and_detail():
    payload = {
        "event_type": "created",
        "path": "C:/sandbox/history_test.dll",
        "timestamp": "2026-08-27T00:00:00+00:00",
        "is_directory": False,
        "destination_path": None,
        "event_id": "phase4-history-item",
        "file_name": "history_test.dll",
        "extension": ".dll",
        "parent_directory": "C:/sandbox",
        "file_size": 512,
    }

    create_response = client.post("/api/analysis/assess", json=payload)
    assert create_response.status_code == 200
    item_id = create_response.json()["id"]

    list_response = client.get("/api/analysis/history")
    assert list_response.status_code == 200
    history = list_response.json()
    assert isinstance(history, list)
    assert any(item["id"] == item_id for item in history)

    detail_response = client.get(f"/api/analysis/history/{item_id}")
    assert detail_response.status_code == 200
    assert detail_response.json()["id"] == item_id

    missing_response = client.get("/api/analysis/history/does-not-exist")
    assert missing_response.status_code == 404


def test_phase4_history_empty_list():
    response = client.get("/api/analysis/history")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
