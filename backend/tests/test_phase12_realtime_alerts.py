"""
test_phase12_realtime_alerts.py

End-to-end tests for real-time analysis:

    file change -> MonitorAgent -> SecurityOrchestrator
                -> threat score -> decision -> SQLite -> /alerts, /stats

Uses a temporary sandbox directory and the temporary test database
configured in conftest.py.
"""

import time

import pytest
from fastapi.testclient import TestClient

from app import config as config_module
from app.agents.monitor_agent import MonitorAgent
from app.db.database import Database
from app.main import app
from app.repositories.security_event_repository import SecurityEventRepository
from app.services.security_orchestrator import SecurityOrchestrator


@pytest.fixture(autouse=True)
def clean_db():
    Database.reset_for_testing()
    yield
    Database.reset_for_testing()


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module.settings, "monitored_directory", str(tmp_path))
    return tmp_path


def _wait_until(predicate, timeout=5.0, interval=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_live_suspicious_file_is_scored_persisted_and_alerted(sandbox):
    orchestrator = SecurityOrchestrator()
    repo = SecurityEventRepository()
    agent = MonitorAgent(name="LiveTest", event_sink=orchestrator.process)
    agent.start()
    try:
        (sandbox / "payload.exe").write_bytes(b"MZ fake")
        assert _wait_until(lambda: agent.get_status()["alert_count"] >= 1)

        status = agent.get_status()
        assert status["real_time_analysis"] is True
        assert status["last_alert"]["decision"] in ("ALERT", "ESCALATE")
        assert status["last_alert"]["path"].endswith("payload.exe")

        alerts = repo.list_alerts()
        assert any(a.path.endswith("payload.exe") for a in alerts)
    finally:
        agent.stop()
        orchestrator.stop()


def test_live_harmless_file_is_persisted_but_not_alerted(sandbox):
    orchestrator = SecurityOrchestrator()
    repo = SecurityEventRepository()
    agent = MonitorAgent(name="LiveTest2", event_sink=orchestrator.process)
    agent.start()
    try:
        (sandbox / "notes.txt").write_text("hello")
        assert _wait_until(lambda: repo.count() >= 1)
        assert agent.get_status()["alert_count"] == 0
        assert repo.count_alerts() == 0
    finally:
        agent.stop()
        orchestrator.stop()


def test_agent_without_sink_keeps_phase2_behaviour(sandbox):
    agent = MonitorAgent(name="NoSink")
    agent.start()
    try:
        (sandbox / "a.exe").write_text("x")
        assert _wait_until(lambda: agent.get_status()["event_count"] >= 1)
        status = agent.get_status()
        assert status["real_time_analysis"] is False
        assert status["alert_count"] == 0
        assert SecurityEventRepository().count() == 0
    finally:
        agent.stop()


def test_sink_failure_does_not_stop_monitoring(sandbox):
    def broken_sink(event):
        raise RuntimeError("boom")

    agent = MonitorAgent(name="Broken", event_sink=broken_sink)
    agent.start()
    try:
        (sandbox / "one.txt").write_text("1")
        (sandbox / "two.txt").write_text("2")
        assert _wait_until(lambda: agent.get_status()["event_count"] >= 2)
        assert agent.is_running()
    finally:
        agent.stop()


def test_alerts_and_stats_endpoints():
    client = TestClient(app)
    ts = "2026-01-01T00:00:00+00:00"
    client.post("/api/security/analyze", json={
        "event_type": "created", "path": "/sandbox/run.ps1", "timestamp": ts, "is_directory": False,
    })
    client.post("/api/security/analyze", json={
        "event_type": "created", "path": "/sandbox/readme.txt", "timestamp": ts, "is_directory": False,
    })

    alerts = client.get("/api/security/alerts").json()
    assert alerts["total"] == 1
    assert alerts["alerts"][0]["path"] == "/sandbox/run.ps1"

    stats = client.get("/api/security/stats").json()
    assert stats["total_events"] == 2
    assert sum(stats["by_decision"].values()) == 2
    assert sum(stats["by_threat_level"].values()) == 2
    assert stats["by_decision"]["ALLOW"] == 1


def test_resubmitting_same_event_is_not_duplicated():
    client = TestClient(app)
    event = {"event_type": "created", "path": "/sandbox/x.bat",
             "timestamp": "2026-01-02T00:00:00+00:00", "is_directory": False}
    first = client.post("/api/security/analyze", json=event).json()
    second = client.post("/api/security/analyze", json=event).json()
    assert first["event_id"] == second["event_id"]
    assert client.get("/api/security/stats").json()["total_events"] == 1
