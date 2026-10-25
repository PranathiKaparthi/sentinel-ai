"""
test_phase14_multi_folder.py

Watching several folders at once, skipping noise, never watching
SentinelAI's own database, and scoring files renamed to executables.
"""

import time

import pytest

from app import config as config_module
from app.agents.monitor_agent import MonitorAgent, MonitorDirectoryError
from app.db.database import get_db_path


def _wait_until(predicate, timeout=5.0, interval=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _paths(agent):
    return [e["path"] for e in agent.get_events()]


@pytest.fixture
def two_folders(tmp_path, monkeypatch):
    a = tmp_path / "Downloads"
    b = tmp_path / "Desktop"
    a.mkdir()
    b.mkdir()
    monkeypatch.setattr(config_module.settings, "monitored_directory", f"{a};{b}")
    return a, b


def test_watches_every_configured_folder(two_folders):
    a, b = two_folders
    agent = MonitorAgent(name="Multi")
    agent.start()
    try:
        status = agent.get_status()
        assert sorted(status["watching_all"]) == sorted([str(a.resolve()), str(b.resolve())])
        (a / "one.txt").write_text("1")
        (b / "two.txt").write_text("2")
        assert _wait_until(lambda: any(p.endswith("one.txt") for p in _paths(agent))
                           and any(p.endswith("two.txt") for p in _paths(agent)))
    finally:
        agent.stop()


def test_missing_folder_is_skipped_when_another_is_valid(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module.settings, "monitored_directory",
                        f"{tmp_path / 'nope'};{tmp_path}")
    agent = MonitorAgent(name="Skip")
    agent.start()
    try:
        assert agent.get_status()["watching_all"] == [str(tmp_path.resolve())]
    finally:
        agent.stop()


def test_all_missing_folders_raise(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module.settings, "monitored_directory",
                        f"{tmp_path / 'a'};{tmp_path / 'b'}")
    with pytest.raises(MonitorDirectoryError):
        MonitorAgent(name="None").start()


def test_nested_folder_is_not_watched_twice(tmp_path, monkeypatch):
    inner = tmp_path / "inner"
    inner.mkdir()
    monkeypatch.setattr(config_module.settings, "monitored_directory", f"{inner};{tmp_path}")
    agent = MonitorAgent(name="Nested")
    agent.start()
    try:
        assert agent.get_status()["watching_all"] == [str(tmp_path.resolve())]
    finally:
        agent.stop()


def test_noise_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module.settings, "monitored_directory", str(tmp_path))
    monkeypatch.setattr(config_module.settings, "ignore_patterns", "node_modules;*.tmp")
    (tmp_path / "node_modules").mkdir()
    agent = MonitorAgent(name="Noise")
    agent.start()
    try:
        (tmp_path / "node_modules" / "lib.js").write_text("x")
        (tmp_path / "scratch.tmp").write_text("x")
        (tmp_path / "real.txt").write_text("x")
        assert _wait_until(lambda: any(p.endswith("real.txt") for p in _paths(agent)))
        time.sleep(0.5)
        paths = _paths(agent)
        assert not any("node_modules" in p for p in paths)
        assert not any(p.endswith(".tmp") for p in paths)
        assert agent.get_status()["ignored_count"] >= 2
    finally:
        agent.stop()


def test_own_database_is_never_analysed(tmp_path, monkeypatch):
    db = tmp_path / "security_events.db"
    monkeypatch.setenv("SENTINEL_DB_PATH", str(db))
    monkeypatch.setattr(config_module.settings, "monitored_directory", str(tmp_path))
    assert get_db_path() == db
    agent = MonitorAgent(name="SelfLoop")
    agent.start()
    try:
        db.write_text("db")
        (tmp_path / "security_events.db-journal").write_text("j")
        (tmp_path / "other.txt").write_text("x")
        assert _wait_until(lambda: any(p.endswith("other.txt") for p in _paths(agent)))
        time.sleep(0.5)
        assert not any("security_events.db" in p for p in _paths(agent))
    finally:
        agent.stop()


def test_rename_to_executable_escalates_through_full_pipeline():
    from app.services.security_orchestrator import SecurityOrchestrator
    from app.db.database import Database
    Database.reset_for_testing()
    orchestrator = SecurityOrchestrator()
    try:
        result = orchestrator.process({
            "event_type": "moved",
            "path": "/downloads/notes.txt",
            "destination_path": "/downloads/payload.exe",
            "timestamp": "2026-10-25T10:00:01+00:00",
            "is_directory": False,
        })
        assert result is not None
        assert result.threat_level in ("HIGH", "CRITICAL")
        assert result.security_decision.decision == "ESCALATE"
        assert any("renamed to a suspicious extension" in f.lower()
                   for f in result.orchestration_result.findings)
    finally:
        orchestrator.stop()
        Database.reset_for_testing()


def test_rename_to_text_file_stays_low():
    from app.services.security_orchestrator import SecurityOrchestrator
    from app.db.database import Database
    Database.reset_for_testing()
    orchestrator = SecurityOrchestrator()
    try:
        result = orchestrator.process({
            "event_type": "moved",
            "path": "/downloads/a.txt",
            "destination_path": "/downloads/b.txt",
            "timestamp": "2026-10-25T10:00:02+00:00",
            "is_directory": False,
        })
        assert result.security_decision.decision != "ESCALATE"
    finally:
        orchestrator.stop()
        Database.reset_for_testing()


def test_database_inside_watched_folder_does_not_loop(tmp_path, monkeypatch):
    """Saving to the DB must not trigger endless 'folder modified' events."""
    from app.db.database import Database
    from app.services.security_orchestrator import SecurityOrchestrator

    db = tmp_path / "security_events.db"
    monkeypatch.setenv("SENTINEL_DB_PATH", str(db))
    monkeypatch.setattr(config_module.settings, "monitored_directory", str(tmp_path))

    # Point the shared connection at the temporary DB for this test.
    Database().close()
    orchestrator = SecurityOrchestrator()
    agent = MonitorAgent(name="Loop", event_sink=orchestrator.process)
    agent.start()
    try:
        (tmp_path / "payload.exe").write_text("x")
        assert _wait_until(lambda: agent.get_status()["alert_count"] >= 1)
        time.sleep(1.5)
        settled = agent.get_status()["analyzed_count"]
        time.sleep(1.5)
        # No new analyses once the file's own events are done.
        assert agent.get_status()["analyzed_count"] == settled
        assert settled < 10
        assert not any(e["is_directory"] and e["event_type"] == "modified" for e in agent.get_events())
    finally:
        agent.stop()
        orchestrator.stop()
        Database().close()


def test_a_failing_event_does_not_kill_the_watcher(tmp_path, monkeypatch):
    """One bad event must be skipped, not stop monitoring for good."""
    monkeypatch.setattr(config_module.settings, "monitored_directory", str(tmp_path))
    agent = MonitorAgent(name="Robust")
    calls = {"n": 0}
    original = agent._is_ignored

    def flaky(raw_event):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("simulated Windows/OneDrive error")
        return original(raw_event)

    monkeypatch.setattr(agent, "_is_ignored", flaky)
    agent.start()
    try:
        (tmp_path / "first.txt").write_text("1")
        assert _wait_until(lambda: calls["n"] >= 1)
        (tmp_path / "second.txt").write_text("2")
        assert _wait_until(lambda: any(p.endswith("second.txt") for p in _paths(agent)))
        assert agent.get_status()["watchers_alive"] is True
    finally:
        agent.stop()
