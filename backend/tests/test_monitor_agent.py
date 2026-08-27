"""
test_monitor_agent.py

Automated tests for MonitorAgent covering create, modify, move/rename,
and delete events, plus lifecycle behavior (clean start/stop, no
duplicate observers, invalid-directory handling).

Isolation note: rather than writing test files directly into the
project's checked-in test_environment/ folder (which would leave
leftover artifacts across test runs), each test points a fresh
MonitorAgent at a pytest-managed temporary directory via monkeypatching
`settings.monitored_directory`. This is strictly more isolated than
watching test_environment/ directly while satisfying the same safety
requirement the spec cares about: only a disposable sandbox directory is
ever watched, never the real filesystem.
"""

import time
from pathlib import Path

import pytest

from app.agents.monitor_agent import MonitorAgent, MonitorDirectoryError
from app import config as config_module


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Point settings.monitored_directory at a fresh temp directory."""
    monkeypatch.setattr(config_module.settings, "monitored_directory", str(tmp_path))
    return tmp_path


@pytest.fixture
def agent(sandbox):
    """A fresh, started MonitorAgent watching the sandbox directory."""
    a = MonitorAgent(name="TestMonitorAgent")
    a.start()
    yield a
    a.stop()


def _wait_until(predicate, timeout: float = 5.0, interval: float = 0.1) -> bool:
    """Poll `predicate()` until it returns truthy or timeout elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def test_agent_inherits_base_agent_and_starts(agent):
    from app.agents.base_agent import BaseAgent

    assert isinstance(agent, BaseAgent)
    assert agent.is_running() is True
    status = agent.get_status()
    assert status["running"] is True
    assert status["watching"] is not None


def test_uses_configured_directory_not_hardcoded(sandbox):
    agent = MonitorAgent(name="TestMonitorAgent2")
    agent.start()
    try:
        assert Path(agent.get_status()["watching"]) == sandbox.resolve()
    finally:
        agent.stop()


def test_missing_directory_raises_clear_error(monkeypatch):
    monkeypatch.setattr(
        config_module.settings, "monitored_directory", "/definitely/not/a/real/path"
    )
    agent = MonitorAgent(name="TestMonitorAgent3")
    with pytest.raises(MonitorDirectoryError):
        agent.start()
    assert agent.is_running() is False


def test_created_event_detected(agent, sandbox):
    target = sandbox / "example.txt"
    target.write_text("hello")

    found = _wait_until(
        lambda: any(
            e["event_type"] == "created" and e["path"] == str(target.resolve())
            for e in agent.get_events()
        )
    )
    assert found, f"created event not seen; events={agent.get_events()}"


def test_modified_event_detected(agent, sandbox):
    target = sandbox / "example.txt"
    target.write_text("hello")
    _wait_until(lambda: len(agent.get_events()) > 0)

    target.write_text("hello again, modified")

    found = _wait_until(
        lambda: any(
            e["event_type"] == "modified" and e["path"] == str(target.resolve())
            for e in agent.get_events()
        )
    )
    assert found, f"modified event not seen; events={agent.get_events()}"


def test_moved_event_detected(agent, sandbox):
    source = sandbox / "before.txt"
    destination = sandbox / "after.txt"
    source.write_text("content")
    _wait_until(lambda: len(agent.get_events()) > 0)

    source.rename(destination)

    found = _wait_until(
        lambda: any(
            e["event_type"] == "moved"
            and e["path"] == str(source.resolve())
            and e["destination_path"] == str(destination.resolve())
            for e in agent.get_events()
        )
    )
    assert found, f"moved event not seen; events={agent.get_events()}"


def test_deleted_event_detected(agent, sandbox):
    target = sandbox / "to_delete.txt"
    target.write_text("content")
    _wait_until(lambda: len(agent.get_events()) > 0)

    target.unlink()

    found = _wait_until(
        lambda: any(
            e["event_type"] == "deleted" and e["path"] == str(target.resolve())
            for e in agent.get_events()
        )
    )
    assert found, f"deleted event not seen; events={agent.get_events()}"


def test_events_have_required_fields(agent, sandbox):
    (sandbox / "shape_check.txt").write_text("x")
    _wait_until(lambda: len(agent.get_events()) > 0)

    event = agent.get_events()[-1]
    for field in ("event_type", "path", "timestamp", "is_directory", "destination_path"):
        assert field in event


def test_stop_releases_observer(agent):
    agent.stop()
    assert agent.is_running() is False
    assert agent._file_monitor is None


def test_duplicate_start_does_not_create_second_observer(agent, sandbox):
    first_monitor = agent._file_monitor
    agent.start()  # calling start() again while already running
    assert agent._file_monitor is first_monitor  # unchanged: no second observer
    assert agent.is_running() is True


def test_restart_after_stop_resumes_monitoring(agent, sandbox):
    agent.stop()
    assert agent.is_running() is False

    agent.start()
    assert agent.is_running() is True

    target = sandbox / "after_restart.txt"
    target.write_text("content")

    found = _wait_until(
        lambda: any(
            e["event_type"] == "created" and e["path"] == str(target.resolve())
            for e in agent.get_events()
        )
    )
    assert found, "monitoring did not resume after restart"
