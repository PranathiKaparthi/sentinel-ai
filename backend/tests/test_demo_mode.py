"""
test_demo_mode.py

Demo mode for hosted deployments: off by default, and when on it creates
harmless sample files only inside the watched folder, which flow through
the live pipeline as real security events.
"""

import time

import pytest
from fastapi.testclient import TestClient

import app.config as config_module
from app.main import app
from app.routers import monitor


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
    monitor.shutdown()


def test_demo_disabled_by_default(client, monkeypatch):
    monkeypatch.delenv("ENABLE_DEMO", raising=False)
    assert client.get("/api/demo/status").json() == {"enabled": False}
    assert client.post("/api/demo/simulate").status_code == 404


def test_demo_creates_files_inside_watched_folder(client, tmp_path, monkeypatch):
    monkeypatch.setenv("ENABLE_DEMO", "true")
    monitor.shutdown()
    monkeypatch.setattr(config_module.settings, "monitored_directory", str(tmp_path))

    assert client.get("/api/demo/status").json() == {"enabled": True}
    resp = client.post("/api/demo/simulate")
    assert resp.status_code == 200
    body = resp.json()

    demo_dir = tmp_path / "sentinel_demo"
    assert body["folder"] == str(demo_dir)
    assert len(body["files"]) == 3
    for name in body["files"]:
        assert (demo_dir / name).is_file()

    # The executable sample should reach the pipeline and be flagged.
    exe_name = next(n for n in body["files"] if n.endswith(".exe"))
    deadline = time.time() + 5
    flagged = False
    while time.time() < deadline and not flagged:
        events = client.get("/api/security/events?limit=50").json()
        rows = events.get("events", events) if isinstance(events, dict) else events
        flagged = any(
            exe_name in f"{row.get('path', '')} {row.get('destination_path') or ''}"
            and row.get("decision") in {"ALERT", "ESCALATE"}
            for row in rows
        )
        time.sleep(0.2)
    assert flagged, "demo .exe file was not flagged by the live pipeline"
