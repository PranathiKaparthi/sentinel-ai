"""
test_phase11_process_monitor.py

Tests for the read-only ProcessMonitor. The risk rules are tested on
hand-built ProcessInfo objects, so results do not depend on what happens
to be running on the test machine.
"""

from fastapi.testclient import TestClient

from app.main import app
from app.services.process_monitor import ProcessInfo, ProcessMonitor, assess, score_to_level


def _proc(name="notepad.exe", exe="C:\\Windows\\notepad.exe", cpu=1.0, mem=1.0, pid=100):
    return ProcessInfo(pid=pid, name=name, exe=exe, username="user", cpu_percent=cpu, memory_percent=mem)


def test_normal_process_is_low_risk():
    p = assess(_proc())
    assert p.risk_score == 0
    assert p.risk_level == "LOW"
    assert p.reasons == []


def test_high_cpu_is_flagged():
    p = assess(_proc(cpu=95.0))
    assert p.risk_score == 30
    assert any("CPU" in r for r in p.reasons)


def test_high_memory_is_flagged():
    p = assess(_proc(mem=40.0))
    assert p.risk_score == 20
    assert any("memory" in r for r in p.reasons)


def test_running_from_temp_folder_is_flagged_windows():
    p = assess(_proc(exe="C:\\Users\\a\\AppData\\Local\\Temp\\update.exe", name="update.exe"))
    assert p.risk_score == 35
    assert p.risk_level == "MEDIUM"


def test_running_from_tmp_folder_is_flagged_linux():
    p = assess(_proc(exe="/tmp/miner", name="miner"))
    assert p.risk_score == 35


def test_lookalike_system_name_is_flagged():
    p = assess(_proc(name="svch0st.exe", exe="C:\\Users\\Public\\svch0st.exe"))
    # lookalike (+40) + public folder (+35)
    assert p.risk_score == 75
    assert p.risk_level == "HIGH"
    assert any("svchost.exe" in r for r in p.reasons)


def test_real_system_name_is_not_flagged():
    p = assess(_proc(name="svchost.exe", exe="C:\\Windows\\System32\\svchost.exe"))
    assert p.risk_score == 0


def test_score_is_capped_at_100():
    p = assess(_proc(name="svch0st.exe", exe="C:\\Users\\Public\\svch0st.exe", cpu=99, mem=60))
    assert p.risk_score == 100
    assert p.risk_level == "CRITICAL"


def test_score_to_level_boundaries():
    assert score_to_level(30) == "LOW"
    assert score_to_level(31) == "MEDIUM"
    assert score_to_level(60) == "MEDIUM"
    assert score_to_level(61) == "HIGH"
    assert score_to_level(85) == "HIGH"
    assert score_to_level(86) == "CRITICAL"


def test_find_suspicious_filters_and_sorts():
    procs = [
        _proc(pid=1),
        _proc(pid=2, cpu=95.0, exe="/tmp/x", name="x"),  # 65
        _proc(pid=3, exe="/tmp/y", name="y"),  # 35
    ]
    flagged = ProcessMonitor.find_suspicious(procs, min_score=31)
    assert [p.pid for p in flagged] == [2, 3]


def test_snapshot_returns_real_processes():
    snapshot = ProcessMonitor.snapshot(sample_seconds=0.1)
    assert len(snapshot) > 0
    assert all(isinstance(p.pid, int) for p in snapshot)


def test_suspicious_endpoint_shape(monkeypatch):
    monkeypatch.setattr(ProcessMonitor, "snapshot", staticmethod(lambda sample_seconds=0.5: [
        _proc(pid=7, name="svch0st.exe", exe="C:\\Users\\Public\\svch0st.exe"),
        _proc(pid=8),
    ]))
    client = TestClient(app)
    resp = client.get("/api/system/processes/suspicious")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["processes"][0]["pid"] == 7
    assert body["processes"][0]["risk_level"] == "HIGH"


def test_top_processes_endpoint(monkeypatch):
    monkeypatch.setattr(ProcessMonitor, "snapshot", staticmethod(lambda sample_seconds=0.5: [
        _proc(pid=1, cpu=5), _proc(pid=2, cpu=50), _proc(pid=3, cpu=20),
    ]))
    client = TestClient(app)
    resp = client.get("/api/system/processes?limit=2&sort_by=cpu")
    assert resp.status_code == 200
    assert [p["pid"] for p in resp.json()["processes"]] == [2, 3]
