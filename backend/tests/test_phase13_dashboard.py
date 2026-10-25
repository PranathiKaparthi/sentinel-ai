"""
test_phase13_dashboard.py

Checks that the dashboard page is served and that it only uses API
endpoints that really exist.
"""

import re

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_dashboard_is_served_as_html():
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "SentinelAI Dashboard" in resp.text


def test_root_links_to_dashboard():
    assert client.get("/").json()["dashboard"] == "/dashboard"


def test_every_api_path_used_by_the_dashboard_exists():
    page = client.get("/dashboard").text
    used = set(re.findall(r'"(/api/[a-z/]+)', page))
    assert used, "dashboard should call the API"
    known = set(client.get("/openapi.json").json()["paths"])
    missing = [path for path in used if path not in known]
    assert not missing, f"dashboard calls unknown endpoints: {missing}"


def test_dashboard_never_uses_innerhtml():
    # API text (like file names) must be inserted with textContent to avoid XSS.
    assert ".innerHTML" not in client.get("/dashboard").text
