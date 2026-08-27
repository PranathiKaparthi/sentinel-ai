from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_investigate_existing_file(tmp_path: Path):
    """Existing file should return read-only filesystem metadata."""

    test_file = tmp_path / "sample.txt"
    test_file.write_text("SentinelAI investigation test")

    payload = {
        "event_type": "created",
        "path": str(test_file),
        "timestamp": "2026-08-27T20:00:00+00:00",
        "is_directory": False,
        "destination_path": None,
        "event_id": "test-event-001",
        "file_name": "sample.txt",
        "extension": ".txt",
        "parent_directory": str(tmp_path),
        "file_size": test_file.stat().st_size,
    }

    response = client.post(
        "/api/investigation/investigate",
        json=payload,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == "test-event-001"
    assert data["event_type"] == "created"
    assert data["path"] == str(test_file)
    assert data["exists"] is True
    assert data["is_directory"] is False
    assert data["current_file_size"] == test_file.stat().st_size
    assert data["file_name"] == "sample.txt"
    assert data["extension"] == ".txt"
    assert data["parent_directory"] == str(tmp_path)
    assert "investigation_timestamp" in data


def test_investigate_deleted_file(tmp_path: Path):
    """Deleted/nonexistent files should be handled safely."""

    deleted_file = tmp_path / "deleted.txt"

    payload = {
        "event_type": "deleted",
        "path": str(deleted_file),
        "timestamp": "2026-08-27T20:00:00+00:00",
        "is_directory": False,
        "destination_path": None,
        "event_id": "test-event-002",
        "file_name": "deleted.txt",
        "extension": ".txt",
        "parent_directory": str(tmp_path),
        "file_size": None,
    }

    response = client.post(
        "/api/investigation/investigate",
        json=payload,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == "test-event-002"
    assert data["event_type"] == "deleted"
    assert data["exists"] is False
    assert data["is_directory"] is False
    assert data["current_file_size"] is None


def test_investigate_directory(tmp_path: Path):
    """Directories should be identified without attempting file-size lookup."""

    test_dir = tmp_path / "test_directory"
    test_dir.mkdir()

    payload = {
        "event_type": "created",
        "path": str(test_dir),
        "timestamp": "2026-08-27T20:00:00+00:00",
        "is_directory": True,
        "destination_path": None,
        "event_id": "test-event-003",
        "file_name": "test_directory",
        "extension": "",
        "parent_directory": str(tmp_path),
        "file_size": None,
    }

    response = client.post(
        "/api/investigation/investigate",
        json=payload,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == "test-event-003"
    assert data["exists"] is True
    assert data["is_directory"] is True
    assert data["current_file_size"] is None


def test_invalid_event_returns_400():
    """Missing required SecurityEvent fields should return HTTP 400."""

    payload = {
        "event_type": "created",
        "path": "some_file.txt",
    }

    response = client.post(
        "/api/investigation/investigate",
        json=payload,
    )

    assert response.status_code == 400
    assert "Invalid SecurityEvent" in response.json()["detail"]


def test_investigation_does_not_modify_file(tmp_path: Path):
    """Investigation must remain strictly read-only."""

    test_file = tmp_path / "readonly_test.txt"
    original_content = "DO NOT MODIFY THIS FILE"
    test_file.write_text(original_content)

    original_size = test_file.stat().st_size

    payload = {
        "event_type": "modified",
        "path": str(test_file),
        "timestamp": "2026-08-27T20:00:00+00:00",
        "is_directory": False,
        "destination_path": None,
        "event_id": "test-event-004",
        "file_name": "readonly_test.txt",
        "extension": ".txt",
        "parent_directory": str(tmp_path),
        "file_size": original_size,
    }

    response = client.post(
        "/api/investigation/investigate",
        json=payload,
    )

    assert response.status_code == 200

    assert test_file.exists()
    assert test_file.read_text() == original_content
    assert test_file.stat().st_size == original_size