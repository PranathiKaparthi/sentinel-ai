from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def make_event(path: str, event_type: str = "created") -> dict:
    path_obj = Path(path)

    return {
        "event_id": "router-test-event-001",
        "event_type": event_type,
        "path": str(path_obj),
        "timestamp": "2026-08-27T00:00:00+00:00",
        "is_directory": False,
        "destination_path": None,
        "file_name": path_obj.name,
        "extension": path_obj.suffix.lower(),
        "parent_directory": str(path_obj.parent),
        "file_size": 10,
    }


def test_analysis_existing_file(tmp_path):
    file_path = tmp_path / "demo.txt"
    file_path.write_text("hello")

    response = client.post(
        "/api/analysis/analyze",
        json=make_event(str(file_path)),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == "router-test-event-001"
    assert data["event_type"] == "created"
    assert data["exists"] is True
    assert data["is_directory"] is False
    assert data["file_name"] == "demo.txt"
    assert data["extension"] == ".txt"
    assert isinstance(data["observations"], list)


def test_analysis_deleted_file(tmp_path):
    file_path = tmp_path / "deleted.txt"

    response = client.post(
        "/api/analysis/analyze",
        json=make_event(
            str(file_path),
            "deleted",
        ),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["exists"] is False
    assert data["event_type"] == "deleted"
    assert data["current_file_size"] is None

    assert (
        "Filesystem deletion event detected."
        in data["observations"]
    )


def test_analysis_directory(tmp_path):
    directory = tmp_path / "folder"
    directory.mkdir()

    event = make_event(str(directory))
    event["is_directory"] = True
    event["file_name"] = "folder"
    event["extension"] = ""

    response = client.post(
        "/api/analysis/analyze",
        json=event,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["exists"] is True
    assert data["is_directory"] is True

    assert "Path is a directory." in data["observations"]


def test_analysis_modified_event(tmp_path):
    file_path = tmp_path / "modified.txt"
    file_path.write_text("changed")

    response = client.post(
        "/api/analysis/analyze",
        json=make_event(
            str(file_path),
            "modified",
        ),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_type"] == "modified"

    assert (
        "Filesystem modification event detected."
        in data["observations"]
    )


def test_analysis_moved_event(tmp_path):
    source = tmp_path / "old.txt"
    destination = tmp_path / "new.txt"

    source.write_text("hello")

    event = make_event(
        str(source),
        "moved",
    )

    event["destination_path"] = str(destination)

    response = client.post(
        "/api/analysis/analyze",
        json=event,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_type"] == "moved"

    assert (
        f"Destination path: {destination}"
        in data["observations"]
    )


def test_invalid_event_returns_400():
    response = client.post(
        "/api/analysis/analyze",
        json={
            "event_type": "created",
        },
    )

    assert response.status_code == 400


def test_analysis_does_not_modify_file(tmp_path):
    file_path = tmp_path / "protected.txt"
    original_content = "DO NOT MODIFY"

    file_path.write_text(original_content)

    response = client.post(
        "/api/analysis/analyze",
        json=make_event(str(file_path)),
    )

    assert response.status_code == 200
    assert file_path.read_text() == original_content