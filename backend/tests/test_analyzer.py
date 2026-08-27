from pathlib import Path

from app.models.investigation_result import InvestigationResult
from app.models.security_event import SecurityEvent
from app.services.analyzer import Analyzer


def make_event(
    path: str,
    event_type: str = "created",
) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        path=path,
        timestamp="2026-08-27T00:00:00+00:00",
        is_directory=False,
        event_id="test-event-123",
        file_name=Path(path).name,
        extension=Path(path).suffix.lower(),
        parent_directory=str(Path(path).parent),
        file_size=10,
    )


def make_investigation(
    event: SecurityEvent,
    *,
    exists: bool = True,
    is_directory: bool = False,
    size: int | None = 10,
) -> InvestigationResult:
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


def test_existing_file_is_analyzed():
    event = make_event("C:\\sandbox\\demo.txt")
    investigation = make_investigation(event)

    result = Analyzer.analyze(event, investigation)

    assert result is not None
    assert result.event_id == event.event_id
    assert result.exists is True
    assert result.is_directory is False
    assert result.current_file_size == 10


def test_created_event_observation():
    event = make_event("C:\\sandbox\\demo.txt", "created")
    investigation = make_investigation(event)

    result = Analyzer.analyze(event, investigation)

    assert result is not None
    assert "Filesystem creation event detected." in result.observations


def test_modified_event_observation():
    event = make_event("C:\\sandbox\\demo.txt", "modified")
    investigation = make_investigation(event)

    result = Analyzer.analyze(event, investigation)

    assert result is not None
    assert "Filesystem modification event detected." in result.observations


def test_deleted_file_is_handled():
    event = make_event("C:\\sandbox\\deleted.txt", "deleted")
    investigation = make_investigation(
        event,
        exists=False,
        size=None,
    )

    result = Analyzer.analyze(event, investigation)

    assert result is not None
    assert result.exists is False
    assert result.current_file_size is None
    assert "Filesystem deletion event detected." in result.observations


def test_directory_is_described():
    event = make_event("C:\\sandbox\\folder")
    investigation = make_investigation(
        event,
        exists=True,
        is_directory=True,
        size=None,
    )

    result = Analyzer.analyze(event, investigation)

    assert result is not None
    assert result.is_directory is True
    assert "Path is a directory." in result.observations


def test_extension_is_reported():
    event = make_event("C:\\sandbox\\malware.exe")
    investigation = make_investigation(event)

    result = Analyzer.analyze(event, investigation)

    assert result is not None
    assert "File extension identified: .exe" in result.observations


def test_no_extension_is_reported():
    event = make_event("C:\\sandbox\\README")
    investigation = make_investigation(event)

    result = Analyzer.analyze(event, investigation)

    assert result is not None
    assert "No file extension identified." in result.observations


def test_analysis_is_json_serializable():
    event = make_event("C:\\sandbox\\demo.txt")
    investigation = make_investigation(event)

    result = Analyzer.analyze(event, investigation)

    assert result is not None

    data = result.to_dict()

    assert isinstance(data, dict)
    assert data["event_id"] == "test-event-123"
    assert isinstance(data["observations"], list)


def test_invalid_input_is_handled_safely():
    result = Analyzer.analyze(None, None)

    assert result is None