from app.models.security_event import SecurityEvent
from app.services.investigator import Investigator


def _event(
    event_type="created",
    path=r"C:\test\sample.txt",
):
    return SecurityEvent(
        event_type=event_type,
        path=path,
        timestamp="2026-08-27T00:00:00+00:00",
        is_directory=False,
        destination_path=None,
        file_name="sample.txt",
        extension=".txt",
        parent_directory=r"C:\test",
        file_size=None,
    )


def test_existing_file_is_investigated(tmp_path):
    real_file = tmp_path / "sample.txt"
    real_file.write_text("hello world")

    event = _event(path=str(real_file))

    result = Investigator.investigate(event)

    assert result is not None
    assert result.event_id == event.event_id
    assert result.event_type == "created"
    assert result.path == str(real_file)
    assert result.exists is True
    assert result.is_directory is False
    assert result.current_file_size == len("hello world")


def test_nonexistent_file_is_handled_safely():
    event = _event(
        event_type="deleted",
        path=r"C:\definitely\does\not\exist.txt",
    )

    result = Investigator.investigate(event)

    assert result is not None
    assert result.exists is False
    assert result.current_file_size is None


def test_directory_is_identified(tmp_path):
    directory = tmp_path / "sample_folder"
    directory.mkdir()

    event = _event(path=str(directory))

    result = Investigator.investigate(event)

    assert result is not None
    assert result.exists is True
    assert result.is_directory is True
    assert result.current_file_size is None


def test_metadata_is_preserved():
    event = _event()

    result = Investigator.investigate(event)

    assert result is not None
    assert result.event_id == event.event_id
    assert result.event_type == event.event_type
    assert result.path == event.path
    assert result.file_name == event.file_name
    assert result.extension == event.extension
    assert result.parent_directory == event.parent_directory


def test_investigation_does_not_raise_for_invalid_input():
    result = Investigator.investigate(None)

    assert result is None