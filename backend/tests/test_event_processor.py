"""
test_event_processor.py

Unit tests for EventProcessor (Phase 3): validation, normalization,
and enrichment of raw FileMonitor event dicts into SecurityEvent
objects.

These tests use tmp_path for any real file, and hand-built dicts for
the raw "event" input, so they run instantly with no filesystem
watching involved (that's already covered by test_monitor_agent.py).
"""

from app.services.event_processor import EventProcessor


def _raw(event_type="created", path="C:\\test\\invoice.exe", **overrides):
    base = {
        "event_type": event_type,
        "path": path,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "is_directory": False,
        "destination_path": None,
    }
    base.update(overrides)
    return base


def test_created_file_is_processed():
    event = EventProcessor.process(_raw(event_type="created"))
    assert event is not None
    assert event.event_type == "created"


def test_modified_file_is_processed():
    event = EventProcessor.process(_raw(event_type="modified"))
    assert event is not None
    assert event.event_type == "modified"


def test_deleted_file_is_processed_without_size_lookup():
    event = EventProcessor.process(_raw(event_type="deleted"))
    assert event is not None
    assert event.event_type == "deleted"
    # Deleted files must never trigger a stat() call (Phase 3.4).
    assert event.file_size is None


def test_moved_file_preserves_destination_path():
    event = EventProcessor.process(
        _raw(
            event_type="moved",
            path="C:\\test\\before.txt",
            destination_path="C:\\test\\after.txt",
        )
    )
    assert event is not None
    assert event.destination_path == "C:\\test\\after.txt"


def test_directory_event_is_processed():
    event = EventProcessor.process(
        _raw(event_type="created", path="C:\\test\\subfolder", is_directory=True)
    )
    assert event is not None
    assert event.is_directory is True
    assert event.file_size is None


def test_missing_path_returns_none():
    raw = _raw()
    del raw["path"]
    assert EventProcessor.process(raw) is None


def test_invalid_event_type_returns_none():
    assert EventProcessor.process(_raw(event_type="renamed")) is None


def test_non_dict_input_does_not_raise():
    # process() must never raise, even given garbage input.
    assert EventProcessor.process(None) is None
    assert EventProcessor.process({}) is None


def test_extension_extraction():
    event = EventProcessor.process(_raw(path="C:\\test\\invoice.EXE"))
    assert event is not None
    assert event.extension == ".exe"  # lowercased


def test_extension_extraction_no_extension():
    event = EventProcessor.process(_raw(path="C:\\test\\README"))
    assert event is not None
    assert event.extension == ""


def test_filename_extraction():
    event = EventProcessor.process(_raw(path="C:\\test\\invoice.exe"))
    assert event is not None
    assert event.file_name == "invoice.exe"


def test_parent_directory_extraction():
    event = EventProcessor.process(_raw(path="C:\\test\\invoice.exe"))
    assert event is not None
    assert event.parent_directory == "C:\\test"


def test_posix_path_is_also_handled():
    event = EventProcessor.process(_raw(path="/home/user/malware.sh"))
    assert event is not None
    assert event.file_name == "malware.sh"
    assert event.extension == ".sh"
    assert event.parent_directory == "/home/user"


def test_timestamp_preserved():
    event = EventProcessor.process(_raw(**{"timestamp": "2026-06-01T12:00:00+00:00"}))
    assert event is not None
    assert event.timestamp == "2026-06-01T12:00:00+00:00"


def test_file_size_populated_for_existing_file(tmp_path):
    real_file = tmp_path / "sample.txt"
    real_file.write_text("hello world")

    event = EventProcessor.process(
        _raw(event_type="created", path=str(real_file), is_directory=False)
    )
    assert event is not None
    assert event.file_size == len("hello world")


def test_file_size_none_for_nonexistent_file():
    event = EventProcessor.process(
        _raw(event_type="created", path="C:\\definitely\\not\\real.txt")
    )
    assert event is not None
    assert event.file_size is None


def test_identical_events_get_the_same_id():
    # Deterministic fingerprint: re-delivering the same event is a duplicate.
    e1 = EventProcessor.process(_raw())
    e2 = EventProcessor.process(_raw())
    assert e1.event_id == e2.event_id


def test_different_events_get_different_ids():
    e1 = EventProcessor.process(_raw())
    e2 = EventProcessor.process(_raw(event_type="deleted"))
    assert e1.event_id != e2.event_id


def test_to_dict_is_json_serializable_shape():
    event = EventProcessor.process(_raw())
    d = event.to_dict()
    for key in (
        "event_id",
        "event_type",
        "path",
        "timestamp",
        "is_directory",
        "destination_path",
        "file_name",
        "extension",
        "parent_directory",
        "file_size",
    ):
        assert key in d
