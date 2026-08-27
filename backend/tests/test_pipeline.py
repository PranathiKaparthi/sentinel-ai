"""
test_pipeline.py

Tests for the SentinelAI Phase 3 ProcessingPipeline.

Pipeline flow:

    Raw filesystem event
            ↓
    EventProcessor
            ↓
    SecurityEvent
            ↓
    Investigator
            ↓
    InvestigationResult
            ↓
    Analyzer
            ↓
    AnalysisResult
            ↓
    PipelineResult
"""

from __future__ import annotations

import json

from app.services.pipeline import ProcessingPipeline


def make_event(
    path: str,
    event_type: str = "created",
    is_directory: bool = False,
    destination_path: str | None = None,
) -> dict:
    """
    Create a valid raw filesystem event for testing.
    """

    return {
        "event_id": "test-event-id",
        "event_type": event_type,
        "path": path,
        "timestamp": "2026-08-27T12:00:00",
        "is_directory": is_directory,
        "destination_path": destination_path,
    }


# ----------------------------------------------------------------------
# CREATED
# ----------------------------------------------------------------------

def test_pipeline_processes_created_file(tmp_path):
    """
    A created file should successfully pass through
    the complete Phase 3 pipeline.
    """

    file_path = tmp_path / "created.txt"

    file_path.write_text(
        "SentinelAI created file test",
        encoding="utf-8",
    )

    raw_event = make_event(
        path=str(file_path),
        event_type="created",
    )

    result = ProcessingPipeline.process(raw_event)

    assert result is not None

    assert result.security_event.event_type == "created"
    assert result.security_event.path == str(file_path)

    assert result.investigation is not None
    assert result.analysis is not None


# ----------------------------------------------------------------------
# MODIFIED
# ----------------------------------------------------------------------

def test_pipeline_processes_modified_file(tmp_path):
    """
    A modified file should successfully pass through
    the complete Phase 3 pipeline.
    """

    file_path = tmp_path / "modified.txt"

    file_path.write_text(
        "Original content",
        encoding="utf-8",
    )

    raw_event = make_event(
        path=str(file_path),
        event_type="modified",
    )

    result = ProcessingPipeline.process(raw_event)

    assert result is not None

    assert result.security_event.event_type == "modified"
    assert result.security_event.path == str(file_path)

    assert result.investigation is not None
    assert result.analysis is not None


# ----------------------------------------------------------------------
# DELETED
# ----------------------------------------------------------------------

def test_pipeline_processes_deleted_file(tmp_path):
    """
    Deleted files should still be processed safely.

    The file no longer exists when the pipeline receives
    the event.
    """

    file_path = tmp_path / "deleted.txt"

    file_path.write_text(
        "This file will be deleted",
        encoding="utf-8",
    )

    raw_event = make_event(
        path=str(file_path),
        event_type="deleted",
    )

    file_path.unlink()

    assert not file_path.exists()

    result = ProcessingPipeline.process(raw_event)

    assert result is not None

    assert result.security_event.event_type == "deleted"
    assert result.security_event.path == str(file_path)

    assert result.investigation is not None
    assert result.analysis is not None


# ----------------------------------------------------------------------
# DIRECTORY
# ----------------------------------------------------------------------

def test_pipeline_processes_directory(tmp_path):
    """
    Directory events should be handled safely.
    """

    directory = tmp_path / "test_directory"

    directory.mkdir()

    raw_event = make_event(
        path=str(directory),
        event_type="created",
        is_directory=True,
    )

    result = ProcessingPipeline.process(raw_event)

    assert result is not None

    assert result.security_event.is_directory is True
    assert result.security_event.path == str(directory)

    assert result.investigation is not None
    assert result.analysis is not None


# ----------------------------------------------------------------------
# INVALID EVENT
# ----------------------------------------------------------------------

def test_pipeline_rejects_invalid_event():
    """
    Invalid filesystem events should be rejected safely.

    ProcessingPipeline.process() must not raise an exception.
    """

    raw_event = {
        "event_type": "invalid",
        "path": "C:\\invalid.txt",
        "timestamp": "2026-08-27T12:00:00",
        "is_directory": False,
    }

    result = ProcessingPipeline.process(raw_event)

    assert result is None


# ----------------------------------------------------------------------
# READ-ONLY BEHAVIOUR
# ----------------------------------------------------------------------

def test_pipeline_does_not_modify_file(tmp_path):
    """
    The Phase 3 pipeline must be completely read-only.

    It must not modify the file contents.
    """

    file_path = tmp_path / "readonly.txt"

    original_content = (
        "DO NOT MODIFY THIS FILE"
    )

    file_path.write_text(
        original_content,
        encoding="utf-8",
    )

    raw_event = make_event(
        path=str(file_path),
        event_type="modified",
    )

    result = ProcessingPipeline.process(raw_event)

    assert result is not None

    assert file_path.exists()

    assert file_path.read_text(
        encoding="utf-8"
    ) == original_content


# ----------------------------------------------------------------------
# SERIALIZATION
# ----------------------------------------------------------------------

def test_pipeline_result_is_serializable(tmp_path):
    """
    PipelineResult.to_dict() should return a JSON-compatible
    dictionary.
    """

    file_path = tmp_path / "serializable.txt"

    file_path.write_text(
        "serialization test",
        encoding="utf-8",
    )

    raw_event = make_event(
        path=str(file_path),
        event_type="created",
    )

    result = ProcessingPipeline.process(raw_event)

    assert result is not None

    data = result.to_dict()

    assert isinstance(data, dict)

    assert "security_event" in data
    assert "investigation" in data
    assert "analysis" in data

    assert isinstance(
        data["security_event"],
        dict,
    )

    assert isinstance(
        data["investigation"],
        dict,
    )

    assert isinstance(
        data["analysis"],
        dict,
    )

    # Confirm that the complete result can actually
    # be converted to JSON.
    json_string = json.dumps(data)

    assert isinstance(
        json_string,
        str,
    )