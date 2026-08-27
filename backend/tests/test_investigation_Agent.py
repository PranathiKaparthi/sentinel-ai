from app.models.investigation_result import InvestigationResult


def test_investigation_result_creation():
    result = InvestigationResult.create(
        event_id="test-event-123",
        event_type="created",
        path=r"C:\test\sample.exe",
        exists=True,
        is_directory=False,
        current_file_size=1024,
        file_name="sample.exe",
        extension=".exe",
        parent_directory=r"C:\test",
    )

    assert result.event_id == "test-event-123"
    assert result.event_type == "created"
    assert result.path == r"C:\test\sample.exe"
    assert result.exists is True
    assert result.is_directory is False
    assert result.current_file_size == 1024
    assert result.file_name == "sample.exe"
    assert result.extension == ".exe"
    assert result.parent_directory == r"C:\test"
    assert result.investigation_timestamp


def test_investigation_result_to_dict():
    result = InvestigationResult.create(
        event_id="abc",
        event_type="modified",
        path=r"C:\test\file.txt",
        exists=True,
        is_directory=False,
        current_file_size=50,
        file_name="file.txt",
        extension=".txt",
        parent_directory=r"C:\test",
    )

    data = result.to_dict()

    assert isinstance(data, dict)
    assert data["event_id"] == "abc"
    assert data["event_type"] == "modified"
    assert data["path"] == r"C:\test\file.txt"
    assert data["exists"] is True
    assert data["is_directory"] is False
    assert data["current_file_size"] == 50
    assert data["file_name"] == "file.txt"
    assert data["extension"] == ".txt"
    assert data["parent_directory"] == r"C:\test"
    assert "investigation_timestamp" in data


def test_deleted_file_can_have_no_current_size():
    result = InvestigationResult.create(
        event_id="deleted-1",
        event_type="deleted",
        path=r"C:\test\deleted.exe",
        exists=False,
        is_directory=False,
        current_file_size=None,
        file_name="deleted.exe",
        extension=".exe",
        parent_directory=r"C:\test",
    )

    assert result.exists is False
    assert result.current_file_size is None


def test_directory_can_have_no_file_size():
    result = InvestigationResult.create(
        event_id="directory-1",
        event_type="created",
        path=r"C:\test\folder",
        exists=True,
        is_directory=True,
        current_file_size=None,
        file_name="folder",
        extension="",
        parent_directory=r"C:\test",
    )

    assert result.is_directory is True
    assert result.current_file_size is None