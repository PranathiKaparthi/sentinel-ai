"""
conftest.py

Shared pytest setup. Runs before any test module imports the app.

Points SENTINEL_DB_PATH at a throwaway file in the system temp directory, so
the test suite never reads or writes the real security_events.db.
"""

import os
import tempfile
from pathlib import Path

_TEST_DB = Path(tempfile.gettempdir()) / "sentinel_ai_test_events.db"
if _TEST_DB.exists():
    _TEST_DB.unlink()
os.environ["SENTINEL_DB_PATH"] = str(_TEST_DB)
