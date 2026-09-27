"""
database.py

Database connection and initialization for SentinelAI Phase 10.

Uses SQLite for local, file-based security event persistence.
Provides connection management and schema initialization.

Architecture:
- Single SQLite database file
- Connection pooling via sqlite3
- Auto-initialization of schema on startup
- Transaction support for consistency
"""

import sqlite3
import os
from pathlib import Path
from typing import Optional

from app.utils.logger import get_logger

logger = get_logger("SentinelAI.Database")

# Database file location - uses a relative path similar to test_environment
DB_FILE = Path(__file__).parent.parent.parent / "security_events.db"


class Database:
    """
    SQLite database connection and schema manager.

    Provides a singleton connection to the security events database
    and handles schema initialization.
    """

    _instance: Optional["Database"] = None
    _connection: Optional[sqlite3.Connection] = None

    def __new__(cls) -> "Database":
        """Implement singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize database (connect and create schema if needed)."""
        if self._connection is None:
            self._connect()
            self._initialize_schema()

    @classmethod
    def get_connection(cls) -> sqlite3.Connection:
        """
        Get or create the database connection.

        Returns:
            sqlite3.Connection to the security events database.
        """
        instance = cls()
        if instance._connection is None:
            instance._connect()
        return instance._connection

    def _connect(self) -> None:
        """Establish SQLite connection."""
        try:
            # Enable row factory for dict-like access
            self._connection = sqlite3.connect(str(DB_FILE), check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
            # Enable foreign keys
            self._connection.execute("PRAGMA foreign_keys = ON")
            logger.info(f"Database connection established: {DB_FILE}")
        except sqlite3.Error as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def _initialize_schema(self) -> None:
        """Create database schema if it doesn't exist."""
        if self._connection is None:
            return

        schema_sql = """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            path TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            is_directory BOOLEAN NOT NULL DEFAULT 0,
            destination_path TEXT,
            file_name TEXT,
            extension TEXT,
            parent_directory TEXT,
            file_size INTEGER,
            suspicion_score INTEGER DEFAULT 0,
            threat_score INTEGER NOT NULL,
            threat_level TEXT NOT NULL,
            decision TEXT NOT NULL,
            recommended_action TEXT,
            automated_action BOOLEAN NOT NULL DEFAULT 0,
            requires_human_review BOOLEAN NOT NULL DEFAULT 0,
            confidence REAL NOT NULL DEFAULT 0.5,
            decision_reason TEXT,
            summary TEXT,
            explanation TEXT,
            evidence TEXT,
            recommended_actions TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            CONSTRAINT valid_threat_level CHECK (threat_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            CONSTRAINT valid_decision CHECK (decision IN ('ALLOW', 'ALERT', 'ESCALATE'))
        );
        
        CREATE INDEX IF NOT EXISTS idx_event_id ON security_events(event_id);
        CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_threat_level ON security_events(threat_level);
        CREATE INDEX IF NOT EXISTS idx_decision ON security_events(decision);
        CREATE INDEX IF NOT EXISTS idx_event_type ON security_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_created_at ON security_events(created_at);
        """

        try:
            cursor = self._connection.cursor()
            cursor.executescript(schema_sql)
            self._connection.commit()
            logger.info("Database schema initialized successfully")
        except sqlite3.Error as e:
            logger.error(f"Schema initialization failed: {e}")
            raise

    def close(self) -> None:
        """Close the database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None
            logger.info("Database connection closed")

    @classmethod
    def reset_for_testing(cls) -> None:
        """
        Reset database for testing (drops and recreates schema).

        WARNING: Only use in test environment.
        """
        instance = cls()
        if instance._connection:
            try:
                cursor = instance._connection.cursor()
                cursor.execute("DROP TABLE IF EXISTS security_events")
                instance._connection.commit()
                logger.warning("Database schema dropped (testing only)")
                instance._initialize_schema()
            except sqlite3.Error as e:
                logger.error(f"Schema reset failed: {e}")
                raise
