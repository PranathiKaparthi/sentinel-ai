"""
security_event_repository.py

SecurityEventRepository for SentinelAI Phase 10 persistence.

Repository pattern implementation for security event persistence.
Handles all database CRUD operations with safety constraints:
- Duplicate event_id handling (safe return of existing)
- Pagination support
- Filtering by threat_level, decision, event_type
- Immutable records (updates only add new entries)
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional

from app.db.database import Database
from app.models.security_event_record import SecurityEventRecord
from app.models.security_analysis_result import SecurityAnalysisResult
from app.utils.logger import get_logger

logger = get_logger("SentinelAI.SecurityEventRepository")

# Decisions that count as alerts (anything that needs a human to look at it).
ALERT_DECISIONS = ("ALERT", "ESCALATE")

# One SQLite connection is shared by API threads and the live-monitoring
# thread, so inserts are serialised with a module-level lock.
_write_lock = threading.Lock()


class SecurityEventRepository:
    """
    Repository for persisting and retrieving security event records.

    Provides safe CRUD operations with duplicate handling and filtering.
    """

    def __init__(self):
        """Initialize repository with database connection."""
        self._db = Database()

    def create(
        self, analysis_result: SecurityAnalysisResult
    ) -> Optional[SecurityEventRecord]:
        """
        Persist a security analysis result to the database.

        Handles duplicate event_id safely by returning the existing record
        instead of creating a duplicate.

        Args:
            analysis_result: The SecurityAnalysisResult to persist

        Returns:
            SecurityEventRecord if successful, None if persistence failed
        """
        try:
            record = SecurityEventRecord.from_analysis_result(analysis_result)

            # Check for existing event_id
            existing = self.get_by_event_id(record.event_id)
            if existing:
                logger.info(
                    f"Event {record.event_id} already persisted; returning existing record"
                )
                return existing

            # Insert new record
            conn = Database.get_connection()
            with _write_lock:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    INSERT INTO security_events (
                        event_id, event_type, path, timestamp, is_directory,
                        destination_path, file_name, extension, parent_directory,
                        file_size, suspicion_score, threat_score, threat_level,
                        decision, recommended_action, automated_action,
                        requires_human_review, confidence, decision_reason,
                        summary, explanation, evidence, recommended_actions,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.event_id,
                        record.event_type,
                        record.path,
                        record.timestamp,
                        record.is_directory,
                        record.destination_path,
                        record.file_name,
                        record.extension,
                        record.parent_directory,
                        record.file_size,
                        record.suspicion_score,
                        record.threat_score,
                        record.threat_level,
                        record.decision,
                        record.recommended_action,
                        record.automated_action,
                        record.requires_human_review,
                        record.confidence,
                        record.decision_reason,
                        record.summary,
                        record.explanation,
                        record.evidence,
                        record.recommended_actions,
                        record.created_at,
                        record.updated_at,
                    ),
                )

                conn.commit()

            # Return the persisted record with id
            record.id = cursor.lastrowid
            logger.info(f"Event {record.event_id} persisted successfully (id={record.id})")
            return record

        except sqlite3.IntegrityError as e:
            logger.warning(f"Duplicate event_id {analysis_result.event_id}: {e}")
            # Return existing record on duplicate
            return self.get_by_event_id(analysis_result.event_id)
        except Exception:
            logger.exception(
                f"Failed to persist event {analysis_result.event_id}"
            )
            return None

    def get_by_event_id(self, event_id: str) -> Optional[SecurityEventRecord]:
        """
        Retrieve a security event record by event_id.

        Args:
            event_id: The unique event identifier

        Returns:
            SecurityEventRecord if found, None otherwise
        """
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM security_events WHERE event_id = ? LIMIT 1",
                (event_id,),
            )
            row = cursor.fetchone()

            if row is None:
                return None

            return self._row_to_record(row)

        except Exception:
            logger.exception(f"Failed to retrieve event {event_id}")
            return None

    def list(
        self,
        skip: int = 0,
        limit: int = 100,
        threat_level: Optional[str] = None,
        decision: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> list[SecurityEventRecord]:
        """
        List security event records with optional filtering and pagination.

        Args:
            skip: Number of records to skip (for pagination)
            limit: Maximum number of records to return
            threat_level: Filter by threat level (LOW, MEDIUM, HIGH, CRITICAL)
            decision: Filter by decision (ALLOW, ALERT, ESCALATE)
            event_type: Filter by event type (created, modified, deleted, moved)

        Returns:
            List of SecurityEventRecord matching filters, sorted by created_at DESC
        """
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()

            # Build query with optional filters
            query = "SELECT * FROM security_events WHERE 1=1"
            params = []

            if threat_level:
                query += " AND threat_level = ?"
                params.append(threat_level.upper())

            if decision:
                query += " AND decision = ?"
                params.append(decision.upper())

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type.lower())

            # Sort by created_at DESC and apply pagination
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, skip])

            cursor.execute(query, params)
            rows = cursor.fetchall()

            return [self._row_to_record(row) for row in rows]

        except Exception:
            logger.exception("Failed to list security events")
            return []

    def get_all(self) -> list[SecurityEventRecord]:
        """
        Get all security event records (for testing).

        Returns:
            List of all SecurityEventRecord in creation order
        """
        return self.list(skip=0, limit=999999)

    def count(
        self,
        threat_level: Optional[str] = None,
        decision: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> int:
        """
        Count security event records with optional filtering.

        Args:
            threat_level: Filter by threat level
            decision: Filter by decision
            event_type: Filter by event type

        Returns:
            Count of records matching filters
        """
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()

            query = "SELECT COUNT(*) FROM security_events WHERE 1=1"
            params = []

            if threat_level:
                query += " AND threat_level = ?"
                params.append(threat_level.upper())

            if decision:
                query += " AND decision = ?"
                params.append(decision.upper())

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type.lower())

            cursor.execute(query, params)
            result = cursor.fetchone()
            return result[0] if result else 0

        except Exception:
            logger.exception("Failed to count security events")
            return 0

    def list_alerts(self, skip: int = 0, limit: int = 100) -> list[SecurityEventRecord]:
        """
        List events whose decision is ALERT or ESCALATE, newest first.

        These are the events that need human attention.
        """
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM security_events
                WHERE decision IN (?, ?)
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (*ALERT_DECISIONS, limit, skip),
            )
            return [self._row_to_record(row) for row in cursor.fetchall()]
        except Exception:
            logger.exception("Failed to list alerts")
            return []

    def count_alerts(self) -> int:
        """Count events whose decision is ALERT or ESCALATE."""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM security_events WHERE decision IN (?, ?)",
                ALERT_DECISIONS,
            )
            return cursor.fetchone()[0]
        except Exception:
            logger.exception("Failed to count alerts")
            return 0

    def stats(self) -> dict:
        """
        Summary counts for a dashboard, computed with SQL GROUP BY.

        Returns total events, counts per threat level, counts per decision,
        and the average threat score.
        """
        by_level = {lvl: 0 for lvl in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
        by_decision = {d: 0 for d in ("ALLOW", "ALERT", "ESCALATE")}
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT COUNT(*), COALESCE(AVG(threat_score), 0) FROM security_events"
            )
            total, avg_score = cursor.fetchone()

            cursor.execute(
                "SELECT threat_level, COUNT(*) FROM security_events GROUP BY threat_level"
            )
            by_level.update({row[0]: row[1] for row in cursor.fetchall()})

            cursor.execute(
                "SELECT decision, COUNT(*) FROM security_events GROUP BY decision"
            )
            by_decision.update({row[0]: row[1] for row in cursor.fetchall()})

            return {
                "total_events": total,
                "average_threat_score": round(float(avg_score), 1),
                "by_threat_level": by_level,
                "by_decision": by_decision,
            }
        except Exception:
            logger.exception("Failed to compute statistics")
            return {
                "total_events": 0,
                "average_threat_score": 0.0,
                "by_threat_level": by_level,
                "by_decision": by_decision,
            }

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> SecurityEventRecord:
        """Convert a database row to a SecurityEventRecord."""
        return SecurityEventRecord(
            id=row["id"],
            event_id=row["event_id"],
            event_type=row["event_type"],
            path=row["path"],
            timestamp=row["timestamp"],
            is_directory=bool(row["is_directory"]),
            destination_path=row["destination_path"],
            file_name=row["file_name"],
            extension=row["extension"],
            parent_directory=row["parent_directory"],
            file_size=row["file_size"],
            suspicion_score=row["suspicion_score"],
            threat_score=row["threat_score"],
            threat_level=row["threat_level"],
            decision=row["decision"],
            recommended_action=row["recommended_action"],
            automated_action=bool(row["automated_action"]),
            requires_human_review=bool(row["requires_human_review"]),
            confidence=row["confidence"],
            decision_reason=row["decision_reason"],
            summary=row["summary"],
            explanation=row["explanation"],
            evidence=row["evidence"] or "",
            recommended_actions=row["recommended_actions"] or "",
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
