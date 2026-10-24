"""
test_phase10_persistence.py

Comprehensive test suite for Phase 10 Security Event Persistence.

Tests the SQLite persistence layer, repository CRUD operations,
GET endpoints, duplicate handling, filtering, and pagination.

All tests use an in-memory test database for isolation.
"""

import json
import pytest
from pathlib import Path
from typing import Any

from app.db.database import Database
from app.models.orchestration_result import OrchestrationResult
from app.models.security_analysis_result import SecurityAnalysisResult
from app.models.security_decision import SecurityDecision
from app.models.response_recommendation import ResponseRecommendation
from app.models.security_event_record import SecurityEventRecord
from app.repositories.security_event_repository import SecurityEventRepository
from app.services.security_orchestrator import SecurityOrchestrator


# ----------------------------------------------------------------------------
# Factory helpers: build models through their real create() constructors so
# tests stay valid when model fields (timestamps, ids) are added.
# ----------------------------------------------------------------------------


def make_orch(*, event_id, security_event, threat_score, threat_level,
              investigation_result=None, suspicion_score=0):
    return OrchestrationResult.create(
        event_id=event_id,
        security_event=security_event,
        investigation=investigation_result or {},
        analysis={},
        suspicion_score=suspicion_score,
        threat_score=threat_score,
        threat_level=threat_level,
        findings=[],
        reasons=[],
    )


def make_dec(*, event_id, threat_score, threat_level, decision,
             recommended_action, decision_reason, automated_action=False):
    return SecurityDecision.create(
        event_id=event_id,
        threat_score=threat_score,
        threat_level=threat_level,
        decision=decision,
        recommended_action=recommended_action,
        decision_reason=decision_reason,
    )


def make_rec(*, summary, explanation, evidence, recommended_actions,
             requires_human_review=False, confidence=0.5,
             event_id="test-event", threat_score=0, threat_level="LOW",
             decision_action="ALLOW", decision_recommendation="NONE"):
    return ResponseRecommendation.create(
        event_id=event_id,
        threat_score=threat_score,
        threat_level=threat_level,
        decision_action=decision_action,
        decision_recommendation=decision_recommendation,
        summary=summary,
        explanation=explanation,
        evidence=evidence,
        recommended_actions=recommended_actions,
        confidence=confidence,
        requires_human_review=requires_human_review,
    )


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(autouse=True)
def reset_database():
    """Reset database before and after each test."""
    Database.reset_for_testing()
    yield
    Database.reset_for_testing()


@pytest.fixture
def repository():
    """Create a fresh repository instance for each test."""
    return SecurityEventRepository()


@pytest.fixture
def sample_orchestration_result() -> OrchestrationResult:
    """Create a sample orchestration result for testing."""
    return make_orch(
        event_id="test-event-001",
        security_event={
            "event_type": "created",
            "path": "/test/file.txt",
            "timestamp": "2024-01-01T12:00:00Z",
            "is_directory": False,
            "file_name": "file.txt",
            "extension": ".txt",
            "parent_directory": "/test",
            "file_size": 1024,
        },
        investigation_result={"investigation_status": "clean"},
        suspicion_score=0,
        threat_score=15,
        threat_level="LOW",
    )


@pytest.fixture
def sample_security_decision() -> SecurityDecision:
    """Create a sample security decision for testing."""
    return make_dec(
        event_id="test-event-001",
        threat_score=15,
        threat_level="LOW",
        decision="ALLOW",
        recommended_action="NONE",
        automated_action=False,
        decision_reason="File appears benign",
    )


@pytest.fixture
def sample_response_recommendation() -> ResponseRecommendation:
    """Create a sample response recommendation for testing."""
    return make_rec(
        summary="Event is safe",
        explanation="File analysis indicates no threats",
        evidence=["file_type_benign", "size_normal", "no_suspicious_patterns"],
        recommended_actions=["monitor_directory"],
        requires_human_review=False,
        confidence=0.92,
    )


@pytest.fixture
def sample_analysis_result(
    sample_orchestration_result,
    sample_security_decision,
    sample_response_recommendation,
) -> SecurityAnalysisResult:
    """Create a sample analysis result for testing."""
    return SecurityAnalysisResult(
        orchestration_result=sample_orchestration_result,
        security_decision=sample_security_decision,
        response_recommendation=sample_response_recommendation,
    )


# ============================================================================
# SecurityEventRecord Tests
# ============================================================================


class TestSecurityEventRecord:
    """Tests for SecurityEventRecord model."""

    def test_from_analysis_result(self, sample_analysis_result):
        """Test creating a record from an analysis result."""
        record = SecurityEventRecord.from_analysis_result(sample_analysis_result)

        assert record.event_id == "test-event-001"
        assert record.event_type == "created"
        assert record.path == "/test/file.txt"
        assert record.threat_score == 15
        assert record.threat_level == "LOW"
        assert record.decision == "ALLOW"
        assert record.automated_action is False
        assert record.created_at != ""
        assert record.updated_at != ""

    def test_to_dict(self, sample_analysis_result):
        """Test converting record to dictionary."""
        record = SecurityEventRecord.from_analysis_result(sample_analysis_result)
        record.id = 1

        result_dict = record.to_dict()

        assert result_dict["id"] == 1
        assert result_dict["event_id"] == "test-event-001"
        assert result_dict["threat_level"] == "LOW"
        assert isinstance(result_dict["evidence"], list)
        assert isinstance(result_dict["recommended_actions"], list)

    def test_json_serialization_handling(self, sample_analysis_result):
        """Test that JSON fields are properly serialized/deserialized."""
        record = SecurityEventRecord.from_analysis_result(sample_analysis_result)

        # Evidence should be JSON string in record
        assert isinstance(record.evidence, str)
        evidence = json.loads(record.evidence)
        assert isinstance(evidence, list)
        assert "file_type_benign" in evidence

        # to_dict should deserialize
        result_dict = record.to_dict()
        assert isinstance(result_dict["evidence"], list)


# ============================================================================
# Repository CRUD Tests
# ============================================================================


class TestSecurityEventRepository:
    """Tests for SecurityEventRepository CRUD operations."""

    def test_create_new_record(self, repository, sample_analysis_result):
        """Test creating a new record."""
        record = repository.create(sample_analysis_result)

        assert record is not None
        assert record.id is not None
        assert record.event_id == "test-event-001"
        assert record.threat_level == "LOW"
        assert record.decision == "ALLOW"

    def test_create_duplicate_event_id_returns_existing(
        self, repository, sample_analysis_result
    ):
        """Test that duplicate event_id returns existing record."""
        # Create first record
        record1 = repository.create(sample_analysis_result)
        record1_id = record1.id

        # Create with same event_id (should return existing)
        record2 = repository.create(sample_analysis_result)

        # Should be same record
        assert record2.id == record1_id
        assert record2.event_id == record1.event_id

    def test_get_by_event_id_found(self, repository, sample_analysis_result):
        """Test retrieving a record by event_id."""
        repository.create(sample_analysis_result)

        record = repository.get_by_event_id("test-event-001")

        assert record is not None
        assert record.event_id == "test-event-001"
        assert record.threat_level == "LOW"

    def test_get_by_event_id_not_found(self, repository):
        """Test retrieving non-existent event_id returns None."""
        record = repository.get_by_event_id("nonexistent-event")
        assert record is None

    def test_list_all_records(self, repository):
        """Test listing all records without filters."""
        # Create multiple records
        orchestration = make_orch(
            event_id="event-001",
            security_event={"event_type": "created", "path": "/test/a.txt"},
            investigation_result={},
            threat_score=15,
            threat_level="LOW",
        )
        decision = make_dec(
            event_id="event-001",
            threat_score=15,
            threat_level="LOW",
            decision="ALLOW",
            recommended_action="NONE",
            automated_action=False,
            decision_reason="Test",
        )
        recommendation = make_rec(
            summary="Test", explanation="Test", evidence=[], recommended_actions=[]
        )

        for i in range(3):
            orch = make_orch(
                event_id=f"event-{i:03d}",
                security_event={"event_type": "created", "path": f"/test/{i}.txt"},
                investigation_result={},
                threat_score=15 + (i * 10),
                threat_level=["LOW", "MEDIUM", "HIGH"][i],
            )
            dec = make_dec(
                event_id=f"event-{i:03d}",
                threat_score=15 + (i * 10),
                threat_level=["LOW", "MEDIUM", "HIGH"][i],
                decision=["ALLOW", "ALERT", "ESCALATE"][i],
                recommended_action="NONE",
                automated_action=False,
                decision_reason="Test",
            )
            result = SecurityAnalysisResult(
                orchestration_result=orch,
                security_decision=dec,
                response_recommendation=recommendation,
            )
            repository.create(result)

        records = repository.list()

        assert len(records) == 3
        # Should be ordered by created_at DESC
        assert records[0].event_id == "event-002"

    def test_list_with_pagination(self, repository):
        """Test pagination with skip and limit."""
        # Create 10 records
        for i in range(10):
            orch = make_orch(
                event_id=f"event-{i:03d}",
                security_event={"event_type": "created"},
                investigation_result={},
                threat_score=10,
                threat_level="LOW",
            )
            dec = make_dec(
                event_id=f"event-{i:03d}",
                threat_score=10,
                threat_level="LOW",
                decision="ALLOW",
                recommended_action="NONE",
                automated_action=False,
                decision_reason="Test",
            )
            result = SecurityAnalysisResult(
                orchestration_result=orch,
                security_decision=dec,
                response_recommendation=make_rec(
                    summary="Test",
                    explanation="Test",
                    evidence=[],
                    recommended_actions=[],
                ),
            )
            repository.create(result)

        # Get first 3 records
        page1 = repository.list(skip=0, limit=3)
        assert len(page1) == 3

        # Get next 3 records
        page2 = repository.list(skip=3, limit=3)
        assert len(page2) == 3

        # Verify no overlap
        page1_ids = {r.event_id for r in page1}
        page2_ids = {r.event_id for r in page2}
        assert page1_ids.isdisjoint(page2_ids)

    def test_list_filter_by_threat_level(self, repository):
        """Test filtering by threat level."""
        for i, level in enumerate(["LOW", "MEDIUM", "HIGH"]):
            orch = make_orch(
                event_id=f"event-{i}",
                security_event={"event_type": "created"},
                investigation_result={},
                threat_score=10 + (i * 20),
                threat_level=level,
            )
            dec = make_dec(
                event_id=f"event-{i}",
                threat_score=10 + (i * 20),
                threat_level=level,
                decision="ALLOW",
                recommended_action="NONE",
                automated_action=False,
                decision_reason="Test",
            )
            result = SecurityAnalysisResult(
                orchestration_result=orch,
                security_decision=dec,
                response_recommendation=make_rec(
                    summary="Test",
                    explanation="Test",
                    evidence=[],
                    recommended_actions=[],
                ),
            )
            repository.create(result)

        # Filter by threat level
        high_events = repository.list(threat_level="HIGH")
        assert len(high_events) == 1
        assert high_events[0].threat_level == "HIGH"

    def test_list_filter_by_decision(self, repository):
        """Test filtering by decision."""
        decisions = ["ALLOW", "ALERT", "ESCALATE"]

        for i, dec in enumerate(decisions):
            orch = make_orch(
                event_id=f"event-{i}",
                security_event={"event_type": "created"},
                investigation_result={},
                threat_score=10,
                threat_level="MEDIUM",
            )
            decision = make_dec(
                event_id=f"event-{i}",
                threat_score=10,
                threat_level="MEDIUM",
                decision=dec,
                recommended_action="NONE",
                automated_action=False,
                decision_reason="Test",
            )
            result = SecurityAnalysisResult(
                orchestration_result=orch,
                security_decision=decision,
                response_recommendation=make_rec(
                    summary="Test",
                    explanation="Test",
                    evidence=[],
                    recommended_actions=[],
                ),
            )
            repository.create(result)

        # Filter by decision
        alert_events = repository.list(decision="ALERT")
        assert len(alert_events) == 1
        assert alert_events[0].decision == "ALERT"

    def test_list_filter_by_event_type(self, repository):
        """Test filtering by event type."""
        event_types = ["created", "modified", "deleted"]

        for i, event_type in enumerate(event_types):
            orch = make_orch(
                event_id=f"event-{i}",
                security_event={"event_type": event_type, "path": "/test/file"},
                investigation_result={},
                threat_score=10,
                threat_level="LOW",
            )
            decision = make_dec(
                event_id=f"event-{i}",
                threat_score=10,
                threat_level="LOW",
                decision="ALLOW",
                recommended_action="NONE",
                automated_action=False,
                decision_reason="Test",
            )
            result = SecurityAnalysisResult(
                orchestration_result=orch,
                security_decision=decision,
                response_recommendation=make_rec(
                    summary="Test",
                    explanation="Test",
                    evidence=[],
                    recommended_actions=[],
                ),
            )
            repository.create(result)

        # Filter by event type
        deleted_events = repository.list(event_type="deleted")
        assert len(deleted_events) == 1
        assert deleted_events[0].event_type == "deleted"

    def test_list_combined_filters(self, repository):
        """Test combining multiple filters."""
        orch = make_orch(
            event_id="event-1",
            security_event={"event_type": "created", "path": "/test/file"},
            investigation_result={},
            threat_score=50,
            threat_level="MEDIUM",
        )
        decision = make_dec(
            event_id="event-1",
            threat_score=50,
            threat_level="MEDIUM",
            decision="ALERT",
            recommended_action="MONITOR",
            automated_action=False,
            decision_reason="Test",
        )
        result = SecurityAnalysisResult(
            orchestration_result=orch,
            security_decision=decision,
            response_recommendation=make_rec(
                summary="Test",
                explanation="Test",
                evidence=[],
                recommended_actions=[],
            ),
        )
        repository.create(result)

        # Filter by multiple criteria
        records = repository.list(
            threat_level="MEDIUM", decision="ALERT", event_type="created"
        )
        assert len(records) == 1
        assert records[0].threat_level == "MEDIUM"
        assert records[0].decision == "ALERT"
        assert records[0].event_type == "created"

    def test_count_all(self, repository):
        """Test counting all records."""
        # Create 5 records
        for i in range(5):
            orch = make_orch(
                event_id=f"event-{i}",
                security_event={"event_type": "created"},
                investigation_result={},
                threat_score=10,
                threat_level="LOW",
            )
            decision = make_dec(
                event_id=f"event-{i}",
                threat_score=10,
                threat_level="LOW",
                decision="ALLOW",
                recommended_action="NONE",
                automated_action=False,
                decision_reason="Test",
            )
            result = SecurityAnalysisResult(
                orchestration_result=orch,
                security_decision=decision,
                response_recommendation=make_rec(
                    summary="Test",
                    explanation="Test",
                    evidence=[],
                    recommended_actions=[],
                ),
            )
            repository.create(result)

        count = repository.count()
        assert count == 5

    def test_count_with_filters(self, repository):
        """Test counting with filters."""
        # Create records with different threat levels
        for i in range(3):
            orch = make_orch(
                event_id=f"event-{i}",
                security_event={"event_type": "created"},
                investigation_result={},
                threat_score=10 + (i * 20),
                threat_level=["LOW", "MEDIUM", "HIGH"][i],
            )
            decision = make_dec(
                event_id=f"event-{i}",
                threat_score=10 + (i * 20),
                threat_level=["LOW", "MEDIUM", "HIGH"][i],
                decision="ALLOW",
                recommended_action="NONE",
                automated_action=False,
                decision_reason="Test",
            )
            result = SecurityAnalysisResult(
                orchestration_result=orch,
                security_decision=decision,
                response_recommendation=make_rec(
                    summary="Test",
                    explanation="Test",
                    evidence=[],
                    recommended_actions=[],
                ),
            )
            repository.create(result)

        # Count with filter
        high_count = repository.count(threat_level="HIGH")
        assert high_count == 1


# ============================================================================
# Integration Tests: Orchestrator with Persistence
# ============================================================================


class TestOrchestratorPersistence:
    """Tests for SecurityOrchestrator with persistence."""

    def test_orchestrator_persists_analysis(self):
        """Test that orchestrator automatically persists analyzed events."""
        Database.reset_for_testing()
        orchestrator = SecurityOrchestrator()
        repository = SecurityEventRepository()

        # Create a valid test event
        event = {
            "event_type": "created",
            "path": "/test/file.txt",
            "timestamp": "2024-01-01T12:00:00Z",
            "is_directory": False,
        }

        # Process event
        result = orchestrator.process(event)
        assert result is not None

        # Verify it was persisted
        persisted = repository.get_by_event_id(result.event_id)
        assert persisted is not None
        assert persisted.event_id == result.event_id
        assert persisted.threat_level == result.threat_level
        assert persisted.decision == result.security_decision.decision

    def test_orchestrator_response_unchanged(self):
        """Test that persistence doesn't change API response."""
        Database.reset_for_testing()
        orchestrator = SecurityOrchestrator()

        event = {
            "event_type": "created",
            "path": "/test/file.txt",
            "timestamp": "2024-01-01T12:00:00Z",
            "is_directory": False,
        }

        result = orchestrator.process(event)
        response = result.to_dict()

        # Verify response structure is unchanged (Phase 8 backward compatibility)
        assert "event_id" in response
        assert "threat_score" in response
        assert "threat_level" in response
        assert "decision" in response
        assert "response_recommendation" in response
        assert "summary" in response["response_recommendation"]
        assert "explanation" in response["response_recommendation"]

    def test_duplicate_events_not_duplicated_in_db(self):
        """Test that processing same event twice doesn't create duplicates."""
        Database.reset_for_testing()
        orchestrator = SecurityOrchestrator()
        repository = SecurityEventRepository()

        event = {
            "event_type": "created",
            "path": "/test/file.txt",
            "timestamp": "2024-01-01T12:00:00Z",
            "is_directory": False,
        }

        # Process same event twice
        result1 = orchestrator.process(event)
        result2 = orchestrator.process(event)

        # Both should return valid results
        assert result1 is not None
        assert result2 is not None

        # Both should have same event_id
        assert result1.event_id == result2.event_id

        # Database should only have 1 record
        all_records = repository.get_all()
        assert len(all_records) == 1


# ============================================================================
# API Endpoint Tests (with TestClient)
# ============================================================================


class TestSecurityEndpoints:
    """Tests for security router GET endpoints."""

    def test_get_events_endpoint(self):
        """Test GET /api/security/events endpoint."""
        from fastapi.testclient import TestClient
        from app.main import app

        Database.reset_for_testing()
        client = TestClient(app)

        # Create some events
        event = {
            "event_type": "created",
            "path": "/test/file.txt",
            "timestamp": "2024-01-01T12:00:00Z",
            "is_directory": False,
        }

        response = client.post("/api/security/analyze", json=event)
        assert response.status_code == 200

        # List events
        list_response = client.get("/api/security/events")
        assert list_response.status_code == 200

        data = list_response.json()
        assert "events" in data
        assert "total" in data
        assert len(data["events"]) > 0

    def test_get_event_by_id_endpoint(self):
        """Test GET /api/security/events/{event_id} endpoint."""
        from fastapi.testclient import TestClient
        from app.main import app

        Database.reset_for_testing()
        client = TestClient(app)

        # Create an event
        event = {
            "event_type": "created",
            "path": "/test/file.txt",
            "timestamp": "2024-01-01T12:00:00Z",
            "is_directory": False,
        }

        response = client.post("/api/security/analyze", json=event)
        assert response.status_code == 200

        event_id = response.json()["event_id"]

        # Get the event
        get_response = client.get(f"/api/security/events/{event_id}")
        assert get_response.status_code == 200

        data = get_response.json()
        assert data["event_id"] == event_id

    def test_get_event_not_found(self):
        """Test GET with non-existent event_id."""
        from fastapi.testclient import TestClient
        from app.main import app

        Database.reset_for_testing()
        client = TestClient(app)

        # Try to get non-existent event
        response = client.get("/api/security/events/nonexistent")
        assert response.status_code == 404

    def test_get_events_with_filters(self):
        """Test GET /api/security/events with filter parameters."""
        from fastapi.testclient import TestClient
        from app.main import app

        Database.reset_for_testing()
        client = TestClient(app)

        # Create events
        for i in range(3):
            event = {
                "event_type": "created",
                "path": f"/test/file{i}.txt",
                "timestamp": "2024-01-01T12:00:00Z",
                "is_directory": False,
            }
            client.post("/api/security/analyze", json=event)

        # List with filter (this may or may not return events based on threat levels)
        response = client.get("/api/security/events?threat_level=LOW")
        assert response.status_code == 200

        data = response.json()
        assert "events" in data
        assert "total" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
