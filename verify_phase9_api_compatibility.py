"""
verify_phase9_api_compatibility.py

Quick verification that Phase 9 API response matches Phase 8 structure exactly.

This script tests the /api/security/analyze endpoint and verifies that
the JSON response contains all expected fields in the correct structure.
"""

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# Get test file path
test_file = Path(__file__).parent.parent / "test_environment" / "phase8_real_test.txt"
test_file_str = str(test_file)

# Create test event
test_event = {
    "event_id": "phase9-compatibility-test",
    "event_type": "modified",
    "path": test_file_str,
    "timestamp": "2026-09-01T00:00:00+00:00",
    "is_directory": False,
    "destination_path": None,
}

# Test the endpoint
print("Testing POST /api/security/analyze...")
response = client.post("/api/security/analyze", json=test_event)

if response.status_code != 200:
    print(f"❌ FAILED: Expected status 200, got {response.status_code}")
    print(f"Response: {response.text}")
    sys.exit(1)

result = response.json()

# Verify top-level fields (OrchestrationResult)
required_top_level = [
    "event_id",
    "threat_score",
    "threat_level",
    "suspicion_score",
    "findings",
    "reasons",
    "security_event",
    "investigation",
    "analysis",
    "processing_timestamp",
    "decision",
    "response_recommendation",
]

print("\nVerifying top-level structure...")
for field in required_top_level:
    if field not in result:
        print(f"❌ FAILED: Missing top-level field: {field}")
        sys.exit(1)
    print(f"  ✓ {field}")

# Verify decision structure (Phase 7)
decision = result.get("decision", {})
required_decision_fields = [
    "event_id",
    "threat_score",
    "threat_level",
    "decision",
    "recommended_action",
    "automated_action",
    "decision_reason",
    "decision_timestamp",
]

print("\nVerifying decision structure...")
for field in required_decision_fields:
    if field not in decision:
        print(f"❌ FAILED: Missing decision field: {field}")
        sys.exit(1)
    print(f"  ✓ decision.{field}")

# Verify response_recommendation structure (Phase 8)
recommendation = result.get("response_recommendation", {})
required_recommendation_fields = [
    "event_id",
    "threat_score",
    "threat_level",
    "decision_action",
    "decision_recommendation",
    "summary",
    "explanation",
    "evidence",
    "recommended_actions",
    "confidence",
    "automated_action",
    "requires_human_review",
    "created_at",
]

print("\nVerifying response_recommendation structure...")
for field in required_recommendation_fields:
    if field not in recommendation:
        print(f"❌ FAILED: Missing recommendation field: {field}")
        sys.exit(1)
    print(f"  ✓ response_recommendation.{field}")

# Verify safety constraints
print("\nVerifying safety constraints...")
if decision.get("automated_action") != False:
    print("❌ FAILED: decision.automated_action is not False")
    sys.exit(1)
print("  ✓ decision.automated_action is False")

if recommendation.get("automated_action") != False:
    print("❌ FAILED: response_recommendation.automated_action is not False")
    sys.exit(1)
print("  ✓ response_recommendation.automated_action is False")

# Verify threat level and decision mapping
threat_level = result.get("threat_level", "").upper()
decision_action = decision.get("decision", "").upper()

print(f"\nVerifying threat level → decision mapping...")
print(f"  Threat level: {threat_level}")
print(f"  Decision action: {decision_action}")

valid_mappings = {
    "LOW": "ALLOW",
    "MEDIUM": "ALERT",
    "HIGH": "ESCALATE",
    "CRITICAL": "ESCALATE",
}

if threat_level in valid_mappings:
    if decision_action != valid_mappings[threat_level]:
        print(f"❌ FAILED: Invalid mapping {threat_level} → {decision_action}")
        print(f"   Expected: {threat_level} → {valid_mappings[threat_level]}")
        sys.exit(1)
    print(f"  ✓ Valid mapping: {threat_level} → {decision_action}")

# Pretty print the response for visual verification
print("\n" + "="*70)
print("PHASE 9 API RESPONSE STRUCTURE (VERIFIED COMPATIBLE)")
print("="*70)
print(json.dumps(result, indent=2)[:500] + "...")

print("\n" + "="*70)
print("✅ ALL CHECKS PASSED - Phase 9 API is compatible with Phase 8")
print("="*70)
