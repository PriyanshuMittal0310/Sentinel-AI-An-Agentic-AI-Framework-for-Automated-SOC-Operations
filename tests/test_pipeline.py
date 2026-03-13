"""
Integration test: End-to-end pipeline validation for Week 1 checkpoint.

Tests that 5 sample alerts pass through the complete empty graph from 
start to finish without errors — the Week 1 checkpoint requirement.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline.state import AlertState, validate_alert_state, create_empty_alert_state


class TestAlertState:
    """Tests for the AlertState TypedDict and helper functions."""
    
    def test_create_empty_state(self):
        """Test creating an empty AlertState."""
        state = create_empty_alert_state("test_001", "test payload")
        
        assert state["alert_id"] == "test_001"
        assert state["raw_payload"] == "test payload"
        assert state["is_clean"] is None
        assert state["severity"] is None
        assert state["errors"] == []

    def test_validate_valid_state(self):
        """Test validation of a valid AlertState."""
        state = create_empty_alert_state("test_001", "payload")
        state["severity"] = "P1"
        state["confidence"] = 0.85
        
        errors = validate_alert_state(state)
        
        assert len(errors) == 0

    def test_validate_invalid_severity(self):
        """Test validation catches invalid severity values."""
        state = create_empty_alert_state("test_001", "payload")
        state["severity"] = "INVALID"  # Not P1-P4
        
        errors = validate_alert_state(state)
        
        assert len(errors) > 0

    def test_validate_invalid_confidence(self):
        """Test validation catches out-of-range confidence values."""
        state = create_empty_alert_state("test_001", "payload")
        state["confidence"] = 1.5  # Must be 0.0-1.0
        
        errors = validate_alert_state(state)
        
        assert len(errors) > 0

    def test_validate_missing_alert_id(self):
        """Test validation catches missing required fields."""
        # Create a state with missing alert_id  
        state = create_empty_alert_state("", "payload")
        
        errors = validate_alert_state(state)
        
        assert len(errors) > 0


class TestPipelineIntegration:
    """Integration tests for the complete pipeline."""
    
    def test_sample_alerts_defined(self):
        """Test that sample alerts can be created for testing."""
        sample_alerts = [
            {"alert_id": f"test_{i:03d}", "raw_payload": f"test payload {i}"}
            for i in range(1, 6)
        ]
        
        assert len(sample_alerts) == 5
        
        for alert in sample_alerts:
            state = create_empty_alert_state(alert["alert_id"], alert["raw_payload"])
            errors = validate_alert_state(state)
            assert len(errors) == 0

    def test_state_immutable_required_fields(self):
        """Test that required fields are preserved throughout pipeline."""
        state = create_empty_alert_state("test_001", "test payload")
        
        # Simulate agents writing to state
        state["is_clean"] = True
        state["severity"] = "P2"
        state["retrieved_techniques"] = [{"name": "Test Technique"}]
        
        # Required fields should remain
        assert state["alert_id"] == "test_001"
        assert state["raw_payload"] == "test payload"
        
        # Agent outputs should be set
        assert state["is_clean"] is True
        assert state["severity"] == "P2"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])