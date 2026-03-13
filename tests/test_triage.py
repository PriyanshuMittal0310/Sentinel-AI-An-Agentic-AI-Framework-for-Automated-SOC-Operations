"""
Unit Tests for the Triage Agent — Week 1 Placeholder Tests

Tests the severity classification functionality:
- Rule-based classification for known attack types
- Handling of unknown event types
- MITRE technique mapping accuracy

Full ReAct LLM tests will be added in Week 2.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.triage_agent import TriageAgent


class TestTriageAgentClassification:
    """Tests for Triage Agent severity classification."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.agent = TriageAgent()

    def test_ddos_classified_as_critical(self):
        """Test that DDoS attacks are classified as P1 Critical."""
        alert = {
            "alert_id": "test_001",
            "event_type": "DDoS",
            "source_ip": "192.168.1.1",
            "raw_payload": "DDoS attack detected"
        }
        
        result = self.agent.classify_alert(alert)
        
        assert result["severity"] == "P1", f"DDoS should be P1, got {result['severity']}"

    def test_benign_classified_as_low(self):
        """Test that benign traffic is classified as P4."""
        alert = {
            "alert_id": "test_002",
            "event_type": "BENIGN",
            "source_ip": "192.168.1.50",
            "raw_payload": "Normal traffic"
        }
        
        result = self.agent.classify_alert(alert)
        
        assert result["severity"] == "P4"

    def test_port_scan_classified_as_high(self):
        """Test that port scan is classified as P2 High."""
        alert = {
            "alert_id": "test_003",
            "event_type": "PortScan",
            "source_ip": "10.0.0.1",
            "raw_payload": "Port scan detected"
        }
        
        result = self.agent.classify_alert(alert)
        
        assert result["severity"] == "P2"

    def test_sql_injection_classified_as_critical(self):
        """Test that SQL injection is classified as P1 Critical."""
        alert = {
            "alert_id": "test_004",
            "event_type": "SQL Injection",
            "source_ip": "203.0.113.1",
            "raw_payload": "SQL injection detected"
        }
        
        result = self.agent.classify_alert(alert)
        
        assert result["severity"] == "P1"

    def test_unknown_event_classified_as_medium(self):
        """Test that unknown events default to P3 Medium."""
        alert = {
            "alert_id": "test_005",
            "event_type": "UnknownAttackType",
            "source_ip": "192.168.0.1",
            "raw_payload": "Unknown event"
        }
        
        result = self.agent.classify_alert(alert)
        
        assert result["severity"] == "P3"

    def test_confidence_in_valid_range(self):
        """Test that confidence score is always between 0 and 1."""
        alert = {
            "alert_id": "test_006",
            "event_type": "PortScan",
            "source_ip": "10.0.0.1",
            "raw_payload": "Port scan"
        }
        
        result = self.agent.classify_alert(alert)
        
        assert 0.0 <= result["confidence"] <= 1.0

    def test_all_required_fields_returned(self):
        """Test that classification result contains all required fields."""
        alert = {
            "alert_id": "test_007",
            "event_type": "BENIGN",
            "source_ip": "192.168.1.1",
            "raw_payload": "Normal traffic"
        }
        
        result = self.agent.classify_alert(alert)
        
        required_fields = ["severity", "mitre_tactic", "mitre_technique", 
                          "confidence", "triage_rationale"]
        
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])