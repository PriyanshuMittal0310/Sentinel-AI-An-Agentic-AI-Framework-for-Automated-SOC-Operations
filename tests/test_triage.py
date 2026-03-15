"""
Unit Tests for the Triage Agent — Phase 2 (Week 2)

Tests the severity classification functionality:
- Rule-based ReAct classification for known attack types
- Handling of unknown event types
- MITRE technique mapping accuracy
- Sigma rule tool integration
- MITRE lookup tool integration
- Triage accuracy on a representative sample
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.triage_agent import TriageAgent, SIGMA_AVAILABLE, MITRE_LOOKUP_AVAILABLE


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

    def test_dos_hulk_classified_as_critical(self):
        """Test that DoS Hulk is classified as P1 Critical."""
        alert = {
            "alert_id": "test_008",
            "event_type": "DoS Hulk",
            "source_ip": "10.0.0.100",
            "raw_payload": "High-rate TCP flood detected",
            "flow_bytes_per_sec": 80000,
        }
        result = self.agent.classify_alert(alert)
        assert result["severity"] == "P1"
        assert result["mitre_tactic"] == "Impact"

    def test_bot_classified_as_high(self):
        """Test that Bot activity is classified as P2."""
        alert = {
            "alert_id": "test_009",
            "event_type": "Bot",
            "source_ip": "192.168.100.84",
            "raw_payload": "Bot C2 beacon detected",
        }
        result = self.agent.classify_alert(alert)
        assert result["severity"] == "P2"

    def test_brute_force_web_classified_as_high(self):
        """Test that web brute force is classified as P2 with Credential Access tactic."""
        alert = {
            "alert_id": "test_010",
            "event_type": "Brute Force -Web",
            "source_ip": "203.0.113.5",
            "raw_payload": "Multiple failed login attempts detected",
        }
        result = self.agent.classify_alert(alert)
        assert result["severity"] == "P2"
        assert result["mitre_tactic"] == "Credential Access"

    def test_mitre_technique_format(self):
        """Test that MITRE technique IDs follow the Txxxx or Txxxx.xxx format."""
        import re
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for event_type in ["PortScan", "DDoS", "SQL Injection", "Bot", "BENIGN"]:
            alert = {"alert_id": "fmt_test", "event_type": event_type, "raw_payload": ""}
            result = self.agent.classify_alert(alert)
            tech = result["mitre_technique"]
            assert pattern.match(tech) or tech == "T0000", \
                f"Invalid technique format for {event_type}: {tech}"

    def test_sigma_hint_present_when_available(self):
        """When Sigma tool is available, sigma_hint should be populated."""
        alert = {
            "alert_id": "sigma_001",
            "event_type": "PortScan",
            "source_ip": "10.0.0.1",
            "raw_payload": "nmap scan against subnet",
            "total_fwd_packets": 200,
            "total_backward_packets": 1,
        }
        result = self.agent.classify_alert(alert)
        if SIGMA_AVAILABLE:
            assert "sigma_hint" in result
            assert isinstance(result["sigma_hint"], str)

    def test_triage_accuracy_on_sample(self):
        """
        ReAct accuracy gate: ≥75% of a representative sample must be
        correctly classified.  (Week 2 checkpoint requirement)
        """
        sample = [
            # (event_type, expected_severity)
            ("BENIGN", "P4"),
            ("PortScan", "P2"),
            ("DoS Hulk", "P1"),
            ("SQL Injection", "P1"),
            ("Bot", "P2"),
            ("Brute Force -Web", "P2"),
            ("DDoS", "P1"),
            ("Heartbleed", "P1"),
        ]
        correct = 0
        for event_type, expected in sample:
            alert = {"alert_id": f"acc_{event_type}", "event_type": event_type, "raw_payload": ""}
            result = self.agent.classify_alert(alert)
            if result["severity"] == expected:
                correct += 1

        accuracy = correct / len(sample)
        assert accuracy >= 0.75, \
            f"Triage accuracy {accuracy:.1%} below 75% target. " \
            f"({correct}/{len(sample)} correct)"


class TestSigmaMatcherTool:
    """Tests for the SigmaMatcher tool (tools/sigma_matcher.py)."""

    @pytest.mark.skipif(not SIGMA_AVAILABLE, reason="SigmaMatcher not available")
    def test_sigma_matches_portscan(self):
        from tools.sigma_matcher import get_matcher
        matcher = get_matcher()
        alert = {
            "event_type": "PortScan",
            "total_fwd_packets": 50,
            "total_backward_packets": 1,
            "raw_payload": "nmap scan detected",
        }
        matches = matcher.match(alert)
        techniques = [m["technique"] for m in matches]
        assert "T1046" in techniques, "Sigma should match T1046 for PortScan"

    @pytest.mark.skipif(not SIGMA_AVAILABLE, reason="SigmaMatcher not available")
    def test_sigma_matches_dos(self):
        from tools.sigma_matcher import get_matcher
        matcher = get_matcher()
        alert = {
            "event_type": "DoS Hulk",
            "flow_bytes_per_sec": 100_000,
            "raw_payload": "hulk flood detected",
        }
        best = matcher.best_match(alert)
        assert best is not None
        assert best["tactic"] == "Impact"

    @pytest.mark.skipif(not SIGMA_AVAILABLE, reason="SigmaMatcher not available")
    def test_sigma_no_false_positive_on_benign(self):
        from tools.sigma_matcher import get_matcher
        matcher = get_matcher()
        alert = {
            "event_type": "BENIGN",
            "total_fwd_packets": 5,
            "total_backward_packets": 3,
            "flow_bytes_per_sec": 200,
            "raw_payload": "[ALLOW] TCP 192.168.1.1 -> 8.8.8.8:443 HTTPS",
        }
        matches = matcher.match(alert)
        # BENIGN should only match the baseline rule (not attack rules)
        non_benign = [m for m in matches if m["attack_type"] != "BENIGN"]
        assert len(non_benign) == 0, \
            f"False positive Sigma matches on benign: {[m['rule_name'] for m in non_benign]}"

    @pytest.mark.skipif(not SIGMA_AVAILABLE, reason="SigmaMatcher not available")
    def test_sigma_summarise_returns_string(self):
        from tools.sigma_matcher import sigma_match
        result = sigma_match({"event_type": "PortScan", "raw_payload": "nmap"})
        assert isinstance(result, str)
        assert len(result) > 0


class TestMitreLookupTool:
    """Tests for the MitreLookup tool (tools/mitre_lookup.py)."""

    @pytest.mark.skipif(not MITRE_LOOKUP_AVAILABLE, reason="MitreLookup not available")
    def test_lookup_known_technique(self):
        from tools.mitre_lookup import get_lookup
        lookup = get_lookup()
        result = lookup.get_technique("T1046")
        assert result is not None
        assert result["technique_id"] == "T1046"
        assert "name" in result
        assert "description" in result

    @pytest.mark.skipif(not MITRE_LOOKUP_AVAILABLE, reason="MitreLookup not available")
    def test_lookup_unknown_technique_returns_none(self):
        from tools.mitre_lookup import get_lookup
        lookup = get_lookup()
        result = lookup.get_technique("TXXXX")
        assert result is None

    @pytest.mark.skipif(not MITRE_LOOKUP_AVAILABLE, reason="MitreLookup not available")
    def test_lookup_has_techniques_loaded(self):
        from tools.mitre_lookup import get_lookup
        lookup = get_lookup()
        assert lookup.technique_count > 0

    @pytest.mark.skipif(not MITRE_LOOKUP_AVAILABLE, reason="MitreLookup not available")
    def test_search_by_tactic_returns_results(self):
        from tools.mitre_lookup import get_lookup
        lookup = get_lookup()
        results = lookup.search_by_tactic("Discovery", max_results=3)
        assert len(results) > 0
        for r in results:
            assert "technique_id" in r

    @pytest.mark.skipif(not MITRE_LOOKUP_AVAILABLE, reason="MitreLookup not available")
    def test_enrich_triage_result_returns_string(self):
        from tools.mitre_lookup import mitre_enrich
        result = mitre_enrich("T1046", "Discovery")
        assert isinstance(result, str)
        assert len(result) > 10


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
