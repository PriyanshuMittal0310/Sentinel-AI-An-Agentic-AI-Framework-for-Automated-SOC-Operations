"""Unit tests for Investigator Agent (Week 3)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.investigator_agent import InvestigatorAgent


class TestInvestigatorAgent:
    def setup_method(self):
        self.agent = InvestigatorAgent()

    def test_generate_report_contract(self):
        alert = {
            "alert_id": "inv_001",
            "event_type": "PortScan",
            "source_ip": "192.168.100.5",
            "destination_ip": "10.0.0.5",
            "raw_payload": "rapid scan detected",
        }
        triage = {
            "severity": "P2",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1046",
            "confidence": 0.83,
            "triage_rationale": "Scan pattern in payload and packet asymmetry",
        }
        context = {
            "retrieved_techniques": [
                {
                    "technique_id": "T1046",
                    "name": "Network Service Scanning",
                    "tactics": "Discovery",
                    "relevance_score": 0.9,
                }
            ]
        }

        report = self.agent.generate_report(alert, triage, context)

        assert "incident_summary" in report
        assert "recommended_actions" in report
        assert "investigation_confidence" in report
        assert isinstance(report["incident_summary"], str)
        assert len(report["incident_summary"]) > 50
        assert isinstance(report["recommended_actions"], list)
        assert len(report["recommended_actions"]) >= 3
        assert 0.0 <= report["investigation_confidence"] <= 1.0

    def test_recommendations_include_source_ip_for_known_playbook(self):
        actions = self.agent._generate_recommendations("SQL Injection", "203.0.113.7")
        assert any("203.0.113.7" in a for a in actions)
        assert len(actions) >= 3

    def test_default_playbook_for_unknown_event(self):
        actions = self.agent._generate_recommendations("UnknownEvent", "192.168.1.10")
        assert len(actions) >= 3
        assert any("192.168.1.10" in a for a in actions)
