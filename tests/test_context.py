"""
Unit tests for Context Agent (Phase 2).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.context_agent import ContextAgent


class TestContextAgent:
    def setup_method(self):
        self.agent = ContextAgent()

    def test_build_query_includes_triage_fields(self):
        triage = {
            "event_type": "PortScan",
            "severity": "P2",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1046",
            "triage_rationale": "Suspicious scan activity",
            "raw_payload": "nmap scan against subnet",
        }

        query = self.agent.build_query(triage)

        assert "PortScan" in query
        assert "P2" in query
        assert "T1046" in query

    def test_retrieve_returns_list(self):
        results = self.agent.retrieve_techniques("port scanning discovery", n_results=2)

        assert isinstance(results, list)
        assert len(results) >= 1
        assert "technique_id" in results[0]
        assert "name" in results[0]
        assert "relevance_score" in results[0]

    def test_enrich_alert_returns_context_contract(self):
        alert = {
            "alert_id": "ctx_001",
            "event_type": "SQL Injection",
            "raw_payload": "SQL injection attempt in login endpoint",
        }
        triage = {
            "severity": "P1",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1190",
            "triage_rationale": "Public-facing app exploit pattern",
        }

        enriched = self.agent.enrich_alert(alert, triage)

        assert "context_query" in enriched
        assert "retrieved_techniques" in enriched
        assert "context_metadata" in enriched
        assert enriched["context_metadata"]["n_retrieved"] >= 1
