"""
Investigator Agent — SENTINEL-AI Incident Report Generation

Combines all agent outputs to generate plain-English incident summaries 
and actionable remediation recommendations.

Input:
- Original alert + raw payload
- Triage result (severity, MITRE tactic/technique, confidence)
- Context enrichment (retrieved MITRE techniques)

Output:
- Incident report in plain English
- 3+ immediate remediation actions  
- Overall investigation confidence score

Week 1: Template-based report generation
Week 3: Full LLM-powered investigation with reasoning
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)


class InvestigatorAgent:
    """
    Investigator Agent that generates comprehensive incident reports.
    
    Week 1: Template-based report generation
    Week 3: LLM-powered narrative generation with MITRE context
    """
    
    def __init__(self, model_name: str = "llama3.1"):
        """
        Initialize the Investigator Agent.
        
        Args:
            model_name: Ollama model to use for investigation
        """
        self.model_name = model_name
        self.llm = None
        
        # Remediation playbooks for common attack types
        self.remediation_playbooks = {
            "DoS": [
                "Immediately rate-limit traffic from source IP {source_ip}",
                "Enable DDoS protection on affected services",
                "Contact ISP to upstream-filter malicious traffic",
                "Review and update firewall rules to block attack patterns"
            ],
            "PortScan": [
                "Block source IP {source_ip} at perimeter firewall for 24 hours",
                "Review which services are exposed and reduce attack surface",
                "Enable port scan detection alerts in SIEM",
                "Conduct vulnerability assessment on exposed ports"
            ],
            "BruteForce": [
                "Lock user accounts targeted from source IP {source_ip}",
                "Implement account lockout policy (max 5 attempts)",
                "Enable multi-factor authentication on targeted services",
                "Block source IP at firewall and review authentication logs"
            ],
            "SQLInjection": [
                "Block source IP {source_ip} immediately",
                "Review web application firewall (WAF) rules",
                "Audit application code for SQL injection vulnerabilities",
                "Rotate database credentials as precaution"
            ],
            "Bot": [
                "Isolate potentially infected hosts",
                "Run malware scan on systems in source subnet",
                "Block known C2 domains and IPs at perimeter",
                "Review process execution logs for suspicious activity"
            ],
            "Default": [
                "Monitor traffic from source IP {source_ip} for 24 hours",
                "Review related logs in SIEM for pattern correlation",
                "Update security monitoring rules based on findings",
                "Document incident for threat intelligence sharing"
            ]
        }

    def generate_report(self, alert_data: Dict[str, Any], triage_result: Dict[str, Any], 
                        context_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive incident report.
        
        Args:
            alert_data: Original alert data
            triage_result: Output from Triage Agent
            context_result: Output from Context Agent
            
        Returns:
            Investigation report with summary and recommended actions
        """
        # Extract key information
        alert_id = alert_data.get('alert_id', 'Unknown')
        event_type = alert_data.get('event_type', 'Unknown')
        source_ip = alert_data.get('source_ip', 'Unknown')
        dest_ip = alert_data.get('destination_ip', 'Unknown')
        
        severity = triage_result.get('severity', 'P3')
        mitre_tactic = triage_result.get('mitre_tactic', 'Unknown')
        mitre_technique = triage_result.get('mitre_technique', 'Unknown')
        confidence = triage_result.get('confidence', 0.5)
        rationale = triage_result.get('triage_rationale', '')
        
        retrieved_techniques = context_result.get('retrieved_techniques', [])
        
        # Generate incident summary
        incident_summary = self._generate_incident_summary(
            alert_id, event_type, source_ip, dest_ip, severity, 
            mitre_tactic, mitre_technique, confidence, rationale, retrieved_techniques
        )
        
        # Generate recommended actions
        recommended_actions = self._generate_recommendations(event_type, source_ip)
        
        # Calculate overall confidence
        investigation_confidence = self._calculate_confidence(confidence, retrieved_techniques)
        
        return {
            "incident_summary": incident_summary,
            "recommended_actions": recommended_actions,
            "investigation_confidence": investigation_confidence
        }

    def _generate_incident_summary(self, alert_id: str, event_type: str, 
                                    source_ip: str, dest_ip: str, severity: str, 
                                    mitre_tactic: str, mitre_technique: str, 
                                    confidence: float, rationale: str, 
                                    techniques: List[Dict]) -> str:
        """
        Generate a plain-English incident summary.
        
        Args:
            Various alert and analysis fields
            
        Returns:
            Formatted incident summary string
        """
        severity_descriptions = {
            'P1': 'CRITICAL — Immediate action required',
            'P2': 'HIGH — Urgent investigation needed',
            'P3': 'MEDIUM — Investigate within 4 hours',
            'P4': 'LOW — Review at next opportunity'
        }
        
        severity_desc = severity_descriptions.get(severity, severity)
        
        # Format retrieved techniques
        technique_info = ""
        if techniques:
            top_technique = techniques[0]
            technique_info = f"\n\nMITRE ATT&CK Context:\n" \
                           f"  • Primary Technique: {top_technique.get('name', 'Unknown')} ({top_technique.get('technique_id', 'T0000')})\n" \
                           f"  • Tactic: {top_technique.get('tactics', 'Unknown')}"
        
        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║                   INCIDENT REPORT                           ║
╚══════════════════════════════════════════════════════════════╝

Alert ID    : {alert_id}
Timestamp   : {datetime.now().isoformat()}
Severity    : {severity} — {severity_desc.split('—')[1].strip() if '—' in severity_desc else ''}

THREAT ACTOR
  Source IP : {source_ip}
  Target IP : {dest_ip or 'Unknown'}

ATTACK ANALYSIS
  Event Type : {event_type}
  MITRE Tactic : {mitre_tactic}
  MITRE Technique : {mitre_technique}
  Detection Confidence : {confidence:.1%}
{technique_info}

ANALYST NOTES
  {rationale}

INVESTIGATION NOTES
  This report was generated by SENTINEL-AI (Week 1 implementation).
  Full LLM-powered investigation will be available in Week 3.
        """.strip()
        
        return summary

    def _generate_recommendations(self, event_type: str, source_ip: str) -> List[str]:
        """
        Generate remediation recommendations based on event type.
        
        Args:
            event_type: Type of security event
            source_ip: Source IP address
            
        Returns:
            List of actionable recommendations
        """
        # Map event types to playbook categories
        playbook_map = {
            'DoS Hulk': 'DoS', 'DoS GoldenEye': 'DoS', 
            'DoS slowloris': 'DoS', 'DoS Slowhttptest': 'DoS', 'DDoS': 'DoS',
            'PortScan': 'PortScan',
            'Brute Force -Web': 'BruteForce', 'Brute Force -XSS': 'BruteForce',
            'Web Attack - Brute Force': 'BruteForce',
            'SQL Injection': 'SQLInjection', 'Web Attack - Sql Injection': 'SQLInjection',
            'Bot': 'Bot'
        }
        
        playbook_key = playbook_map.get(event_type, 'Default')
        actions = self.remediation_playbooks.get(playbook_key, self.remediation_playbooks['Default'])
        
        # Format actions with actual source IP
        formatted_actions = [
            action.format(source_ip=source_ip) for action in actions
        ]
        
        return formatted_actions[:4]  # Return top 4 recommendations

    def _calculate_confidence(self, triage_confidence: float, retrieved_techniques: List[Dict]) -> float:
        """
        Calculate overall investigation confidence.
        
        Args:
            triage_confidence: Confidence from Triage Agent
            retrieved_techniques: Techniques from Context Agent
            
        Returns:
            Overall confidence score (0.0-1.0)
        """
        # Weight: 60% triage confidence, 40% knowledge base quality
        retrieval_quality = 0.0
        if retrieved_techniques:
            avg_relevance = sum(t.get('relevance_score', 0.5) for t in retrieved_techniques) / len(retrieved_techniques)
            retrieval_quality = avg_relevance
        
        overall_confidence = (0.6 * triage_confidence) + (0.4 * retrieval_quality)
        return min(max(overall_confidence, 0.0), 1.0)  # Clamp to [0, 1]