"""
Triage Agent — SENTINEL-AI Severity Classification

Implements the Triage Agent using ReAct (Reason + Act) pattern:
1. Reads security alert
2. Reasons step-by-step about severity
3. Maps to MITRE ATT&CK tactic and technique  
4. Outputs: Severity (P1-P4), MITRE tactic, technique, confidence, rationale

Tools available:
- sigma_matcher: Match alert against Sigma rules
- mitre_lookup: Look up MITRE ATT&CK technique details

Week 1: Scaffold implementation — full ReAct loop in Week 2.
"""

import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

# LLM imports (available after pip install)
try:
    from langchain_ollama import OllamaLLM
    from langchain_core.prompts import PromptTemplate
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

# Set up logging
logger = logging.getLogger(__name__)


# System prompt for Triage Agent
TRIAGE_SYSTEM_PROMPT = """You are a senior cybersecurity analyst at a Security Operations Centre (SOC). 
Your task is to triage security alerts and classify their severity.

Given a security alert, you must:
1. REASON about what kind of attack this could be
2. LOOK UP relevant MITRE ATT&CK techniques  
3. CLASSIFY the severity using the P1-P4 scale
4. PROVIDE a clear rationale for your decision

Severity Scale:
- P1 (Critical): Active breach, data loss imminent, or critical system compromise
- P2 (High): Active attack in progress or high-value target at risk
- P3 (Medium): Suspicious activity requiring investigation
- P4 (Low): Anomalous but likely benign activity

Always structure your response as JSON with these fields:
{
    "reasoning": "Step-by-step analysis...",
    "severity": "P1|P2|P3|P4",
    "mitre_tactic": "tactic name",
    "mitre_technique": "T1234",
    "confidence": 0.0-1.0,
    "rationale": "Clear explanation for the classification"
}"""


class TriageAgent:
    """
    Triage Agent that classifies security alert severity using ReAct reasoning.
    
    Week 1: Basic rule-based classification
    Week 2: Full ReAct loop with LLM reasoning and tool use
    """
    
    def __init__(self, model_name: str = "llama3.1", max_iterations: int = 3):
        """
        Initialize the Triage Agent.
        
        Args:
            model_name: Ollama model to use for reasoning
            max_iterations: Maximum ReAct loop iterations
        """
        self.model_name = model_name
        self.max_iterations = max_iterations
        self.llm = None
        
        # Simple severity mapping for Week 1 stub
        self.severity_map = {
            'BENIGN': ('P4', 'None', 'T0000'),
            'DoS Hulk': ('P1', 'Impact', 'T1499.002'),
            'DoS GoldenEye': ('P1', 'Impact', 'T1499.002'),
            'DoS slowloris': ('P1', 'Impact', 'T1499.002'),
            'DoS Slowhttptest': ('P1', 'Impact', 'T1499.002'),
            'DDoS': ('P1', 'Impact', 'T1499.002'),
            'PortScan': ('P2', 'Discovery', 'T1046'),
            'Brute Force -Web': ('P2', 'Credential Access', 'T1110.001'),
            'Brute Force -XSS': ('P2', 'Credential Access', 'T1110.001'),
            'SQL Injection': ('P1', 'Initial Access', 'T1190'),
            'Web Attack - Sql Injection': ('P1', 'Initial Access', 'T1190'),
            'Web Attack - Brute Force': ('P2', 'Credential Access', 'T1110.001'),
            'Web Attack - XSS': ('P2', 'Execution', 'T1059.007'),
            'Infiltration': ('P1', 'Lateral Movement', 'T1055'),
            'Bot': ('P2', 'Execution', 'T1059'),
            'Heartbleed': ('P1', 'Initial Access', 'T1190'),
        }
        
        if LANGCHAIN_AVAILABLE:
            self._initialize_llm()

    def _initialize_llm(self) -> None:
        """Initialize Ollama LLM client."""
        try:
            self.llm = OllamaLLM(model=self.model_name)
            logger.info(f"✅ Triage Agent initialized with model: {self.model_name}")
        except Exception as e:
            logger.warning(f"⚠️  Could not initialize LLM: {e}. Will use rule-based fallback.")
            self.llm = None

    def classify_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify the severity of a security alert.
        
        Args:
            alert_data: Alert data dictionary
            
        Returns:
            Classification result with severity, MITRE info, and rationale
        """
        event_type = alert_data.get('event_type', 'Unknown')
        source_ip = alert_data.get('source_ip', 'Unknown')
        
        # Week 1: Rule-based classification
        if event_type in self.severity_map:
            severity, tactic, technique = self.severity_map[event_type]
            rationale = f"Rule-based classification: {event_type} mapped to severity {severity}"
            confidence = 0.85
        else:
            # Unknown event type - medium priority
            severity = "P3"
            tactic = "Unknown"
            technique = "T0000"
            rationale = f"Unknown event type '{event_type}' - defaulting to Medium priority (P3)"
            confidence = 0.5
        
        return {
            "severity": severity,
            "mitre_tactic": tactic,
            "mitre_technique": technique,
            "confidence": confidence,
            "triage_rationale": rationale,
            "classification_method": "rule-based-stub"
        }

    def get_triage_prompt(self, alert_data: Dict[str, Any]) -> str:
        """
        Generate the triage analysis prompt for the LLM.
        
        Args:
            alert_data: Alert data to analyze
            
        Returns:
            Formatted prompt string
        """
        return f"""Analyze this security alert and provide a triage classification:

Alert ID: {alert_data.get('alert_id', 'Unknown')}
Event Type: {alert_data.get('event_type', 'Unknown')}
Source IP: {alert_data.get('source_ip', 'Unknown')}
Destination IP: {alert_data.get('destination_ip', 'Unknown')}
Protocol: {alert_data.get('protocol', 'Unknown')}
Raw Payload: {alert_data.get('raw_payload', 'No payload')}
Timestamp: {alert_data.get('timestamp', 'Unknown')}

Provide your analysis following the JSON format specified in your instructions."""