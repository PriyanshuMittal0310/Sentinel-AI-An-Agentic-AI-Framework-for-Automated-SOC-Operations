"""
SENTINEL-AI State Definition

Defines the shared state structure passed between all agents in the LangGraph pipeline.
The AlertState TypedDict contains all data fields that agents read from and write to.
"""

from typing import TypedDict, Optional, List, Dict, Any
from datetime import datetime


class AlertState(TypedDict):
    """
    Shared state object passed through the entire SENTINEL-AI LangGraph pipeline.
    
    This state is shared across all agents and contains:
    - Input alert data (from CICIDS parser or live feeds)
    - Security validation results (from Guardrail Agent) 
    - Triage classification (from Triage Agent)
    - Context enrichment (from Context Agent)
    - Investigation results (from Investigator Agent)
    """
    
    # ===== INPUT DATA (Set by ingestion layer) =====
    alert_id: str                    # Unique identifier for this alert
    raw_payload: str                 # Raw log text (UNTRUSTED - may contain injection)
    source_ip: str                   # Source IP address from the alert
    destination_ip: Optional[str]    # Destination IP (if applicable)
    destination_port: Optional[int]  # Destination port (if applicable)
    protocol: Optional[str]          # Network protocol (TCP, UDP, ICMP, etc.)
    event_type: str                  # Alert type/category (DoS, PortScan, etc.)
    timestamp: str                   # ISO format timestamp
    
    # Additional metadata from CICIDS2017 or other sources
    flow_duration: Optional[float]               # Network flow duration
    total_fwd_packets: Optional[int]             # Forward packet count
    total_backward_packets: Optional[int]        # Backward packet count
    flow_bytes_per_sec: Optional[float]         # Flow rate
    
    # Ground truth (for evaluation) - not available in real deployment
    true_severity: Optional[str]                 # P1-P4 (for evaluation)
    true_mitre_technique: Optional[str]          # Technique ID (for evaluation)
    
    # ===== GUARDRAIL AGENT OUTPUT =====
    is_clean: Optional[bool]         # False if injection detected
    injection_reason: Optional[str]  # Why injection was detected
    injection_confidence: Optional[float]  # Confidence score (0.0-1.0)
    guardrail_layer: Optional[str]   # "layer1" (regex) or "layer2" (LLM)
    
    # ===== TRIAGE AGENT OUTPUT =====
    severity: Optional[str]          # P1 (Critical), P2 (High), P3 (Medium), P4 (Low)
    mitre_tactic: Optional[str]      # MITRE ATT&CK tactic (e.g., "Discovery")
    mitre_technique: Optional[str]   # MITRE technique ID (e.g., "T1046")
    confidence: Optional[float]      # Classification confidence (0.0-1.0)
    triage_rationale: Optional[str]  # Reasoning for the classification
    sigma_hint: Optional[str]        # Sigma rule match summary from SigmaMatcher tool
    
    # ===== CONTEXT AGENT OUTPUT =====
    retrieved_techniques: Optional[List[Dict[str, Any]]]  # Top-3 from ChromaDB
    context_query: Optional[str]     # Query used for retrieval
    context_metadata: Optional[Dict[str, Any]]  # Additional context info
    
    # ===== INVESTIGATOR AGENT OUTPUT =====
    incident_summary: Optional[str]              # Human-readable investigation report
    recommended_actions: Optional[List[str]]     # 3+ remediation steps
    investigation_confidence: Optional[float]    # Overall confidence in findings
    
    # ===== PIPELINE METADATA =====
    pipeline_start_time: Optional[str]      # When processing started
    pipeline_end_time: Optional[str]        # When processing completed
    processing_time_seconds: Optional[float] # Total time taken
    agent_execution_log: Optional[List[Dict[str, Any]]]  # Log of which agents ran
    
    # Error handling
    errors: Optional[List[str]]              # Any errors that occurred
    warnings: Optional[List[str]]            # Any warnings generated


# Helper functions for state manipulation
def create_empty_alert_state(alert_id: str, raw_payload: str) -> AlertState:
    """
    Create an empty AlertState with just the required input fields.
    
    Args:
        alert_id: Unique alert identifier
        raw_payload: Raw log data to process
        
    Returns:
        AlertState with minimal required fields populated
    """
    return AlertState(
        # Required input fields
        alert_id=alert_id,
        raw_payload=raw_payload,
        source_ip="",
        event_type="Unknown",
        timestamp=datetime.now().isoformat(),
        
        # Initialize optional fields to None
        destination_ip=None,
        destination_port=None,
        protocol=None,
        flow_duration=None,
        total_fwd_packets=None,
        total_backward_packets=None,
        flow_bytes_per_sec=None,
        true_severity=None,
        true_mitre_technique=None,
        
        # Guardrail fields
        is_clean=None,
        injection_reason=None,
        injection_confidence=None,
        guardrail_layer=None,
        
        # Triage fields
        severity=None,
        mitre_tactic=None,
        mitre_technique=None,
        confidence=None,
        triage_rationale=None,
        sigma_hint=None,
        
        # Context fields
        retrieved_techniques=None,
        context_query=None,
        context_metadata=None,
        
        # Investigator fields
        incident_summary=None,
        recommended_actions=None,
        investigation_confidence=None,
        
        # Pipeline metadata
        pipeline_start_time=datetime.now().isoformat(),
        pipeline_end_time=None,
        processing_time_seconds=None,
        agent_execution_log=[],
        
        # Error handling
        errors=[],
        warnings=[]
    )


def log_agent_execution(state: AlertState, agent_name: str, execution_time: float, success: bool) -> AlertState:
    """
    Log agent execution in the state.
    
    Args:
        state: Current AlertState
        agent_name: Name of the agent that executed
        execution_time: Time taken in seconds
        success: Whether execution was successful
        
    Returns:
        Updated AlertState with execution log entry
    """
    if state.get("agent_execution_log") is None:
        state["agent_execution_log"] = []
    
    log_entry = {
        "agent": agent_name,
        "timestamp": datetime.now().isoformat(),
        "execution_time": execution_time,
        "success": success
    }
    
    state["agent_execution_log"].append(log_entry)
    return state


def add_error(state: AlertState, error_message: str) -> AlertState:
    """
    Add an error message to the state.
    
    Args:
        state: Current AlertState
        error_message: Error message to add
        
    Returns:
        Updated AlertState with error added
    """
    if state.get("errors") is None:
        state["errors"] = []
    
    state["errors"].append(f"{datetime.now().isoformat()}: {error_message}")
    return state


def add_warning(state: AlertState, warning_message: str) -> AlertState:
    """
    Add a warning message to the state.
    
    Args:
        state: Current AlertState
        warning_message: Warning message to add
        
    Returns:
        Updated AlertState with warning added
    """
    if state.get("warnings") is None:
        state["warnings"] = []
    
    state["warnings"].append(f"{datetime.now().isoformat()}: {warning_message}")
    return state


def finalize_state(state: AlertState) -> AlertState:
    """
    Finalize the state by setting end time and calculating processing time.
    
    Args:
        state: AlertState to finalize
        
    Returns:
        AlertState with finalized timing information
    """
    end_time = datetime.now()
    state["pipeline_end_time"] = end_time.isoformat()
    
    if state.get("pipeline_start_time"):
        start_time = datetime.fromisoformat(state["pipeline_start_time"])
        processing_time = (end_time - start_time).total_seconds()
        state["processing_time_seconds"] = processing_time
    
    return state


# Validation functions
def validate_alert_state(state: AlertState) -> List[str]:
    """
    Validate that AlertState contains required fields.
    
    Args:
        state: AlertState to validate
        
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    # Check required fields
    required_fields = ["alert_id", "raw_payload"]
    for field in required_fields:
        if not state.get(field):
            errors.append(f"Missing required field: {field}")
    
    # Validate field types and ranges
    if state.get("confidence") is not None:
        if not 0.0 <= state["confidence"] <= 1.0:
            errors.append("Confidence must be between 0.0 and 1.0")
    
    if state.get("injection_confidence") is not None:
        if not 0.0 <= state["injection_confidence"] <= 1.0:
            errors.append("Injection confidence must be between 0.0 and 1.0")
    
    if state.get("severity") is not None:
        valid_severities = ["P1", "P2", "P3", "P4"]
        if state["severity"] not in valid_severities:
            errors.append(f"Severity must be one of: {valid_severities}")
    
    return errors