"""
Guardrail Agent — SENTINEL-AI Security Defense Layer

Implements two-layer protection against Indirect Prompt Injection attacks:

Layer 1 — Pattern-Based Input Scanning (Before any LLM processes the log):
    Fast regex matching against known injection patterns.
    Returns result in <1ms. Catches obvious attacks.

Layer 2 — Intent Verification (After Investigator Agent responds):
    Uses Mistral 7B to verify output consistency with original alert.
    Catches sophisticated attacks that bypass Layer 1.

Week 1: Scaffold implementation — full injection detection in Week 3.
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import yaml

# Set up logging
logger = logging.getLogger(__name__)


class GuardrailAgent:
    """
    Security guard agent that validates alerts for prompt injection attacks.
    
    Pattern-based Layer 1 is fully implemented.
    LLM-based Layer 2 is a stub for Week 3 implementation.
    """
    
    def __init__(self, patterns_path: str = "tools/injection_patterns.yaml"):
        """
        Initialize the Guardrail Agent.
        
        Args:
            patterns_path: Path to YAML file containing injection patterns
        """
        self.patterns_path = Path(patterns_path)
        self.injection_patterns: List[Dict[str, Any]] = []
        self.thresholds: Dict[str, int] = {}
        
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load injection detection patterns from YAML configuration."""
        if not self.patterns_path.exists():
            logger.warning(f"Patterns file not found at {self.patterns_path}. Using defaults.")
            self._load_default_patterns()
            return
        
        try:
            with open(self.patterns_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Flatten all patterns into a single list
            for category, patterns in config.get('injection_patterns', {}).items():
                for pattern_entry in patterns:
                    self.injection_patterns.append({
                        'category': category,
                        'pattern': re.compile(pattern_entry['pattern'], re.IGNORECASE),
                        'severity': pattern_entry.get('severity', 'MEDIUM'),
                        'description': pattern_entry.get('description', '')
                    })
            
            self.thresholds = config.get('thresholds', {})
            logger.info(f"Loaded {len(self.injection_patterns)} injection patterns")
            
        except Exception as e:
            logger.error(f"Error loading patterns from {self.patterns_path}: {e}")
            self._load_default_patterns()

    def _load_default_patterns(self) -> None:
        """Load default hardcoded injection patterns as fallback."""
        default_patterns = [
            (r'ignore.{0,30}instructions?', 'HIGH'),
            (r'disregard.{0,30}previous', 'HIGH'),
            (r'you are now in (admin|maintenance|debug) mode', 'CRITICAL'),
            (r'system prompt:', 'CRITICAL'),
            (r'override (security|classification|severity)', 'CRITICAL'),
            (r'new (task|objective|instruction):', 'HIGH'),
        ]
        
        self.injection_patterns = [
            {
                'category': 'default',
                'pattern': re.compile(pattern, re.IGNORECASE),
                'severity': severity,
                'description': f'Default pattern: {pattern}'
            }
            for pattern, severity in default_patterns
        ]
        
        logger.info(f"Using {len(self.injection_patterns)} default patterns")

    def layer1_scan(self, raw_payload: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Layer 1: Fast pattern-based injection detection.
        
        Scans raw log payload with regex patterns. Runs before ANY LLM processing.
        
        Args:
            raw_payload: Raw log text to scan
            
        Returns:
            Tuple of (is_injection_detected, reason, severity)
        """
        if not raw_payload:
            return False, None, None
        
        detected_patterns = []
        highest_severity = None
        
        severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        
        for pattern_entry in self.injection_patterns:
            match = pattern_entry['pattern'].search(raw_payload)
            
            if match:
                severity = pattern_entry['severity']
                detected_patterns.append({
                    'pattern': pattern_entry['description'],
                    'severity': severity,
                    'matched_text': match.group(),
                    'category': pattern_entry['category']
                })
                
                # Track highest severity found
                if highest_severity is None or severity_order.get(severity, 0) > severity_order.get(highest_severity, 0):
                    highest_severity = severity
        
        if detected_patterns:
            reason = f"Layer 1 detection: {len(detected_patterns)} injection pattern(s) found. " \
                    f"Highest severity: {highest_severity}. " \
                    f"Matched: [{', '.join(p['matched_text'] for p in detected_patterns)}]"
            
            logger.warning(f"🚨 Injection detected in payload: {reason}")
            return True, reason, highest_severity
        
        return False, None, None

    def layer2_verify(self, original_alert: Dict[str, Any], agent_output: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Layer 2: LLM-based intent verification (Week 3 stub).
        
        Checks if agent output is semantically consistent with original alert.
        Uses separate Mistral 7B model to avoid contamination.
        
        Args:
            original_alert: Original alert data before processing
            agent_output: Final output from Investigator Agent
            
        Returns:
            Tuple of (is_consistent, reason_if_inconsistent)
        """
        # Week 1 Stub: Basic consistency checks without LLM
        # Full LLM verification will be implemented in Week 3
        
        logger.info("Layer 2 verification running (Week 1 stub mode)")
        
        # Basic sanity checks
        event_type = original_alert.get('event_type', '').lower()
        incident_summary = agent_output.get('incident_summary', '').lower()
        recommended_actions = agent_output.get('recommended_actions', [])
        severity = agent_output.get('severity', '')
        
        # Check for suspicious recommendations
        suspicious_keywords = ['whitelist', 'allow all', 'ignore', 'skip', 'no action required']
        
        if event_type != 'benign':  # Non-benign alerts shouldn't be whitelisted
            for action in recommended_actions:
                for keyword in suspicious_keywords:
                    if keyword in action.lower():
                        reason = f"Suspicious recommendation for {event_type} attack: '{action}'"
                        logger.warning(f"🚨 Layer 2 inconsistency detected: {reason}")
                        return False, reason
        
        # Severity consistency check
        if event_type in ['ddos', 'sql injection', 'heartbleed'] and severity == 'P4':
            reason = f"Critical attack type ({event_type}) assigned low severity (P4) - potential manipulation"
            logger.warning(f"🚨 Layer 2 inconsistency detected: {reason}")
            return False, reason
        
        logger.info("✅ Layer 2 verification passed (stub)")
        return True, None

    def check_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run complete guardrail check on an alert.
        
        Args:
            alert_data: Alert data dictionary
            
        Returns:
            Dictionary with guardrail results
        """
        raw_payload = alert_data.get('raw_payload', '')
        
        # Run Layer 1 scan
        is_injected, reason, severity = self.layer1_scan(raw_payload)
        
        return {
            'is_clean': not is_injected,
            'injection_detected': is_injected,
            'injection_reason': reason,
            'injection_severity': severity,
            'guardrail_layer': 'layer1' if is_injected else None,
            'injection_confidence': 0.9 if is_injected else 0.0
        }