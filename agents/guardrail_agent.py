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

try:
    from langchain_ollama import OllamaLLM
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

# Set up logging
logger = logging.getLogger(__name__)


class GuardrailAgent:
    """
    Security guard agent that validates alerts for prompt injection attacks.
    
    Pattern-based Layer 1 is fully implemented.
    LLM-based Layer 2 is a stub for Week 3 implementation.
    """
    
    def __init__(
        self,
        patterns_path: str = "tools/injection_patterns.yaml",
        layer2_model_name: str = "mistral",
        use_layer2_llm: bool = True,
    ):
        """
        Initialize the Guardrail Agent.
        
        Args:
            patterns_path: Path to YAML file containing injection patterns
        """
        self.patterns_path = Path(patterns_path)
        self.layer2_model_name = layer2_model_name
        self.use_layer2_llm = use_layer2_llm
        self.injection_patterns: List[Dict[str, Any]] = []
        self.thresholds: Dict[str, int] = {}
        self.layer2_llm = None
        
        self._load_patterns()
        self._initialize_layer2_model()

    def _initialize_layer2_model(self) -> None:
        if not self.use_layer2_llm or not LANGCHAIN_AVAILABLE:
            return
        try:
            self.layer2_llm = OllamaLLM(model=self.layer2_model_name)
            logger.info("Guardrail Layer 2 model initialized: %s", self.layer2_model_name)
        except Exception as exc:
            logger.warning("Guardrail Layer 2 model unavailable, using heuristic mode: %s", exc)
            self.layer2_llm = None

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
            high_or_critical = [
                p for p in detected_patterns if p["severity"] in {"HIGH", "CRITICAL"}
            ]
            medium = [p for p in detected_patterns if p["severity"] == "MEDIUM"]
            low = [p for p in detected_patterns if p["severity"] == "LOW"]

            high_threshold = int(self.thresholds.get("high_risk_patterns", 1))
            medium_threshold = int(self.thresholds.get("medium_risk_patterns", 2))
            low_threshold = int(self.thresholds.get("low_risk_patterns", 5))

            triggered = (
                len(high_or_critical) >= high_threshold
                or len(medium) >= medium_threshold
                or len(low) >= low_threshold
            )

            if not triggered:
                return False, None, None

            reason = f"Layer 1 detection: {len(detected_patterns)} injection pattern(s) found. " \
                    f"Highest severity: {highest_severity}. " \
                    f"Matched: [{', '.join(p['matched_text'] for p in detected_patterns)}]"
            
            logger.warning(f"🚨 Injection detected in payload: {reason}")
            return True, reason, highest_severity
        
        return False, None, None

    def _expected_severity(self, event_type: str) -> Optional[str]:
        normalized = str(event_type).strip().lower()
        expected = {
            "benign": "P4",
            "ddos": "P1",
            "dos hulk": "P1",
            "dos goldeneye": "P1",
            "dos slowloris": "P1",
            "dos slowhttptest": "P1",
            "sql injection": "P1",
            "heartbleed": "P1",
            "portscan": "P2",
            "brute force -web": "P2",
            "brute force -xss": "P2",
            "bot": "P2",
            "infiltration": "P1",
        }
        return expected.get(normalized)

    def _heuristic_layer2_verify(self, original_alert: Dict[str, Any], agent_output: Dict[str, Any]) -> Tuple[bool, Optional[str], float]:
        event_type = str(original_alert.get('event_type', '')).lower()
        recommended_actions = agent_output.get('recommended_actions', []) or []
        severity = str(agent_output.get('severity', '')).strip()
        incident_summary = str(agent_output.get('incident_summary', '')).lower()

        suspicious_keywords = ['whitelist', 'allow all', 'ignore', 'skip', 'no action required']

        if event_type != 'benign':
            for action in recommended_actions:
                lower_action = str(action).lower()
                if any(keyword in lower_action for keyword in suspicious_keywords):
                    return False, f"Suspicious recommendation for {event_type} attack: '{action}'", 0.85

        expected = self._expected_severity(event_type)
        if expected and severity and expected != severity:
            # Only flag obviously risky down-grades.
            if expected == 'P1' and severity in {'P3', 'P4'}:
                return False, f"Critical attack type ({event_type}) assigned low severity ({severity})", 0.8

        if event_type in {'ddos', 'sql injection', 'heartbleed'} and 'benign' in incident_summary:
            return False, f"Summary appears inconsistent with attack type ({event_type})", 0.75

        return True, None, 0.65

    def _llm_layer2_verify(self, original_alert: Dict[str, Any], agent_output: Dict[str, Any]) -> Tuple[bool, Optional[str], float]:
        if not self.layer2_llm:
            return True, None, 0.0

        prompt = (
            "You are a security consistency verifier. "
            "Return ONLY JSON with keys: consistent (bool), reason (string), confidence (0-1).\n\n"
            f"Original alert: {original_alert}\n\n"
            f"Agent output: {agent_output}\n\n"
            "Mark as inconsistent if output downplays clear attacks or suggests unsafe actions "
            "(whitelist/ignore/allow-all for malicious alerts)."
        )
        try:
            raw = self.layer2_llm.invoke(prompt)
            # Best-effort JSON extraction.
            start = raw.find("{")
            end = raw.rfind("}")
            if start == -1 or end == -1:
                return True, None, 0.0
            candidate = raw[start : end + 1]
            import json

            parsed = json.loads(candidate)
            consistent = bool(parsed.get("consistent", True))
            reason = parsed.get("reason")
            conf = float(parsed.get("confidence", 0.6))
            conf = max(0.0, min(1.0, conf))
            return consistent, reason, conf
        except Exception as exc:
            logger.warning("Layer 2 LLM verification fallback due to parse/runtime issue: %s", exc)
            return True, None, 0.0

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
        logger.info("Layer 2 verification running")

        heur_consistent, heur_reason, heur_conf = self._heuristic_layer2_verify(original_alert, agent_output)
        if not heur_consistent:
            logger.warning("🚨 Layer 2 heuristic inconsistency detected: %s", heur_reason)
            return False, heur_reason

        llm_consistent, llm_reason, llm_conf = self._llm_layer2_verify(original_alert, agent_output)
        if not llm_consistent and llm_conf >= 0.65:
            reason = llm_reason or "Layer 2 LLM detected semantic inconsistency"
            logger.warning("🚨 Layer 2 LLM inconsistency detected: %s", reason)
            return False, reason

        logger.info("✅ Layer 2 verification passed (heuristic_conf=%.2f llm_conf=%.2f)", heur_conf, llm_conf)
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

    def verify_final_output(self, original_alert: Dict[str, Any], agent_output: Dict[str, Any]) -> Dict[str, Any]:
        """Run Layer 2 verification over final pipeline output contract."""
        is_consistent, reason = self.layer2_verify(original_alert, agent_output)
        return {
            "is_consistent": is_consistent,
            "injection_detected": not is_consistent,
            "injection_reason": reason,
            "guardrail_layer": "layer2" if not is_consistent else None,
            "injection_confidence": 0.75 if not is_consistent else 0.0,
        }