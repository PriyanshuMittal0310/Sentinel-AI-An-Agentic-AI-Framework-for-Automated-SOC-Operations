"""
Triage Agent — SENTINEL-AI Severity Classification (Phase 2)

Implements a practical ReAct-style triage flow:
1. Observe alert fields and payload indicators.
2. Reason over attack signal strength.
3. Act by producing severity + MITRE mapping.
4. Optionally refine with local LLM output (if available).
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional

try:
    from langchain_ollama import OllamaLLM
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

logger = logging.getLogger(__name__)


TRIAGE_SYSTEM_PROMPT = """You are a SOC triage analyst.
Return ONLY valid JSON with keys:
reasoning, severity, mitre_tactic, mitre_technique, confidence, rationale

Severity scale:
- P1: active exploitation / service impact / high certainty compromise
- P2: strong malicious evidence, high risk activity
- P3: suspicious but uncertain activity
- P4: likely benign or low-risk anomaly
"""


class TriageAgent:
    """Phase 2 triage agent with deterministic logic + optional LLM enhancement."""

    def __init__(self, model_name: str = "llama3.1", max_iterations: int = 3):
        self.model_name = model_name
        self.max_iterations = max_iterations
        self.llm = None

        # Canonical mappings for CICIDS labels used in this project.
        self.severity_map = {
            "BENIGN": ("P4", "None", "T0000"),
            "DoS Hulk": ("P1", "Impact", "T1499.002"),
            "DoS GoldenEye": ("P1", "Impact", "T1499.002"),
            "DoS slowloris": ("P1", "Impact", "T1499.002"),
            "DoS Slowhttptest": ("P1", "Impact", "T1499.002"),
            "DDoS": ("P1", "Impact", "T1499.002"),
            "PortScan": ("P2", "Discovery", "T1046"),
            "Brute Force -Web": ("P2", "Credential Access", "T1110.001"),
            "Brute Force -XSS": ("P2", "Credential Access", "T1110.001"),
            "SQL Injection": ("P1", "Initial Access", "T1190"),
            "Web Attack - Sql Injection": ("P1", "Initial Access", "T1190"),
            "Web Attack - Brute Force": ("P2", "Credential Access", "T1110.001"),
            "Web Attack - XSS": ("P2", "Execution", "T1059.007"),
            "Infiltration": ("P1", "Lateral Movement", "T1055"),
            "Bot": ("P2", "Execution", "T1059"),
            "Heartbleed": ("P1", "Initial Access", "T1190"),
        }

        if LANGCHAIN_AVAILABLE:
            self._initialize_llm()

    def _initialize_llm(self) -> None:
        try:
            self.llm = OllamaLLM(model=self.model_name)
            logger.info("TriageAgent initialized with model: %s", self.model_name)
        except Exception as exc:
            logger.warning("LLM initialization failed, using deterministic mode: %s", exc)
            self.llm = None

    def _payload_signals(self, payload: str) -> List[str]:
        signals = []
        checks = {
            "port scan behavior": r"port\s*scan|syn\s*scan|nmap",
            "credential attack behavior": r"brute\s*force|failed\s*login|password\s*attempt",
            "sql injection indicators": r"sql\s*injection|union\s+select|or\s+1=1",
            "denial-of-service indicators": r"ddos|dos|slowloris|hulk|flood",
            "web exploit indicators": r"xss|<script>|public-facing|exploit",
        }
        for label, pattern in checks.items():
            if re.search(pattern, payload, flags=re.IGNORECASE):
                signals.append(label)
        return signals

    def _reason_and_classify(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        event_type = str(alert_data.get("event_type", "Unknown"))
        payload = str(alert_data.get("raw_payload", ""))

        # ReAct-style iterative reasoning (bounded loop).
        observations: List[str] = []
        current_guess = "P3"
        tactic = "Unknown"
        technique = "T0000"

        for step in range(self.max_iterations):
            if step == 0:
                observations.append(f"Observed event_type={event_type}")
                if event_type in self.severity_map:
                    current_guess, tactic, technique = self.severity_map[event_type]
                    observations.append("Known CICIDS label mapping found")
                    break

            if step == 1:
                signals = self._payload_signals(payload)
                if signals:
                    observations.append(f"Payload signals: {', '.join(signals)}")
                    if any("denial-of-service" in s for s in signals):
                        current_guess, tactic, technique = "P1", "Impact", "T1499.002"
                    elif any("sql injection" in s for s in signals):
                        current_guess, tactic, technique = "P1", "Initial Access", "T1190"
                    elif any("credential attack" in s for s in signals):
                        current_guess, tactic, technique = "P2", "Credential Access", "T1110.001"
                    elif any("port scan" in s for s in signals):
                        current_guess, tactic, technique = "P2", "Discovery", "T1046"
                    else:
                        current_guess = "P3"
                else:
                    observations.append("No strong malicious payload markers found")

            if step == 2:
                # Final calibration for unknown/noisy data.
                if event_type.upper() == "BENIGN":
                    current_guess, tactic, technique = "P4", "None", "T0000"
                    observations.append("Benign marker present, lowering severity")

        confidence = 0.85 if event_type in self.severity_map else 0.65
        if current_guess == "P3" and not payload:
            confidence = 0.5

        reasoning = " | ".join(observations) if observations else "Insufficient indicators"
        rationale = f"Classified {event_type} as {current_guess} based on mapped label and payload evidence."

        return {
            "reasoning": reasoning,
            "severity": current_guess,
            "mitre_tactic": tactic,
            "mitre_technique": technique,
            "confidence": round(float(confidence), 2),
            "rationale": rationale,
            "classification_method": "react-deterministic",
        }

    def _try_llm_refinement(self, alert_data: Dict[str, Any], deterministic: Dict[str, Any]) -> Dict[str, Any]:
        if not self.llm:
            return deterministic

        prompt = (
            TRIAGE_SYSTEM_PROMPT
            + "\n\nAlert:\n"
            + json.dumps(alert_data, ensure_ascii=True)
            + "\n\nInitial deterministic result:\n"
            + json.dumps(deterministic, ensure_ascii=True)
        )
        try:
            raw = self.llm.invoke(prompt)
            parsed = json.loads(raw)
            required = {"severity", "mitre_tactic", "mitre_technique", "confidence", "rationale"}
            if not required.issubset(parsed.keys()):
                return deterministic

            sev = parsed.get("severity", deterministic["severity"])
            if sev not in {"P1", "P2", "P3", "P4"}:
                sev = deterministic["severity"]

            conf = parsed.get("confidence", deterministic["confidence"])
            try:
                conf = float(conf)
            except Exception:
                conf = deterministic["confidence"]
            conf = max(0.0, min(1.0, conf))

            return {
                "reasoning": parsed.get("reasoning", deterministic.get("reasoning", "")),
                "severity": sev,
                "mitre_tactic": parsed.get("mitre_tactic", deterministic["mitre_tactic"]),
                "mitre_technique": parsed.get("mitre_technique", deterministic["mitre_technique"]),
                "confidence": round(conf, 2),
                "triage_rationale": parsed.get("rationale", deterministic["rationale"]),
                "classification_method": "react-llm",
            }
        except Exception:
            return deterministic

    def classify_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        base = self._reason_and_classify(alert_data)
        refined = self._try_llm_refinement(alert_data, base)

        # Normalize to pipeline contract field names.
        if "triage_rationale" not in refined:
            refined["triage_rationale"] = refined.get("rationale", "")

        return {
            "severity": refined["severity"],
            "mitre_tactic": refined.get("mitre_tactic", "Unknown"),
            "mitre_technique": refined.get("mitre_technique", "T0000"),
            "confidence": refined.get("confidence", 0.5),
            "triage_rationale": refined.get("triage_rationale", "No rationale provided"),
            "classification_method": refined.get("classification_method", "react-deterministic"),
            "reasoning": refined.get("reasoning", ""),
        }
