"""
Sigma Rule Matcher — SENTINEL-AI Triage Tool

Provides lightweight Sigma-like rule matching for network security alerts.
Maps alert fields (source port, packet rates, payload patterns) to attack
categories and confidence signals that the Triage Agent can use in its
ReAct reasoning loop.

Sigma rules are simplified to pattern dictionaries — no external Sigma
library is required, keeping this project dependency-free.
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Simplified Sigma-like rule definitions
# ---------------------------------------------------------------------------
# Each rule has:
#   name        - human-readable rule name
#   description - what this rule detects
#   conditions  - dict of field -> regex/range checks
#   attack_type - likely CICIDS event label
#   tactic      - MITRE ATT&CK tactic
#   technique   - MITRE technique ID
#   confidence  - base confidence boost (0.0–1.0)
# ---------------------------------------------------------------------------

SIGMA_RULES: List[Dict[str, Any]] = [
    # ── Denial-of-Service ─────────────────────────────────────────────────
    {
        "name": "High-Rate TCP Flood (DoS/DDoS)",
        "description": "Detects abnormally high packet rate indicating a flood attack.",
        "conditions": {
            "flow_bytes_per_sec": {"min": 50_000},
            "event_type_pattern": r"dos|ddos|flood|hulk|goldeneve|slowloris|slowhttp",
        },
        "attack_type": "DoS",
        "tactic": "Impact",
        "technique": "T1499.002",
        "confidence": 0.90,
    },
    {
        "name": "Slow HTTP DoS (Slowloris/Slowhttptest)",
        "description": "Long-duration low-bandwidth flow suggesting slow HTTP DoS.",
        "conditions": {
            "flow_duration": {"min": 300_000},
            "flow_bytes_per_sec": {"max": 500},
            "event_type_pattern": r"slowloris|slowhttp",
        },
        "attack_type": "DoS Slowloris",
        "tactic": "Impact",
        "technique": "T1499.002",
        "confidence": 0.85,
    },
    # ── Port Scanning ─────────────────────────────────────────────────────
    {
        "name": "Horizontal Port Scan",
        "description": "Rapid SYN packets to multiple ports indicating port scan.",
        "conditions": {
            "total_fwd_packets": {"min": 10},
            "total_backward_packets": {"max": 3},
            "event_type_pattern": r"portscan|port.?scan|nmap",
        },
        "attack_type": "PortScan",
        "tactic": "Discovery",
        "technique": "T1046",
        "confidence": 0.88,
    },
    # ── Web Attacks ────────────────────────────────────────────────────────
    {
        "name": "SQL Injection Attempt",
        "description": "SQL keywords in payload indicate SQL injection attack.",
        "conditions": {
            "payload_pattern": r"union\s+select|or\s+1=1|'\s*--|\bexec\s*\(|drop\s+table",
            "event_type_pattern": r"sql.injection|sqli",
        },
        "attack_type": "SQL Injection",
        "tactic": "Initial Access",
        "technique": "T1190",
        "confidence": 0.92,
    },
    {
        "name": "XSS Injection Attempt",
        "description": "Script tags or JS event handlers in payload.",
        "conditions": {
            "payload_pattern": r"<script[^>]*>|javascript:|onerror=|onload=|alert\s*\(",
            "event_type_pattern": r"xss|cross.site",
        },
        "attack_type": "XSS",
        "tactic": "Execution",
        "technique": "T1059.007",
        "confidence": 0.88,
    },
    # ── Credential Attacks ────────────────────────────────────────────────
    {
        "name": "Brute Force Login",
        "description": "High failed-login count from single IP.",
        "conditions": {
            "total_fwd_packets": {"min": 20},
            "event_type_pattern": r"brute.force|brute_force|login.fail|password.attempt",
        },
        "attack_type": "Brute Force",
        "tactic": "Credential Access",
        "technique": "T1110.001",
        "confidence": 0.85,
    },
    # ── Bot / C2 Activity ─────────────────────────────────────────────────
    {
        "name": "Bot / C2 Beacon",
        "description": "Regular periodic traffic pattern consistent with bot C2.",
        "conditions": {
            "event_type_pattern": r"\bbot\b|c2|command.and.control|beacon",
        },
        "attack_type": "Bot",
        "tactic": "Execution",
        "technique": "T1059",
        "confidence": 0.80,
    },
    # ── Heartbleed ────────────────────────────────────────────────────────
    {
        "name": "Heartbleed TLS Exploit",
        "description": "Abnormal TLS heartbeat indicating Heartbleed exploitation.",
        "conditions": {
            "destination_port": {"values": [443, 8443]},
            "event_type_pattern": r"heartbleed|heartbeat",
        },
        "attack_type": "Heartbleed",
        "tactic": "Initial Access",
        "technique": "T1190",
        "confidence": 0.92,
    },
    # ── Infiltration ─────────────────────────────────────────────────────
    {
        "name": "Lateral Movement / Infiltration",
        "description": "Internal host accessing many other internal hosts.",
        "conditions": {
            "event_type_pattern": r"infiltrat|lateral.movement|pivot",
        },
        "attack_type": "Infiltration",
        "tactic": "Lateral Movement",
        "technique": "T1055",
        "confidence": 0.80,
    },
    # ── Benign Baseline ────────────────────────────────────────────────────
    {
        "name": "Normal Traffic Baseline",
        "description": "Traffic matches benign baseline patterns.",
        "conditions": {
            "event_type_pattern": r"^benign$",
        },
        "attack_type": "BENIGN",
        "tactic": "None",
        "technique": "T0000",
        "confidence": 0.95,
    },
]


# ---------------------------------------------------------------------------
# Matching engine
# ---------------------------------------------------------------------------

class SigmaMatcher:
    """Lightweight Sigma rule engine for SENTINEL-AI triage enrichment."""

    def __init__(self) -> None:
        self._compiled_rules = self._compile_rules()
        logger.info("SigmaMatcher initialised with %d rules", len(self._compiled_rules))

    def _compile_rules(self) -> List[Dict[str, Any]]:
        compiled: List[Dict[str, Any]] = []
        for rule in SIGMA_RULES:
            r = dict(rule)
            cond = dict(r.get("conditions", {}))
            if "payload_pattern" in cond:
                cond["_payload_re"] = re.compile(cond["payload_pattern"], re.IGNORECASE)
            if "event_type_pattern" in cond:
                cond["_event_re"] = re.compile(cond["event_type_pattern"], re.IGNORECASE)
            r["_compiled_conditions"] = cond
            compiled.append(r)
        return compiled

    def _check_condition(self, cond: Dict[str, Any], alert: Dict[str, Any]) -> bool:
        """Return True only if ALL conditions in the rule match the alert."""
        for key, check in cond.items():
            if key.startswith("_"):  # compiled regex objects
                continue

            if key == "payload_pattern":
                re_obj = cond.get("_payload_re")
                payload = str(alert.get("raw_payload", ""))
                if re_obj and not re_obj.search(payload):
                    return False

            elif key == "event_type_pattern":
                re_obj = cond.get("_event_re")
                event_type = str(alert.get("event_type", ""))
                if re_obj and not re_obj.search(event_type):
                    return False

            elif key == "destination_port":
                port = alert.get("destination_port")
                if port is not None and "values" in check:
                    if int(port) not in check["values"]:
                        return False

            elif key in ("flow_duration", "flow_bytes_per_sec",
                         "total_fwd_packets", "total_backward_packets"):
                value = alert.get(key)
                if value is None:
                    continue  # missing numeric field → skip this sub-check
                value = float(value)
                if "min" in check and value < check["min"]:
                    return False
                if "max" in check and value > check["max"]:
                    return False

        return True

    def match(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run all Sigma rules against *alert* and return matched rules (unsorted).

        Returns a list of dicts: {name, description, attack_type, tactic,
                                   technique, confidence}
        """
        matches: List[Dict[str, Any]] = []
        for rule in self._compiled_rules:
            cond = rule.get("_compiled_conditions", {})
            if self._check_condition(cond, alert):
                matches.append(
                    {
                        "rule_name": rule["name"],
                        "description": rule["description"],
                        "attack_type": rule["attack_type"],
                        "tactic": rule["tactic"],
                        "technique": rule["technique"],
                        "confidence": rule["confidence"],
                    }
                )
        return matches

    def best_match(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return the highest-confidence matching rule, or None if no match."""
        matches = self.match(alert)
        if not matches:
            return None
        return max(matches, key=lambda m: m["confidence"])

    def summarise(self, alert: Dict[str, Any]) -> str:
        """Return a one-line triage hint string for the Triage Agent ReAct loop."""
        matches = self.match(alert)
        if not matches:
            return "No Sigma rules matched. Treat as unknown activity."
        names = [m["rule_name"] for m in matches]
        best = max(matches, key=lambda m: m["confidence"])
        return (
            f"Sigma matched {len(matches)} rule(s): {', '.join(names)}. "
            f"Best match: '{best['rule_name']}' "
            f"(tactic={best['tactic']}, technique={best['technique']}, "
            f"confidence={best['confidence']:.0%})"
        )


# ---------------------------------------------------------------------------
# Module-level singleton for cheap import
# ---------------------------------------------------------------------------
_matcher: Optional[SigmaMatcher] = None


def get_matcher() -> SigmaMatcher:
    global _matcher
    if _matcher is None:
        _matcher = SigmaMatcher()
    return _matcher


def sigma_match(alert: Dict[str, Any]) -> str:
    """
    Convenience function: run Sigma rules against *alert* and return a
    human-readable summary string for use in the Triage Agent's ReAct prompt.
    """
    return get_matcher().summarise(alert)
