"""
Phase 2 evaluation runner.

Runs the Guardrail -> Triage -> Context pipeline over 50 alerts from the
CICIDS2017 processed dataset, writes a CSV log, and computes triage accuracy
metrics (target: macro-F1 ≥ 0.75).
"""

import csv
import json
from pathlib import Path
from typing import List, Dict, Any
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.graph import SentinelAIGraph
from evaluation.metrics import compute_metrics, print_report


def load_alerts(alert_file: Path) -> List[Dict[str, Any]]:
    with alert_file.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Expected alert JSON file to contain a list")
    return data


def run_phase2_eval(sample_size: int = 50) -> Path:
    project_root = Path(__file__).resolve().parent.parent
    input_file = project_root / "data" / "processed" / "cicids_alerts.json"
    output_file = project_root / "evaluation" / "results" / "phase2_50_alerts.csv"

    alerts = load_alerts(input_file)[:sample_size]
    graph = SentinelAIGraph()

    rows: List[Dict[str, Any]] = []
    for alert in alerts:
        result = graph.process_alert(alert)
        top_technique = ""
        techniques = result.get("retrieved_techniques") or []
        if techniques:
            top_technique = techniques[0].get("technique_id", "")

        rows.append(
            {
                "alert_id": result.get("alert_id", ""),
                "event_type": result.get("event_type", ""),
                "source_ip": result.get("source_ip", ""),
                # Ground truth (from cicids_alerts.json — available for evaluation)
                "true_severity": alert.get("true_severity", ""),
                # Predicted output from Triage Agent
                "severity": result.get("severity", ""),
                "mitre_tactic": result.get("mitre_tactic", ""),
                "mitre_technique": result.get("mitre_technique", ""),
                "top_retrieved_technique": top_technique,
                "confidence": result.get("confidence", ""),
                "context_source": (result.get("context_metadata") or {}).get("source", ""),
                "processing_time_seconds": result.get("processing_time_seconds", ""),
                "sigma_hint": result.get("sigma_hint", ""),
            }
        )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            writer.writeheader()
            writer.writerows(rows)

    print(f"\nPhase 2 evaluation CSV written to: {output_file}")

    # Compute and display accuracy metrics
    metrics = compute_metrics(rows)
    print_report(metrics)

    return output_file


if __name__ == "__main__":
    out = run_phase2_eval(sample_size=50)

