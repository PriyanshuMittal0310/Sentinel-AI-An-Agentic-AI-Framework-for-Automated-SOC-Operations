"""
Evaluation Metrics — SENTINEL-AI Phase 2

Computes triage accuracy metrics from an evaluation CSV produced by run_eval.py.

Metrics reported:
  - Per-class precision, recall, F1
  - Macro-averaged F1 (primary target ≥ 0.75)
  - Overall accuracy
  - Mean alert processing time
  - Context source breakdown (chromadb vs fallback)

Usage:
    python evaluation/metrics.py                       # reads default CSV
    python evaluation/metrics.py path/to/custom.csv    # custom CSV path
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Any

# ── Severity label definitions ─────────────────────────────────────────────
SEVERITY_LABELS = ["P1", "P2", "P3", "P4"]

# Ground-truth severity mapping for CICIDS event labels
# (mirrors TriageAgent.severity_map so we can compute true_severity for rows
#  that have the event_type but no explicit true_severity column)
_LABEL_TO_SEVERITY: Dict[str, str] = {
    "BENIGN": "P4",
    "DoS Hulk": "P1",
    "DoS GoldenEye": "P1",
    "DoS slowloris": "P1",
    "DoS Slowhttptest": "P1",
    "DDoS": "P1",
    "PortScan": "P2",
    "Brute Force -Web": "P2",
    "Brute Force -XSS": "P2",
    "SQL Injection": "P1",
    "Web Attack - Sql Injection": "P1",
    "Web Attack - Brute Force": "P2",
    "Web Attack - XSS": "P2",
    "Infiltration": "P1",
    "Bot": "P2",
    "Heartbleed": "P1",
}


# ---------------------------------------------------------------------------
# Core metric computation
# ---------------------------------------------------------------------------

def _confusion(y_true: List[str], y_pred: List[str]) -> Dict[str, Dict[str, int]]:
    """Build per-class TP/FP/FN counts."""
    counts: Dict[str, Dict[str, int]] = {
        cls: {"tp": 0, "fp": 0, "fn": 0} for cls in SEVERITY_LABELS
    }
    for true, pred in zip(y_true, y_pred):
        for cls in SEVERITY_LABELS:
            if true == cls and pred == cls:
                counts[cls]["tp"] += 1
            elif true != cls and pred == cls:
                counts[cls]["fp"] += 1
            elif true == cls and pred != cls:
                counts[cls]["fn"] += 1
    return counts


def compute_metrics(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute all evaluation metrics from a list of result row dicts.

    Each row must have keys: 'severity' (predicted), 'true_severity' or
    'event_type' (to derive ground truth), optionally 'processing_time_seconds'
    and 'context_source'.
    """
    y_pred: List[str] = []
    y_true: List[str] = []
    times: List[float] = []
    source_counts: Dict[str, int] = defaultdict(int)

    skipped = 0
    for row in rows:
        pred = str(row.get("severity", "")).strip()

        # Determine ground truth
        true_sev = str(row.get("true_severity", "")).strip()
        if not true_sev or true_sev == "nan":
            event_type = str(row.get("event_type", "")).strip()
            true_sev = _LABEL_TO_SEVERITY.get(event_type, "")

        if pred not in SEVERITY_LABELS or true_sev not in SEVERITY_LABELS:
            skipped += 1
            continue

        y_pred.append(pred)
        y_true.append(true_sev)

        try:
            times.append(float(row.get("processing_time_seconds", 0) or 0))
        except (ValueError, TypeError):
            pass

        src = str(row.get("context_source", "unknown")).strip()
        source_counts[src] += 1

    n = len(y_true)
    if n == 0:
        return {"error": "No valid rows with matching severity labels found."}

    # Accuracy
    correct = sum(t == p for t, p in zip(y_true, y_pred))
    accuracy = correct / n

    # Per-class precision / recall / F1
    confusion = _confusion(y_true, y_pred)
    per_class: Dict[str, Dict[str, float]] = {}
    f1_scores: List[float] = []
    for cls in SEVERITY_LABELS:
        tp = confusion[cls]["tp"]
        fp = confusion[cls]["fp"]
        fn = confusion[cls]["fn"]
        total_true = sum(1 for t in y_true if t == cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        per_class[cls] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": total_true,
        }
        if total_true > 0:
            f1_scores.append(f1)

    macro_f1 = sum(f1_scores) / len(f1_scores) if f1_scores else 0.0
    mean_time = sum(times) / len(times) if times else 0.0

    return {
        "n_evaluated": n,
        "n_skipped": skipped,
        "accuracy": round(accuracy, 4),
        "macro_f1": round(macro_f1, 4),
        "per_class": per_class,
        "mean_processing_time_s": round(mean_time, 4),
        "context_source_counts": dict(source_counts),
        "target_met": macro_f1 >= 0.75,
    }


# ---------------------------------------------------------------------------
# Report formatter
# ---------------------------------------------------------------------------

def print_report(metrics: Dict[str, Any]) -> None:
    """Pretty-print the metrics to stdout."""
    if "error" in metrics:
        print(f"❌ Metrics error: {metrics['error']}")
        return

    n = metrics["n_evaluated"]
    acc = metrics["accuracy"]
    f1 = metrics["macro_f1"]
    target = metrics["target_met"]
    mean_t = metrics["mean_processing_time_s"]

    banner = "SENTINEL-AI Phase 2 — Triage Evaluation Report"
    print("\n" + "=" * 60)
    print(banner)
    print("=" * 60)
    print(f"  Alerts evaluated  : {n}  (skipped: {metrics['n_skipped']})")
    print(f"  Overall Accuracy  : {acc:.1%}")
    print(f"  Macro-avg F1      : {f1:.4f}  {'✅ TARGET MET (≥0.75)' if target else '❌ Below target (0.75)'}")
    print(f"  Mean Process Time : {mean_t:.3f}s / alert")
    print()
    print("  Per-class Metrics:")
    print(f"  {'Class':<6} {'Precision':>10} {'Recall':>8} {'F1':>8} {'Support':>8}")
    print("  " + "-" * 44)
    for cls in SEVERITY_LABELS:
        pc = metrics["per_class"].get(cls, {})
        print(
            f"  {cls:<6} {pc.get('precision', 0):>10.4f} "
            f"{pc.get('recall', 0):>8.4f} "
            f"{pc.get('f1', 0):>8.4f} "
            f"{pc.get('support', 0):>8}"
        )
    print()
    print("  Context Source Breakdown:")
    for src, count in metrics.get("context_source_counts", {}).items():
        print(f"    {src}: {count} alerts")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# CSV reader
# ---------------------------------------------------------------------------

def load_csv(csv_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(dict(row))
    return rows


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def run(csv_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Compute and print metrics from *csv_path*.
    If csv_path is None, defaults to evaluation/results/phase2_50_alerts.csv.
    """
    if csv_path is None:
        csv_path = (
            Path(__file__).resolve().parent
            / "results"
            / "phase2_50_alerts.csv"
        )

    if not csv_path.exists():
        print(f"❌ CSV not found: {csv_path}")
        return {}

    rows = load_csv(csv_path)
    metrics = compute_metrics(rows)
    print_report(metrics)
    return metrics


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    result = run(path)
    if result.get("target_met"):
        sys.exit(0)
    else:
        sys.exit(1)
