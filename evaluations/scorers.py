"""Scorers for the operator anti-pattern scanner evaluation.

Measures scanner accuracy across three dimensions:
1. Detection rate (true positives)
2. False positive rate (true negatives)
3. Severity accuracy
"""

import json
import subprocess
from pathlib import Path


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def run_scanner(fixture_dir: str) -> dict:
    """Run the scanner and return parsed JSON results."""
    script = Path(__file__).parent.parent / "scan-operator-antipatterns.sh"
    result = subprocess.run(
        [str(script), fixture_dir, "--json"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0 and not result.stdout:
        return {"findings": [], "error": result.stderr}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"findings": [], "parse_error": result.stdout[:500]}


def score_true_positive(case: dict, scan_results: dict) -> dict:
    """Score a true-positive case: did the scanner detect the expected anti-pattern?"""
    expected_ap = case["expectations"]["expected_ap"]
    min_severity = case["expectations"]["min_severity"]
    code_marker = case["expectations"].get("code_marker", "")

    findings = scan_results.get("findings", [])
    matching = [f for f in findings if f.get("id") == expected_ap]

    detected = len(matching) > 0
    severity_ok = False
    marker_ok = False

    if matching:
        best = max(matching, key=lambda f: SEVERITY_RANK.get(f.get("severity", ""), 0))
        actual_sev = SEVERITY_RANK.get(best.get("severity", ""), 0)
        expected_sev = SEVERITY_RANK.get(min_severity, 0)
        severity_ok = actual_sev >= expected_sev

        if code_marker:
            marker_ok = any(
                code_marker.lower() in str(f.get("code_snippet", "")).lower() or
                code_marker.lower() in str(f.get("description", "")).lower()
                for f in matching
            )
        else:
            marker_ok = True

    return {
        "case_id": case["inputs"]["case_id"],
        "expected_ap": expected_ap,
        "detected": detected,
        "severity_correct": severity_ok,
        "marker_found": marker_ok,
        "score": 1.0 if (detected and severity_ok) else (0.5 if detected else 0.0),
        "findings_count": len(matching),
    }


def score_true_negative(case: dict, scan_results: dict) -> dict:
    """Score a true-negative case: did the scanner avoid false positives?"""
    forbidden_aps = case["expectations"].get("forbidden_aps", [])
    fixture = case["inputs"]["fixture"]

    findings = scan_results.get("findings", [])
    false_positives = []

    for f in findings:
        if f.get("id") in forbidden_aps:
            if fixture.split("/")[-1] in f.get("file", ""):
                false_positives.append(f)

    return {
        "case_id": case["inputs"]["case_id"],
        "forbidden_aps": forbidden_aps,
        "false_positives": len(false_positives),
        "score": 1.0 if len(false_positives) == 0 else 0.0,
        "details": [
            {"id": f["id"], "file": f.get("file"), "line": f.get("line")}
            for f in false_positives
        ],
    }


def compute_summary(tp_scores: list, tn_scores: list) -> dict:
    """Compute overall evaluation metrics."""
    tp_detected = sum(1 for s in tp_scores if s["detected"])
    tp_total = len(tp_scores)
    tp_severity_ok = sum(1 for s in tp_scores if s["severity_correct"])

    tn_clean = sum(1 for s in tn_scores if s["false_positives"] == 0)
    tn_total = len(tn_scores)
    total_fp = sum(s["false_positives"] for s in tn_scores)

    all_scores = [s["score"] for s in tp_scores] + [s["score"] for s in tn_scores]
    overall = sum(all_scores) / len(all_scores) if all_scores else 0.0

    return {
        "overall_score": round(overall, 3),
        "detection_rate": round(tp_detected / tp_total, 3) if tp_total else 0.0,
        "severity_accuracy": round(tp_severity_ok / tp_total, 3) if tp_total else 0.0,
        "false_positive_rate": round(1.0 - (tn_clean / tn_total), 3) if tn_total else 0.0,
        "true_positives": f"{tp_detected}/{tp_total}",
        "true_negatives": f"{tn_clean}/{tn_total}",
        "total_false_positives": total_fp,
    }
