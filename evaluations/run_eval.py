#!/usr/bin/env python3
"""Run operator anti-pattern scanner evaluation.

Usage:
    python evaluations/run_eval.py                    # Run against testdata/
    python evaluations/run_eval.py --fixture /path    # Run against custom fixture
    python evaluations/run_eval.py --json             # JSON output
    python evaluations/run_eval.py --verbose          # Show per-case details
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from datasets import TRUE_POSITIVE_CASES, TRUE_NEGATIVE_CASES
from scorers import run_scanner, score_true_positive, score_true_negative, compute_summary


def main():
    parser = argparse.ArgumentParser(description="Operator Anti-Pattern Scanner Eval")
    parser.add_argument("--fixture", default=None, help="Path to fixture directory (default: testdata/)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="JSON output")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    repo_root = Path(__file__).parent.parent
    fixture_dir = args.fixture or str(repo_root / "testdata")

    print(f"Scanning: {fixture_dir}")
    print("Running scanner...")
    scan_results = run_scanner(fixture_dir)

    if "error" in scan_results:
        print(f"ERROR: Scanner failed: {scan_results['error']}", file=sys.stderr)
        sys.exit(1)

    findings = scan_results.get("findings", [])
    print(f"Scanner returned {len(findings)} findings\n")

    # Score true positives
    tp_scores = []
    for case in TRUE_POSITIVE_CASES:
        score = score_true_positive(case, scan_results)
        tp_scores.append(score)

    # Score true negatives
    tn_scores = []
    for case in TRUE_NEGATIVE_CASES:
        score = score_true_negative(case, scan_results)
        tn_scores.append(score)

    summary = compute_summary(tp_scores, tn_scores)

    if args.json_output:
        output = {
            "fixture_dir": fixture_dir,
            "scan_results": scan_results,
            "true_positive_scores": tp_scores,
            "true_negative_scores": tn_scores,
            "summary": summary,
        }
        print(json.dumps(output, indent=2))
        return

    # Text output
    print("=" * 70)
    print("  OPERATOR ANTI-PATTERN SCANNER EVALUATION")
    print("=" * 70)

    print("\n--- True Positives (should detect) ---")
    for s in tp_scores:
        status = "PASS" if s["detected"] else "FAIL"
        sev = "sev-ok" if s["severity_correct"] else "sev-wrong"
        marker = "marker-ok" if s["marker_found"] else "marker-miss"
        print(f"  [{status}] {s['case_id']:40s}  {s['expected_ap']}  {sev}  {marker}")

        if args.verbose and not s["detected"]:
            print(f"         Expected {s['expected_ap']} but scanner did not detect it")

    print("\n--- True Negatives (should NOT detect) ---")
    for s in tn_scores:
        status = "PASS" if s["false_positives"] == 0 else "FAIL"
        print(f"  [{status}] {s['case_id']:40s}  FPs: {s['false_positives']}")

        if args.verbose and s["false_positives"] > 0:
            for d in s["details"]:
                print(f"         False positive: {d['id']} at {d['file']}:{d['line']}")

    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  Overall score:       {summary['overall_score']:.1%}")
    print(f"  Detection rate:      {summary['detection_rate']:.1%}  ({summary['true_positives']})")
    print(f"  Severity accuracy:   {summary['severity_accuracy']:.1%}")
    print(f"  False positive rate: {summary['false_positive_rate']:.1%}  ({summary['true_negatives']} clean)")
    print(f"  Total FPs:           {summary['total_false_positives']}")
    print("=" * 70)

    if summary["detection_rate"] < 0.7:
        print("\nWARNING: Detection rate below 70% — scanner needs improvement")
        sys.exit(1)
    elif summary["overall_score"] >= 0.9:
        print("\nScanner performance: EXCELLENT")
    elif summary["overall_score"] >= 0.7:
        print("\nScanner performance: GOOD")
    else:
        print("\nScanner performance: NEEDS WORK")


if __name__ == "__main__":
    main()
