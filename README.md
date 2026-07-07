# Operator Anti-Pattern Scanner

Static analysis scanner that detects 10 controller-runtime anti-patterns known to cause OOMKill, memory bloat, and cluster-wide vulnerabilities in Kubernetes operators written in Go.

Based on two Red Hat articles:
- [5 anti-patterns that cause Kubernetes operator vulnerabilities](https://developers.redhat.com/articles/2026/07/06/5-anti-patterns-cause-kubernetes-operator-vulnerabilities) (2026-07-06)
- [Protect your Kubernetes Operator from OOMKill](https://developers.redhat.com/articles/2026/06/01/protect-your-kubernetes-operator-oomkill) (2026-06-01)

## Quick start

```bash
# Scan a local operator repo
make scan TARGET=/path/to/my-operator

# Scan a remote repo
make scan-repo REPO=https://github.com/org/my-operator

# JSON output
make scan-json TARGET=/path/to/my-operator
```

Requires: `rg` (ripgrep), `python3`. Optional: `semgrep` for AST-level detection.

## What it detects

### Cache & informer anti-patterns

| ID | Anti-Pattern | Severity | Detection |
|----|-------------|----------|-----------|
| AP-1 | **Predicate filters don't limit cache** — `WithPredicates`/`WithEventFilter` only filter events, not what the informer caches | HIGH | ripgrep + semgrep |
| AP-2 | **DisableFor doesn't affect Owns/Watches** — `DisableFor` only affects `client.Get`/`List`, not informers from `Owns()`/`Watches()` | HIGH | ripgrep + semgrep |
| AP-3 | **Invisible informer from client.Get()** — a plain `Get()` for an unregistered type silently creates a cluster-wide informer | CRITICAL | ripgrep + semgrep |
| AP-4 | **No DefaultNamespaces** — every informer watches all namespaces by default | HIGH | ripgrep |
| AP-5 | **Typed/unstructured cache trap** — mismatched object representations cause duplicate caches | HIGH | ripgrep + semgrep |

### OOMKill anti-patterns

| ID | Anti-Pattern | Severity | Detection |
|----|-------------|----------|-----------|
| AP-6 | **Unfiltered ByObject entries** — `&corev1.ConfigMap{}: {}` caches ALL ConfigMaps cluster-wide | CRITICAL | ripgrep + semgrep |
| AP-7 | **Operator-created resources missing cache labels** — resources invisible to filtered cache | MEDIUM | ripgrep + semgrep |
| AP-8 | **No upgrade path for pre-existing resources** — `Create()` without `IsAlreadyExists` fallback | LOW | ripgrep |
| AP-9 | **Labels not propagated during updates** — label lost on `Update()`, resource becomes invisible | MEDIUM | ripgrep + semgrep |
| AP-10 | **No DefaultTransform to strip managedFields** — ~2-5KB of metadata bloat per cached object | MEDIUM | ripgrep |

## Example: scanning cluster-network-operator

```
$ make scan TARGET=~/git/cluster-network-operator

========================================================================
  Operator Anti-Pattern Scanner v1.0.0
  Scanning: /home/mike/git/cluster-network-operator
========================================================================

[CRITICAL]  AP-3: Invisible informer from client.Get()
  File: pkg/apply/apply.go:168
  Code: err := cli.CRClient().Get(ctx, types.NamespacedName{...}, ret)
  Desc: client.Get()/List() for unstructured.Unstructured which is not in
        ByObject or DisableFor. On first call, the cached client silently
        creates a cluster-wide informer.
  Fix:  Add &unstructured.Unstructured{} to DisableFor to bypass cache.

  ... (24 CRITICAL AP-3 findings across 15 files) ...

[HIGH]  AP-4: No DefaultNamespaces — everything is cluster-wide
  File: pkg/operator/operator.go:66

========================================================================
  SUMMARY: 25 findings (24 CRITICAL, 1 HIGH)
========================================================================
```

## Release scanning

Scan **every operator** in an OpenShift release at the exact commit shipped in the release image:

```bash
# Scan all operators in OCP 4.21.21 (clones ~43 repos, runs scanner, generates HTML report)
make scan-release OCP_VERSION=4.21.21

# JSON only, no HTML
make scan-release-json OCP_VERSION=4.21.21

# Regenerate HTML from cached JSON (no re-clone or re-scan)
make release-report OCP_VERSION=4.21.21
```

Output goes to `/tmp/ocp-operator-scan-4.21.21/`:
- `release-scan-4.21.21.json` — aggregate JSON with all per-operator results
- `release-scan-4.21.21.html` — self-contained HTML report with drilldown details

The HTML report includes:
- Executive summary with severity cards
- Anti-pattern distribution heatmap across all operators
- Sortable operator table with finding counts
- Expandable per-operator details showing every finding with file, line, code snippet, and fix recommendation
- Client-side filtering by severity, anti-pattern ID, and operator name

The scanner deduplicates shared repos (e.g., `csi-operator` appears as 5 different components) and clones each at the exact commit SHA from the release.

## Usage

### Scan a local repo

```bash
./scan-operator-antipatterns.sh /path/to/operator      # text output
./scan-operator-antipatterns.sh /path/to/operator --json  # JSON output
./scan-operator-antipatterns.sh /path/to/operator --semgrep  # + semgrep SAST
```

### Makefile targets

```
make help                # show all targets

# Scanning
make scan TARGET=...     # scan local repo (text)
make scan-json TARGET=.. # scan local repo (JSON)
make scan-semgrep        # scan with semgrep SAST rules
make scan-repo REPO=...  # clone and scan a remote repo

# Release scanning
make scan-release        # scan all operators in OCP release (OCP_VERSION=4.21.21)
make scan-release-json   # release scan, JSON only
make release-report      # regenerate HTML from cached JSON

# Testing
make test                # full evaluation (15 test cases)
make test-quick          # smoke test (10/10 APs detected)
make eval-verbose        # eval with per-case details
make check-deps          # verify rg, python3, semgrep, etc.

# Container
make image-build         # build UBI9 container image
make image-run TARGET=.. # scan via container
make image-push          # push to registry

# Deploy (Hermes/OpenShift)
make deploy NAMESPACE=.. # deploy as Hermes kanban skill
make undeploy            # remove from cluster
```

### Container usage

```bash
make image-build
podman run --rm -v /path/to/operator:/repo:ro,Z \
  quay.io/$USER/operator-anti-pattern-scanner:latest /repo
```

### JSON output schema

```json
{
  "repo": "/path/to/operator",
  "scan_date": "2026-07-07T12:00:00Z",
  "scanner_version": "1.0.0",
  "tools_used": ["ripgrep"],
  "findings_summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  },
  "findings": [
    {
      "id": "AP-6",
      "title": "Unfiltered ByObject entry",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "file": "internal/controller/manager.go",
      "line": 42,
      "code_snippet": "&corev1.ConfigMap{}: {},",
      "description": "ByObject entry with empty config...",
      "recommendation": "Add a label selector..."
    }
  ],
  "anti_pattern_coverage": {
    "AP-1": {"detected": false, "scanned": true},
    "AP-2": {"detected": true, "scanned": true}
  }
}
```

## Semgrep SAST rules

The scanner uses ripgrep for fast pattern matching. For deeper AST-level analysis, 10 custom semgrep rules are included in `.semgrep-operator-antipatterns.yml`:

```bash
# Install semgrep
make install-semgrep

# Run with semgrep
make scan-semgrep TARGET=/path/to/operator

# Or standalone
semgrep --config .semgrep-operator-antipatterns.yml /path/to/operator
```

Semgrep catches patterns ripgrep cannot, such as matching types across `DisableFor` and `Owns()` declarations, or detecting `ObjectMeta{}` without a `Labels` field in resource creation.

## Evaluation

The scanner ships with a test suite: 10 true-positive cases (one per anti-pattern in `testdata/vulnerable_manager.go`) and 5 true-negative cases (correct patterns in `testdata/safe_manager.go`).

```
$ make eval

  OPERATOR ANTI-PATTERN SCANNER EVALUATION

  --- True Positives (should detect) ---
    [PASS] tp-ap1-predicate-false-safety   AP-1  sev-ok  marker-ok
    [PASS] tp-ap2-disable-for-owns         AP-2  sev-ok  marker-ok
    ...all 10 PASS...

  --- True Negatives (should NOT detect) ---
    [PASS] tn-safe-manager                 FPs: 0
    ...all 5 PASS...

  Overall score:       100.0%
  Detection rate:      100.0%  (10/10)
  False positive rate: 0.0%    (5/5 clean)

  Scanner performance: EXCELLENT
```

## Hermes kanban deployment

The scanner can run as a Hermes kanban worker skill. The `SKILL.md` defines the task interface: receive a repo URL, clone it, run the scan, and call `kanban_complete` with structured JSON findings.

```bash
make deploy NAMESPACE=hermes
```

This creates two ConfigMaps:
- `operator-anti-pattern-scanner-skill` — the SKILL.md
- `operator-anti-pattern-scanner-scripts` — the scanner script and semgrep rules

Mount them into the Hermes pod's skills directory.

## Project structure

```
.
├── scan-operator-antipatterns.sh     # Per-repo scanner (ripgrep-based)
├── scan-release.sh                   # Release scanner (clone + scan all operators)
├── generate-release-report.py        # HTML report generator
├── .semgrep-operator-antipatterns.yml # Semgrep SAST rules (10 rules)
├── SKILL.md                          # Hermes kanban skill (per-repo)
├── RELEASE-SCAN-SKILL.md            # Hermes kanban skill (release scan)
├── Makefile                          # Build, scan, test, deploy
├── Containerfile                     # UBI9 container image
├── evaluations/
│   ├── run_eval.py                   # Evaluation runner
│   ├── datasets.py                   # 15 test cases (10 TP + 5 TN)
│   └── scorers.py                    # Detection & false-positive scoring
└── testdata/
    ├── go.mod                        # Fake module for scanner validation
    ├── vulnerable_manager.go         # All 10 anti-patterns present
    └── safe_manager.go               # All fixes applied, zero findings
```

## Why these anti-patterns matter

A standard cluster user with the `edit` ClusterRole can create 700 ConfigMaps at 900KB each (630MB total). If an operator caches ConfigMaps without a label selector (AP-6), or creates an invisible informer via `client.Get()` (AP-3), this data is deserialized and held in memory — exceeding a typical 512MiB limit and triggering OOMKill.

These aren't theoretical: the articles document real-world incidents where production operators entered `CrashLoopBackOff` due to unfiltered caches. The patterns are systemic across the `controller-runtime` ecosystem because the defaults are maximally broad.
