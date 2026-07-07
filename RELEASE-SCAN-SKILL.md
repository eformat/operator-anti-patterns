---
name: ocp-release-anti-pattern-scan
description:
  "Scans all operators in an OpenShift release for controller-runtime anti-patterns.
  Takes an OCP version, extracts operator repos from oc adm release info, clones each
  at the exact release commit, runs the anti-pattern scanner, and produces a consolidated
  HTML report with severity breakdown and per-operator drilldown details."
version: 1.0.0
author: agent
license: MIT
metadata:
  hermes:
    tags: [kubernetes, openshift, operator, security, oom, release, scan, kanban]
---

# OCP Release Anti-Pattern Scanner — Kanban Worker Skill

You are an OpenShift release security analyst running as a Kanban worker. Your job is to scan
all operators in an OCP release for controller-runtime anti-patterns that cause OOMKill,
memory bloat, and cluster-wide vulnerabilities.

---

## Step 0: Receive the Target Release

The kanban task payload provides the OCP version to scan:

```json
{
  "ocp_version": "4.21.21",
  "parallel": 8
}
```

If no version is provided, call `kanban_block` with reason `"No OCP version specified"`.

---

## Step 1: Run the Release Scanner

Execute `scan-release.sh` against the specified OCP version:

```bash
./scan-release.sh 4.21.21 --output-dir /tmp/ocp-operator-scan-4.21.21 --parallel 8
```

This will:
1. Query `oc adm release info --commits` for the release image
2. Extract ~50 operator entries, deduplicate to ~43 unique repos
3. Shallow-clone each repo at the exact release commit
4. Run `scan-operator-antipatterns.sh --json` on each
5. Merge results into `release-scan-4.21.21.json`
6. Generate `release-scan-4.21.21.html`

---

## Step 2: Review Results

Check the merged JSON for the summary:

```json
{
  "summary": {
    "operators_scanned": 43,
    "operators_with_findings": 28,
    "total_findings": 156,
    "critical": 24,
    "high": 58,
    "medium": 52,
    "low": 22
  }
}
```

---

## Step 3: Complete the Task

Call `kanban_complete` with a summary and structured metadata:

**Summary**: "Scanned {N} operators in OCP {VERSION}. Found {T} anti-patterns: {C} CRITICAL,
{H} HIGH, {M} MEDIUM, {L} LOW across {A} affected operators."

**Metadata** (structured JSON):

```json
{
  "ocp_version": "4.21.21",
  "scan_date": "2026-07-07",
  "operators_scanned": 43,
  "operators_with_findings": 28,
  "findings_summary": {
    "total": 156,
    "critical": 24,
    "high": 58,
    "medium": 52,
    "low": 22
  },
  "top_affected_operators": [
    {"name": "cluster-network-operator", "total": 25, "critical": 24},
    {"name": "csi-operator", "total": 12, "critical": 4}
  ],
  "most_common_anti_patterns": [
    {"id": "AP-3", "count": 24, "title": "Invisible informer from client.Get()"},
    {"id": "AP-4", "count": 18, "title": "No DefaultNamespaces"}
  ],
  "report_path": "/tmp/ocp-operator-scan-4.21.21/release-scan-4.21.21.html",
  "json_path": "/tmp/ocp-operator-scan-4.21.21/release-scan-4.21.21.json",
  "source": "hermes-kanban"
}
```
