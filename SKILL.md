---
name: operator-anti-pattern-scanner
description:
  "Kubernetes operator cache & memory anti-pattern scanner for Kanban workers. Clones a Go
  operator repository, runs ripgrep and optional semgrep SAST rules to detect 10 known
  controller-runtime anti-patterns that cause OOMKill, memory bloat, and security
  vulnerabilities. Outputs structured JSON findings via kanban_complete."
version: 1.0.0
author: agent
license: MIT
metadata:
  hermes:
    tags: [kubernetes, operator, security, oom, controller-runtime, golang, sast, kanban]
---

# Operator Anti-Pattern Scanner — Kanban Worker Skill

You are a Kubernetes operator security analyst running as a Kanban worker. Your job is to scan
Go-based operator repositories for 10 known controller-runtime anti-patterns that cause
OOMKill, memory bloat, and cluster-wide vulnerabilities.

Sources:
- "5 anti-patterns that cause Kubernetes operator vulnerabilities" (Red Hat, 2026-07-06)
- "Protect your Kubernetes Operator from OOMKill" (Red Hat, 2026-06-01)

---

## Step 0: Receive the Target Repository

The kanban task payload provides the repository to scan:

```json
{
  "repo_url": "https://github.com/org/my-operator",
  "ref": "main",
  "scan_depth": "full"
}
```

Clone the repository (shallow clone is fine). If `ref` is provided, check out that ref.
If the repository is not a Go project using controller-runtime, call `kanban_complete` with
`"result": "skipped"` and reason `"Not a controller-runtime operator"`.

Verify it's an operator by checking for:
- `go.mod` importing `sigs.k8s.io/controller-runtime`
- Files containing `ctrl.NewManager` or `manager.New`

---

## Step 1: Run the Scanner

Execute `scan-operator-antipatterns.sh` against the cloned repo:

```bash
./scan-operator-antipatterns.sh /path/to/cloned/repo
```

The script detects these 10 anti-patterns using ripgrep:

### Category A: Cache & Informer Anti-Patterns (from "5 anti-patterns")

| ID   | Anti-Pattern | Risk |
|------|-------------|------|
| AP-1 | Predicate filters don't limit cache | Memory bloat: predicates filter events, not what the informer caches |
| AP-2 | DisableFor doesn't affect Owns/Watches informers | False safety: DisableFor only affects client.Get/List, not informers from Owns()/Watches() |
| AP-3 | Invisible informer from client.Get() | Hidden cluster-wide informer created silently on first cached Get for unregistered type |
| AP-4 | No DefaultNamespaces — everything is cluster-wide | All informers watch all namespaces by default |
| AP-5 | Typed/unstructured cache trap | Mismatched object representations cause duplicate caches or wasted memory |

### Category B: OOMKill Anti-Patterns (from "Protect your Operator from OOMKill")

| ID   | Anti-Pattern | Risk |
|------|-------------|------|
| AP-6 | Unfiltered ByObject entries (empty `{}`) | Caches ALL objects of that type cluster-wide — OOMKill vector |
| AP-7 | Operator-created resources missing cache labels | Resources created by the operator become invisible to filtered cache |
| AP-8 | No upgrade path for pre-existing unlabeled resources | Filtered cache can't see old resources — reconciliation loop |
| AP-9 | Labels not propagated during resource updates | Label can be lost on update, making resource invisible to cache |
| AP-10 | No DefaultTransform to strip managedFields | Every cached object carries ~2-5KB of managedFields metadata bloat |

---

## Step 2: Run SAST Analysis (if semgrep available)

If `semgrep` is installed, run the custom rules for deeper structural analysis:

```bash
semgrep --config .semgrep-operator-antipatterns.yml /path/to/cloned/repo --json
```

Semgrep provides AST-level detection that catches patterns ripgrep cannot:
- Matching `Owns()` types against `DisableFor` types
- Detecting `client.Get()` calls on types not registered in `ByObject` or `DisableFor`
- Finding `ObjectMeta{}` without labels in resource creation

---

## Step 3: Analyze and Classify Findings

For each finding:

1. **Severity**: CRITICAL (AP-3, AP-6), HIGH (AP-1, AP-2, AP-4, AP-5), MEDIUM (AP-7, AP-9, AP-10), LOW (AP-8)
2. **Confidence**: HIGH (exact pattern match), MEDIUM (heuristic match), LOW (contextual inference)
3. **File and line**: Exact location from rg/semgrep output
4. **Recommendation**: Specific fix from the articles

Cross-reference findings:
- If AP-6 is found (unfiltered ByObject), check if AP-7 would apply after fixing it
- If AP-2 is found (DisableFor + Owns), verify which types overlap
- If AP-1 is found (predicates), check if a label selector exists in ByObject for the same type

---

## Step 4: Complete the Task

Call `kanban_complete` with a summary and structured metadata:

**Summary**: "Scanned {repo}. Found {N} anti-patterns: {X} CRITICAL, {Y} HIGH, {Z} MEDIUM."

**Metadata** (structured JSON):

```json
{
  "repo_url": "https://github.com/org/my-operator",
  "ref": "main",
  "scan_date": "2026-07-07",
  "scanner_version": "1.0.0",
  "tools_used": ["ripgrep", "semgrep"],
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
      "description": "ByObject entry for ConfigMap has no label selector — caches ALL ConfigMaps cluster-wide. An attacker can create 700x 900KB ConfigMaps to OOMKill the operator.",
      "recommendation": "Add a label selector: &corev1.ConfigMap{}: { Label: labels.SelectorFromSet(labels.Set{\"app.kubernetes.io/managed-by\": \"my-operator\"}) }"
    }
  ],
  "anti_pattern_coverage": {
    "AP-1": {"detected": false, "scanned": true},
    "AP-2": {"detected": true, "scanned": true},
    "AP-3": {"detected": false, "scanned": true},
    "AP-4": {"detected": true, "scanned": true},
    "AP-5": {"detected": false, "scanned": true},
    "AP-6": {"detected": true, "scanned": true},
    "AP-7": {"detected": false, "scanned": true},
    "AP-8": {"detected": false, "scanned": true},
    "AP-9": {"detected": false, "scanned": true},
    "AP-10": {"detected": true, "scanned": true}
  },
  "source": "hermes-kanban"
}
```

---

## Anti-Pattern Detection Reference

### AP-1: Predicate Filters Don't Limit Cache

**What to look for**: `builder.WithPredicates` or `WithEventFilter` on `Watches()` calls where
the developer thinks predicate filtering limits what gets cached.

**Why it's dangerous**: Predicates operate between the informer and the work queue — they control
which events reach the reconciler, not what the informer stores. The informer still performs a
full LIST and WATCH on every object of that type cluster-wide.

**Fix**: For occasional reads, replace `Watches()` with a direct API call via `mgr.GetAPIReader()`.
If real-time events are needed, apply a label selector in the `ByObject` cache configuration.

### AP-2: DisableFor Doesn't Affect Owns/Watches Informers

**What to look for**: A type listed in `DisableFor` that also appears in `Owns()` or `Watches()`.

**Why it's dangerous**: `DisableFor` only affects `client.Get()` and `client.List()` reads. The
`Owns()` and `Watches()` calls create completely independent informers that `DisableFor` cannot touch.

**Fix**: If `Owns()` is only for garbage collection, remove it — owner references handle cleanup
without informers. If drift detection is needed, add a label selector in `ByObject`.

### AP-3: Invisible Informer from client.Get()

**What to look for**: `r.Client.Get()` or `r.Get()` calls for types not registered in `ByObject`
and not listed in `DisableFor`. On first call, the cached client creates an on-the-fly
cluster-wide informer.

**Why it's dangerous**: Completely invisible during code review. No `Watches()` or `Owns()` call —
just a normal `Get()`. One audited operator had label selectors on nine resource types but omitted
Secrets — a single `client.Get()` triggered an unfiltered cluster-wide Secret informer.

**Fix**: Add every type that the reconciler reads via `client.Get()`/`client.List()` to `DisableFor`,
or register it in `ByObject` with a label selector.

### AP-4: No DefaultNamespaces

**What to look for**: `cache.Options` without `DefaultNamespaces` set. Every informer watches all
namespaces by default.

**Why it's dangerous**: Even if an operator only manages resources in 5 namespaces, its informers
watch all 500 namespaces on the cluster.

**Fix**: For single-namespace operators, set `DefaultNamespaces`. For multi-namespace operators,
use label selectors in `ByObject`.

### AP-5: Typed/Unstructured Cache Trap

**What to look for**: Watches using typed objects (`&corev1.ConfigMap{}`) but reads using
`unstructured.Unstructured{}`. These hit completely separate caches.

**Why it's dangerous**: The typed cache stores every matching object at full size but none of those
cached objects serve unstructured reads — pure waste. Worse, the unstructured read might create a
second separate cache, doubling memory consumption.

**Fix**: Use `WatchesMetadata()` if you only need triggers. Otherwise ensure watch and read use the
same representation.

### AP-6: Unfiltered ByObject Entries

**What to look for**: `ByObject` entries with empty `{}` — e.g., `&corev1.ConfigMap{}: {}`.

**Why it's dangerous**: Directs the informer to cache ALL objects of that type cluster-wide. 700
ConfigMaps at 900KB each = 630MB, exceeding typical 512MiB limits. Any user with the `edit`
ClusterRole can trigger this — it's a low-barrier DoS vector.

**Fix**: Add a label selector to every `ByObject` entry.

### AP-7: Operator-Created Resources Missing Cache Labels

**What to look for**: `ObjectMeta{}` in resource creation (`&corev1.ConfigMap{ObjectMeta: ...}`)
where the Labels map doesn't include the label used in the ByObject filter.

**Why it's dangerous**: After adding label filters to the cache, the operator's own resources become
invisible to the filtered cache if they lack the required label.

**Fix**: Always include the filtering label when creating resources.

### AP-8: No Upgrade Path for Pre-existing Resources

**What to look for**: Absence of `errors.IsAlreadyExists` handling with a merge patch fallback when
creating resources. After deploying a label-filtered cache, pre-existing unlabeled resources cause
`client.Get()` → NotFound but `client.Create()` → AlreadyExists.

**Fix**: Use `client.MergeFrom(base)` patch as a fallback when `Create` returns `AlreadyExists`.

### AP-9: Labels Not Propagated During Updates

**What to look for**: `r.Update(ctx, obj)` calls where the obj's Labels map isn't checked or set
before the update.

**Fix**: Always ensure `obj.Labels` is non-nil and contains the required filter label before calling
`Update`.

### AP-10: No DefaultTransform to Strip managedFields

**What to look for**: Absence of `cache.TransformStripManagedFields()` in the cache configuration.

**Why it's dangerous**: Every cached object carries ~2-5KB of `managedFields` metadata that operators
almost never need. Across thousands of objects, this adds significant memory overhead.

**Fix**: Add `DefaultTransform: cache.TransformStripManagedFields()` to `cache.Options`.
