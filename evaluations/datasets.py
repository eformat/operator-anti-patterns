"""Operator anti-pattern scanner evaluation dataset.

Each case is a Go code snippet (or repo fixture) plus expected findings.
The scanner should detect the expected anti-patterns and NOT flag the clean patterns.
"""

# True-positive cases: code that contains a specific anti-pattern.
# Each entry maps to one anti-pattern ID.
TRUE_POSITIVE_CASES = [
    {
        "inputs": {
            "case_id": "tp-ap1-predicate-false-safety",
            "fixture": "testdata/vulnerable_manager.go",
            "description": "Watches() with WithPredicates but no ByObject label selector",
        },
        "expectations": {
            "expected_ap": "AP-1",
            "should_detect": True,
            "min_severity": "HIGH",
            "code_marker": "WithPredicates",
        },
    },
    {
        "inputs": {
            "case_id": "tp-ap2-disable-for-owns",
            "fixture": "testdata/vulnerable_manager.go",
            "description": "Pod in DisableFor but also in Owns()",
        },
        "expectations": {
            "expected_ap": "AP-2",
            "should_detect": True,
            "min_severity": "HIGH",
            "code_marker": "Owns(&corev1.Pod{})",
        },
    },
    {
        "inputs": {
            "case_id": "tp-ap3-invisible-informer",
            "fixture": "testdata/vulnerable_manager.go",
            "description": "client.Get() for ServiceAccount not in ByObject or DisableFor",
        },
        "expectations": {
            "expected_ap": "AP-3",
            "should_detect": True,
            "min_severity": "CRITICAL",
            "code_marker": "ServiceAccount",
        },
    },
    {
        "inputs": {
            "case_id": "tp-ap4-no-default-namespaces",
            "fixture": "testdata/vulnerable_manager.go",
            "description": "cache.Options without DefaultNamespaces",
        },
        "expectations": {
            "expected_ap": "AP-4",
            "should_detect": True,
            "min_severity": "HIGH",
            "code_marker": "DefaultNamespaces",
        },
    },
    {
        "inputs": {
            "case_id": "tp-ap5-typed-unstructured-trap",
            "fixture": "testdata/vulnerable_manager.go",
            "description": "Watches typed ConfigMap but reads via unstructured.Unstructured",
        },
        "expectations": {
            "expected_ap": "AP-5",
            "should_detect": True,
            "min_severity": "HIGH",
            "code_marker": "unstructured.Unstructured",
        },
    },
    {
        "inputs": {
            "case_id": "tp-ap6-unfiltered-byobject",
            "fixture": "testdata/vulnerable_manager.go",
            "description": "ByObject entry with empty {} for ConfigMap",
        },
        "expectations": {
            "expected_ap": "AP-6",
            "should_detect": True,
            "min_severity": "CRITICAL",
            "code_marker": "&corev1.ConfigMap{}: {}",
        },
    },
    {
        "inputs": {
            "case_id": "tp-ap7-missing-label-create",
            "fixture": "testdata/vulnerable_manager.go",
            "description": "ObjectMeta without label matching ByObject selector",
        },
        "expectations": {
            "expected_ap": "AP-7",
            "should_detect": True,
            "min_severity": "MEDIUM",
            "code_marker": "ObjectMeta",
        },
    },
    {
        "inputs": {
            "case_id": "tp-ap8-no-upgrade-path",
            "fixture": "testdata/vulnerable_manager.go",
            "description": "Create() without IsAlreadyExists fallback",
        },
        "expectations": {
            "expected_ap": "AP-8",
            "should_detect": True,
            "min_severity": "LOW",
            "code_marker": "IsAlreadyExists",
        },
    },
    {
        "inputs": {
            "case_id": "tp-ap9-update-no-labels",
            "fixture": "testdata/vulnerable_manager.go",
            "description": "Update() without ensuring filter label is present",
        },
        "expectations": {
            "expected_ap": "AP-9",
            "should_detect": True,
            "min_severity": "MEDIUM",
            "code_marker": "Update(ctx",
        },
    },
    {
        "inputs": {
            "case_id": "tp-ap10-no-strip-managed-fields",
            "fixture": "testdata/vulnerable_manager.go",
            "description": "cache.Options without DefaultTransform: TransformStripManagedFields()",
        },
        "expectations": {
            "expected_ap": "AP-10",
            "should_detect": True,
            "min_severity": "MEDIUM",
            "code_marker": "TransformStripManagedFields",
        },
    },
]

# True-negative cases: clean code that should NOT trigger findings.
TRUE_NEGATIVE_CASES = [
    {
        "inputs": {
            "case_id": "tn-safe-manager",
            "fixture": "testdata/safe_manager.go",
            "description": "Correctly configured operator with all fixes applied",
        },
        "expectations": {
            "should_detect": False,
            "forbidden_aps": ["AP-1", "AP-5", "AP-6", "AP-7", "AP-8"],
        },
    },
    {
        "inputs": {
            "case_id": "tn-safe-default-namespaces",
            "fixture": "testdata/safe_manager.go",
            "description": "Manager with DefaultNamespaces configured",
        },
        "expectations": {
            "should_detect": False,
            "forbidden_aps": ["AP-4"],
        },
    },
    {
        "inputs": {
            "case_id": "tn-safe-strip-managed-fields",
            "fixture": "testdata/safe_manager.go",
            "description": "Manager with TransformStripManagedFields configured",
        },
        "expectations": {
            "should_detect": False,
            "forbidden_aps": ["AP-10"],
        },
    },
    {
        "inputs": {
            "case_id": "tn-safe-watches-metadata",
            "fixture": "testdata/safe_manager.go",
            "description": "Uses WatchesMetadata instead of Watches for triggers",
        },
        "expectations": {
            "should_detect": False,
            "forbidden_aps": ["AP-1", "AP-5"],
        },
    },
    {
        "inputs": {
            "case_id": "tn-safe-already-exists-handler",
            "fixture": "testdata/safe_manager.go",
            "description": "Create() with IsAlreadyExists fallback and MergeFrom",
        },
        "expectations": {
            "should_detect": False,
            "forbidden_aps": ["AP-8"],
        },
    },
]

EVAL_DATASET = TRUE_POSITIVE_CASES + TRUE_NEGATIVE_CASES
