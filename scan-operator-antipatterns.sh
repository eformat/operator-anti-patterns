#!/usr/bin/env bash
# scan-operator-antipatterns.sh — Detect controller-runtime anti-patterns in Go operator repos.
#
# Usage: ./scan-operator-antipatterns.sh /path/to/operator-repo [--json] [--semgrep]
#
# Sources:
#   - "5 anti-patterns that cause Kubernetes operator vulnerabilities" (Red Hat, 2026-07-06)
#   - "Protect your Kubernetes Operator from OOMKill" (Red Hat, 2026-06-01)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="${1:-.}"
OUTPUT_JSON="${2:---text}"
USE_SEMGREP=false
JSON_MODE=false

for arg in "$@"; do
    case "$arg" in
        --json) JSON_MODE=true ;;
        --semgrep) USE_SEMGREP=true ;;
    esac
done

if [[ ! -d "$REPO_DIR" ]]; then
    echo "ERROR: Directory not found: $REPO_DIR" >&2
    exit 1
fi

if ! command -v rg &>/dev/null; then
    echo "ERROR: ripgrep (rg) is required but not found" >&2
    exit 1
fi

if ! rg -q 'sigs.k8s.io/controller-runtime' "$REPO_DIR/go.mod" 2>/dev/null; then
    echo "WARNING: go.mod does not import controller-runtime — this may not be an operator" >&2
fi

# -- State -------------------------------------------------------------------
declare -a FINDINGS=()
FINDING_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

declare -A AP_DETECTED
for i in $(seq 1 10); do AP_DETECTED["AP-$i"]=false; done

add_finding() {
    local id="$1" title="$2" severity="$3" confidence="$4" file="$5" line="$6" snippet="$7" desc="$8" rec="$9"
    FINDING_COUNT=$((FINDING_COUNT + 1))
    AP_DETECTED["$id"]=true

    case "$severity" in
        CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
        HIGH)     HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
        MEDIUM)   MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
        LOW)      LOW_COUNT=$((LOW_COUNT + 1)) ;;
    esac

    local rel_file="${file#$REPO_DIR/}"

    if $JSON_MODE; then
        local json_entry
        json_entry=$(python3 -c "
import json, sys
print(json.dumps({
    'id': sys.argv[1],
    'title': sys.argv[2],
    'severity': sys.argv[3],
    'confidence': sys.argv[4],
    'file': sys.argv[5],
    'line': int(sys.argv[6]),
    'code_snippet': sys.argv[7],
    'description': sys.argv[8],
    'recommendation': sys.argv[9],
}, indent=6))
" "$id" "$title" "$severity" "$confidence" "$rel_file" "$line" "$snippet" "$desc" "$rec" 2>/dev/null)
        FINDINGS+=("$json_entry")
    else
        local color
        case "$severity" in
            CRITICAL) color="\033[1;31m" ;;
            HIGH)     color="\033[0;31m" ;;
            MEDIUM)   color="\033[0;33m" ;;
            LOW)      color="\033[0;36m" ;;
        esac
        echo -e "${color}[$severity]  $id: $title\033[0m"
        echo "  File: $rel_file:$line"
        echo "  Code: $snippet"
        echo "  Desc: $desc"
        echo "  Fix:  $rec"
        echo ""
    fi
}

# -- Helpers -----------------------------------------------------------------
# Directories to skip: vendored deps, generated code, test fixtures
RG_EXCLUDE=(--glob '!vendor/' --glob '!third_party/' --glob '!hack/' --glob '!_output/')

# Run rg on Go files, excluding vendor/tests. Args: pattern, extra rg flags...
rg_go() {
    local pattern="$1"; shift
    rg --type go --no-heading --line-number --with-filename \
        "${RG_EXCLUDE[@]}" \
        "$pattern" "$REPO_DIR" "$@" 2>/dev/null || true
}

# Run rg on Go files, excluding vendor/tests AND comment lines.
# Note: when using -l (files-only), comment filtering is skipped since there are no match lines.
rg_go_code() {
    local pattern="$1"; shift
    local args=("$@")
    local is_files_only=false
    for a in "${args[@]}"; do [[ "$a" == "-l" ]] && is_files_only=true; done

    if $is_files_only; then
        rg_go "$pattern" "$@"
    else
        rg_go "$pattern" "$@" | grep -vE '^[^:]+:[^:]+:\s*//' || true
    fi
}

# -- AP-1: Predicate filters don't limit cache --------------------------------
scan_ap1() {
    local matches
    matches=$(rg_go_code 'WithPredicates|WithEventFilter' --glob '!*_test.go')
    if [[ -z "$matches" ]]; then return; fi

    while IFS= read -r match; do
        local file line snippet
        file=$(echo "$match" | cut -d: -f1)
        line=$(echo "$match" | cut -d: -f2)
        snippet=$(echo "$match" | cut -d: -f3-)

        # Skip function declarations / type definitions (library code)
        if echo "$snippet" | grep -qE '^\s*func |^\s*type '; then continue; fi

        if rg -q 'Watches\(' "$file" 2>/dev/null; then
            if true; then
                add_finding "AP-1" \
                    "Predicate filters don't limit cache" \
                    "HIGH" "HIGH" "$file" "$line" \
                    "$snippet" \
                    "Predicate/event filter used on Watches() but predicates only filter events reaching the reconciler, not what the informer caches. The informer still does a full LIST+WATCH cluster-wide." \
                    "Replace Watches() with mgr.GetAPIReader() for occasional reads, or add a label selector in ByObject cache config."
            fi
        fi
    done <<< "$matches"
}

# -- AP-2: DisableFor doesn't affect Owns/Watches informers -------------------
scan_ap2() {
    local disable_for_types
    # Extract types inside DisableFor blocks only (limit context to closing bracket)
    local disable_for_files
    disable_for_files=$(rg_go 'DisableFor' --glob '!*_test.go' -l)
    if [[ -z "$disable_for_files" ]]; then return; fi

    local disable_for_types=""
    while IFS= read -r dfile; do
        # Find the DisableFor line number and extract a small window
        local df_line
        df_line=$(rg --line-number 'DisableFor' "$dfile" 2>/dev/null | head -1 | cut -d: -f1)
        [[ -z "$df_line" ]] && continue
        # Extract up to 10 lines after DisableFor, stop at closing }] or },
        local block
        block=$(sed -n "${df_line},$((df_line + 10))p" "$dfile" 2>/dev/null | sed '/^\s*}\s*[],]/q')
        local types_in_block
        types_in_block=$(echo "$block" | rg '&\w+\.\w+\{\}' -o 2>/dev/null | sort -u || true)
        disable_for_types=$(echo -e "${disable_for_types}\n${types_in_block}" | sort -u | grep -v '^$' || true)
    done <<< "$disable_for_files"

    if [[ -z "$disable_for_types" ]]; then return; fi

    while IFS= read -r dtype; do
        local short_type
        short_type=$(echo "$dtype" | sed 's/&//;s/{}//')

        # Escape the type for use in rg pattern (dots and braces)
        local escaped_dtype
        escaped_dtype=$(echo "$dtype" | sed 's/[.{}]/\\&/g')

        local owns_matches
        owns_matches=$(rg_go "Owns\(\s*${escaped_dtype}" --glob '!*_test.go')
        local watches_matches
        watches_matches=$(rg_go "Watches\(\s*${escaped_dtype}" --glob '!*_test.go')

        local all_matches
        all_matches=$(echo -e "${owns_matches}\n${watches_matches}" | grep -v '^$' || true)

        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            local file line snippet
            file=$(echo "$match" | cut -d: -f1)
            line=$(echo "$match" | cut -d: -f2)
            snippet=$(echo "$match" | cut -d: -f3-)

            add_finding "AP-2" \
                "DisableFor doesn't affect Owns/Watches informers" \
                "HIGH" "HIGH" "$file" "$line" \
                "$snippet" \
                "$short_type is in DisableFor (bypasses cache for client.Get/List) but also registered via Owns()/Watches() which creates an independent cluster-wide informer that DisableFor cannot touch." \
                "If Owns() is only for GC, remove it — owner references handle cleanup without informers. Otherwise add a label selector in ByObject."
        done <<< "$all_matches"
    done <<< "$disable_for_types"
}

# -- AP-3: Invisible informer from client.Get() -------------------------------
scan_ap3() {
    local byobject_types disable_for_types all_registered_types

    # Build list of all known types (ByObject, DisableFor, For, Owns, Watches)
    # These are types the operator has explicitly registered — client.Get for anything else is AP-3
    local all_registered_types=""

    # Extract from ByObject blocks per-file
    local bo_files
    bo_files=$(rg_go 'ByObject' --glob '!*_test.go' -l)
    if [[ -n "$bo_files" ]]; then
        while IFS= read -r bf; do
            local bo_line
            bo_line=$(rg --line-number 'ByObject' "$bf" 2>/dev/null | head -1 | cut -d: -f1)
            [[ -z "$bo_line" ]] && continue
            local bo_block
            bo_block=$(sed -n "${bo_line},$((bo_line + 30))p" "$bf" 2>/dev/null)
            all_registered_types=$(echo -e "${all_registered_types}\n$(echo "$bo_block" | rg '&\w+\.\w+\{\}' -o 2>/dev/null || true)" | sort -u | grep -v '^$' || true)
        done <<< "$bo_files"
    fi

    # Extract from DisableFor blocks per-file
    local df_files
    df_files=$(rg_go 'DisableFor' --glob '!*_test.go' -l)
    if [[ -n "$df_files" ]]; then
        while IFS= read -r df; do
            local df_line
            df_line=$(rg --line-number 'DisableFor' "$df" 2>/dev/null | head -1 | cut -d: -f1)
            [[ -z "$df_line" ]] && continue
            local df_block
            df_block=$(sed -n "${df_line},$((df_line + 10))p" "$df" 2>/dev/null | sed '/^\s*}\s*[],]/q')
            all_registered_types=$(echo -e "${all_registered_types}\n$(echo "$df_block" | rg '&\w+\.\w+\{\}' -o 2>/dev/null || true)" | sort -u | grep -v '^$' || true)
        done <<< "$df_files"
    fi

    # Extract from For/Owns/Watches
    local for_types owns_types watches_types
    for_types=$(rg_go 'For\(\s*&\w' --glob '!*_test.go' | rg '&\w+\.\w+\{\}' -o 2>/dev/null | sort -u || true)
    owns_types=$(rg_go 'Owns\(\s*&\w' --glob '!*_test.go' | rg '&\w+\.\w+\{\}' -o 2>/dev/null | sort -u || true)
    watches_types=$(rg_go '(Watches|WatchesMetadata)\(\s*&\w' --glob '!*_test.go' | rg '&\w+\.\w+\{\}' -o 2>/dev/null | sort -u || true)

    all_registered_types=$(echo -e "${all_registered_types}\n${for_types}\n${owns_types}\n${watches_types}" | sort -u | grep -v '^$' || true)

    local get_calls
    get_calls=$(rg_go_code '\.(Client\.)?Get\(ctx' --glob '!*_test.go' --glob '!*setup*.go' --glob '!*main.go')
    if [[ -z "$get_calls" ]]; then return; fi

    local list_calls
    list_calls=$(rg_go_code '\.(Client\.)?List\(ctx' --glob '!*_test.go' --glob '!*setup*.go' --glob '!*main.go')

    local all_reads
    all_reads=$(echo -e "${get_calls}\n${list_calls}" | grep -v '^$' | sort -u || true)

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        local file line
        file=$(echo "$match" | cut -d: -f1)
        line=$(echo "$match" | cut -d: -f2)

        local line_num=$((line - 5))
        [[ $line_num -lt 1 ]] && line_num=1

        local context
        context=$(sed -n "${line_num},$((line + 2))p" "$file" 2>/dev/null || true)

        local var_type
        var_type=$(echo "$context" | rg '(var\s+\w+\s+|:=\s*&)(\w+\.\w+)' -o --replace '$2' 2>/dev/null | head -1 || true)
        [[ -z "$var_type" ]] && continue

        local type_ref="&${var_type}{}"
        if ! echo "$all_registered_types" | grep -qF "$type_ref" 2>/dev/null; then
            local snippet
            snippet=$(echo "$match" | cut -d: -f3-)
            add_finding "AP-3" \
                "Invisible informer from client.Get()" \
                "CRITICAL" "MEDIUM" "$file" "$line" \
                "$snippet" \
                "client.Get()/List() for $var_type which is not in ByObject or DisableFor. On first call, the cached client silently creates a cluster-wide informer with a full LIST of every $var_type in every namespace." \
                "Add $type_ref to DisableFor to bypass cache, or add it to ByObject with a label selector."
        fi
    done <<< "$all_reads"
}

# -- AP-4: No DefaultNamespaces -----------------------------------------------
scan_ap4() {
    local manager_files
    manager_files=$(rg_go 'ctrl\.NewManager|manager\.New' --glob '!*_test.go' -l)
    if [[ -z "$manager_files" ]]; then return; fi

    while IFS= read -r file; do
        if ! rg -q '^[^/]*DefaultNamespaces' "$file" 2>/dev/null; then
            local match
            match=$(rg --line-number 'ctrl\.NewManager|manager\.New' "$file" | head -1)
            local line
            line=$(echo "$match" | cut -d: -f1)
            [[ -z "$line" ]] && line=1

            add_finding "AP-4" \
                "No DefaultNamespaces — everything is cluster-wide" \
                "HIGH" "HIGH" "$file" "$line" \
                "cache.Options without DefaultNamespaces" \
                "No DefaultNamespaces set in cache configuration. Every informer watches ALL namespaces by default, even if the operator only manages resources in a few namespaces." \
                "For single-namespace operators, set DefaultNamespaces: map[string]cache.Config{\"my-ns\": {}}. For multi-namespace, use label selectors in ByObject."
        fi
    done <<< "$manager_files"
}

# -- AP-5: Typed/unstructured cache trap ---------------------------------------
scan_ap5() {
    local typed_watches
    typed_watches=$(rg_go 'Watches\(\s*&\w+\.\w+\{\}' --glob '!*_test.go' -l)
    if [[ -z "$typed_watches" ]]; then return; fi

    local unstructured_usage
    unstructured_usage=$(rg_go 'unstructured\.Unstructured\{\}|SetGroupVersionKind' --glob '!*_test.go')
    if [[ -z "$unstructured_usage" ]]; then return; fi

    while IFS= read -r match; do
        local file line snippet
        file=$(echo "$match" | cut -d: -f1)
        line=$(echo "$match" | cut -d: -f2)
        snippet=$(echo "$match" | cut -d: -f3-)

        if echo "$typed_watches" | grep -qF "$file" 2>/dev/null || \
           rg -q 'Watches|Owns|For\(' "$file" 2>/dev/null; then
            add_finding "AP-5" \
                "Typed/unstructured cache trap" \
                "HIGH" "MEDIUM" "$file" "$line" \
                "$snippet" \
                "Unstructured object usage found in a file that also registers typed watches. controller-runtime maintains 3 separate caches (typed, unstructured, metadata) — mismatched representations cause duplicate caches or wasted memory." \
                "Use WatchesMetadata() if you only need triggers. Otherwise ensure watch and read use the same object representation."
        fi
    done <<< "$unstructured_usage"
}

# -- AP-6: Unfiltered ByObject entries -----------------------------------------
scan_ap6() {
    local byobject_blocks
    byobject_blocks=$(rg_go 'ByObject' --glob '!*_test.go' -l)
    if [[ -z "$byobject_blocks" ]]; then return; fi

    while IFS= read -r file; do
        local matches
        matches=$(rg --line-number --no-heading '&\w+v\d*\.\w+\{\}:\s*\{\}' "$file" 2>/dev/null || true)
        if [[ -z "$matches" ]]; then
            matches=$(rg --line-number --no-heading '&\w+\.\w+\{\}:\s*\{\}' "$file" 2>/dev/null || true)
        fi
        if [[ -z "$matches" ]]; then
            matches=$(rg --line-number --no-heading '&\w+\.\w+\{\}:\s*cache\.ByObject\{\}' "$file" 2>/dev/null || true)
        fi

        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            local line snippet
            line=$(echo "$match" | cut -d: -f1)
            snippet=$(echo "$match" | cut -d: -f2-)

            add_finding "AP-6" \
                "Unfiltered ByObject entry" \
                "CRITICAL" "HIGH" "$file" "$line" \
                "$snippet" \
                "ByObject entry with empty config {} — caches ALL objects of this type cluster-wide. 700 objects at 900KB = 630MB, exceeding typical 512MiB limits. Any user with the edit ClusterRole can trigger OOMKill." \
                "Add a label selector: { Label: labels.SelectorFromSet(labels.Set{\"app.kubernetes.io/managed-by\": \"my-operator\"}) }"
        done <<< "$matches"
    done <<< "$byobject_blocks"
}

# -- AP-7: Operator-created resources missing cache labels ---------------------
scan_ap7() {
    local label_selector
    label_selector=$(rg_go 'SelectorFromSet|LabelSelector' --glob '!*_test.go' -A 3 | rg '"[a-z/.-]+":\s*"[^"]*"' -o 2>/dev/null | head -1 || true)

    if [[ -z "$label_selector" ]]; then return; fi

    local label_key
    label_key=$(echo "$label_selector" | cut -d: -f1 | tr -d '"' | xargs)

    local create_calls
    create_calls=$(rg_go_code '\.(Client\.)?Create\(ctx' --glob '!*_test.go' -l)
    if [[ -z "$create_calls" ]]; then return; fi

    while IFS= read -r file; do
        local obj_meta_blocks
        obj_meta_blocks=$(rg --line-number --no-heading 'ObjectMeta\s*:?\s*metav1\.ObjectMeta\{' "$file" 2>/dev/null || true)
        if [[ -z "$obj_meta_blocks" ]]; then continue; fi

        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            local line
            line=$(echo "$match" | cut -d: -f1)

            local block_end=$((line + 15))
            local block
            block=$(sed -n "${line},${block_end}p" "$file" 2>/dev/null || true)

            if ! echo "$block" | grep -qF "$label_key" 2>/dev/null && \
               ! echo "$block" | grep -q 'Labels:\s*map\[string\]string{' 2>/dev/null && \
               ! echo "$block" | grep -q 'Labels:.*{' 2>/dev/null; then
                add_finding "AP-7" \
                    "Operator-created resource missing cache label" \
                    "MEDIUM" "MEDIUM" "$file" "$line" \
                    "ObjectMeta without label: $label_key" \
                    "Resource created by the operator lacks the label ($label_key) required by the ByObject cache filter. This resource will be invisible to the operator's own cached reads." \
                    "Add Labels: map[string]string{\"$label_key\": \"true\"} to the ObjectMeta."
            fi
        done <<< "$obj_meta_blocks"
    done <<< "$create_calls"
}

# -- AP-8: No upgrade path for pre-existing unlabeled resources ----------------
scan_ap8() {
    local byobject_with_labels
    byobject_with_labels=$(rg_go 'ByObject.*Label|SelectorFromSet' --glob '!*_test.go')
    if [[ -z "$byobject_with_labels" ]]; then return; fi

    local create_calls
    create_calls=$(rg_go_code '\.(Client\.)?Create\(ctx' --glob '!*_test.go' -l)
    if [[ -z "$create_calls" ]]; then return; fi

    while IFS= read -r file; do
        if ! rg -q 'IsAlreadyExists|errors\.IsAlreadyExists' "$file" 2>/dev/null; then
            if ! rg -q 'MergeFrom|StrategicMerge' "$file" 2>/dev/null; then
                local match
                match=$(rg --line-number 'Create\(ctx' "$file" 2>/dev/null | head -1)
                local line
                line=$(echo "$match" | cut -d: -f1)
                [[ -z "$line" ]] && line=1

                add_finding "AP-8" \
                    "No upgrade path for pre-existing unlabeled resources" \
                    "LOW" "MEDIUM" "$file" "$line" \
                    "Create() without IsAlreadyExists fallback" \
                    "Label-filtered cache is configured but Create() has no fallback for pre-existing unlabeled resources. After deploying the filtered cache, old resources cause Get()→NotFound but Create()→AlreadyExists." \
                    "Handle errors.IsAlreadyExists by falling back to a client.MergeFrom(base) patch that adds the required label."
            fi
        fi
    done <<< "$create_calls"
}

# -- AP-9: Labels not propagated during resource updates -----------------------
scan_ap9() {
    local label_selector
    label_selector=$(rg_go 'SelectorFromSet|LabelSelector' --glob '!*_test.go' -A 3 | rg '"[a-z/.-]+":\s*"[^"]*"' -o 2>/dev/null | head -1 || true)
    if [[ -z "$label_selector" ]]; then return; fi

    local label_key
    label_key=$(echo "$label_selector" | cut -d: -f1 | tr -d '"' | xargs)

    local update_calls
    update_calls=$(rg_go_code '\.(Client\.)?Update\(ctx' --glob '!*_test.go')
    if [[ -z "$update_calls" ]]; then return; fi

    while IFS= read -r match; do
        local file line
        file=$(echo "$match" | cut -d: -f1)
        line=$(echo "$match" | cut -d: -f2)

        local context_start=$((line - 10))
        [[ $context_start -lt 1 ]] && context_start=1
        local context
        context=$(sed -n "${context_start},${line}p" "$file" 2>/dev/null || true)

        if ! echo "$context" | grep -qF "$label_key" 2>/dev/null; then
            if ! echo "$context" | grep -q 'Labels\[' 2>/dev/null; then
                local snippet
                snippet=$(echo "$match" | cut -d: -f3-)
                add_finding "AP-9" \
                    "Labels not propagated during resource update" \
                    "MEDIUM" "LOW" "$file" "$line" \
                    "$snippet" \
                    "Update() call found without explicit label propagation. If the object's Labels map is nil or missing the required filter label ($label_key), the resource becomes invisible to the filtered cache after the update." \
                    "Before Update(): if obj.Labels == nil { obj.Labels = map[string]string{} }; obj.Labels[\"$label_key\"] = \"true\""
            fi
        fi
    done <<< "$update_calls"
}

# -- AP-10: No DefaultTransform to strip managedFields -------------------------
scan_ap10() {
    local manager_files
    manager_files=$(rg_go 'ctrl\.NewManager|cache\.Options' --glob '!*_test.go' -l)
    if [[ -z "$manager_files" ]]; then return; fi

    while IFS= read -r file; do
        if rg -q 'cache\.Options' "$file" 2>/dev/null; then
            if ! rg -q '^[^/]*(DefaultTransform|TransformStripManagedFields|StripManagedFields)' "$file" 2>/dev/null; then
                local match
                match=$(rg --line-number 'cache\.Options' "$file" 2>/dev/null | head -1)
                local line
                line=$(echo "$match" | cut -d: -f1)
                [[ -z "$line" ]] && line=1

                add_finding "AP-10" \
                    "No DefaultTransform to strip managedFields" \
                    "MEDIUM" "HIGH" "$file" "$line" \
                    "cache.Options without DefaultTransform" \
                    "Cache configuration does not strip managedFields. Every cached object carries ~2-5KB of managedFields metadata that operators almost never need. Across thousands of objects this adds significant memory overhead." \
                    "Add DefaultTransform: cache.TransformStripManagedFields() to cache.Options."
            fi
        fi
    done <<< "$manager_files"
}

# -- Main execution -----------------------------------------------------------
if ! $JSON_MODE; then
    echo "========================================================================"
    echo "  Operator Anti-Pattern Scanner v1.0.0"
    echo "  Scanning: $REPO_DIR"
    echo "========================================================================"
    echo ""
fi

scan_ap1
scan_ap2
scan_ap3
scan_ap4
scan_ap5
scan_ap6
scan_ap7
scan_ap8
scan_ap9
scan_ap10

# -- Optional: Run semgrep ----------------------------------------------------
if $USE_SEMGREP; then
    if command -v semgrep &>/dev/null; then
        SEMGREP_RULES="$SCRIPT_DIR/.semgrep-operator-antipatterns.yml"
        if [[ -f "$SEMGREP_RULES" ]]; then
            if ! $JSON_MODE; then
                echo "--- Running semgrep SAST rules ---"
            fi
            semgrep --config "$SEMGREP_RULES" "$REPO_DIR" --json 2>/dev/null | \
                python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('results', []):
    print(f\"  [{r['extra']['severity'].upper()}] {r['check_id']}\")
    print(f\"    File: {r['path']}:{r['start']['line']}\")
    print(f\"    {r['extra']['message']}\")
    print()
" 2>/dev/null || true
        fi
    else
        if ! $JSON_MODE; then
            echo "NOTE: semgrep not installed — skipping SAST rules. Install: pip install semgrep"
        fi
    fi
fi

# -- Output summary -----------------------------------------------------------
if $JSON_MODE; then
    # Build findings array with proper comma separation
    findings_json="["
    for i in "${!FINDINGS[@]}"; do
        if [[ $i -gt 0 ]]; then findings_json+=","; fi
        findings_json+="${FINDINGS[$i]}"
    done
    findings_json+="]"

    python3 -c "
import json, sys
findings = json.loads(sys.argv[1])
result = {
    'repo': sys.argv[2],
    'scan_date': sys.argv[3],
    'scanner_version': '1.0.0',
    'tools_used': ['ripgrep'],
    'findings_summary': {
        'total': int(sys.argv[4]),
        'critical': int(sys.argv[5]),
        'high': int(sys.argv[6]),
        'medium': int(sys.argv[7]),
        'low': int(sys.argv[8]),
    },
    'findings': findings,
    'anti_pattern_coverage': {}
}
for i in range(1, 11):
    key = f'AP-{i}'
    result['anti_pattern_coverage'][key] = {
        'detected': sys.argv[8 + i] == 'true',
        'scanned': True,
    }
print(json.dumps(result, indent=2))
" "$findings_json" \
  "$REPO_DIR" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$FINDING_COUNT" "$CRITICAL_COUNT" "$HIGH_COUNT" "$MEDIUM_COUNT" "$LOW_COUNT" \
  "${AP_DETECTED[AP-1]}" "${AP_DETECTED[AP-2]}" "${AP_DETECTED[AP-3]}" "${AP_DETECTED[AP-4]}" \
  "${AP_DETECTED[AP-5]}" "${AP_DETECTED[AP-6]}" "${AP_DETECTED[AP-7]}" "${AP_DETECTED[AP-8]}" \
  "${AP_DETECTED[AP-9]}" "${AP_DETECTED[AP-10]}"
else
    echo "========================================================================"
    echo "  SUMMARY"
    echo "========================================================================"
    echo "  Total findings: $FINDING_COUNT"
    echo "    CRITICAL: $CRITICAL_COUNT"
    echo "    HIGH:     $HIGH_COUNT"
    echo "    MEDIUM:   $MEDIUM_COUNT"
    echo "    LOW:      $LOW_COUNT"
    echo ""
    echo "  Anti-pattern coverage:"
    for i in $(seq 1 10); do
        local_key="AP-$i"
        if ${AP_DETECTED[$local_key]}; then
            echo "    $local_key: DETECTED"
        else
            echo "    $local_key: clean"
        fi
    done
    echo "========================================================================"
fi
