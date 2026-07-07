#!/usr/bin/env bash
# scan-release.sh — Scan all operators in an OpenShift release for anti-patterns.
#
# Usage: ./scan-release.sh VERSION [--output-dir DIR] [--parallel N] [--skip-clone] [--json-only]
#
# Example:
#   ./scan-release.sh 4.21.21
#   ./scan-release.sh 4.21.21 --output-dir /tmp/my-scan --parallel 4 --json-only

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER="$SCRIPT_DIR/scan-operator-antipatterns.sh"
REPORT_GEN="$SCRIPT_DIR/generate-release-report.py"

# -- Defaults -----------------------------------------------------------------
VERSION=""
OUTPUT_DIR=""
PARALLEL=8
SKIP_CLONE=false
JSON_ONLY=false
RELEASE_REGISTRY="quay.io/openshift-release-dev/ocp-release"

# -- Argument parsing ---------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)  OUTPUT_DIR="$2"; shift 2 ;;
        --parallel)    PARALLEL="$2"; shift 2 ;;
        --skip-clone)  SKIP_CLONE=true; shift ;;
        --json-only)   JSON_ONLY=true; shift ;;
        --help|-h)
            echo "Usage: $0 VERSION [--output-dir DIR] [--parallel N] [--skip-clone] [--json-only]"
            echo ""
            echo "Scan all operators in an OpenShift release for controller-runtime anti-patterns."
            echo ""
            echo "Arguments:"
            echo "  VERSION        OCP release version (e.g., 4.21.21)"
            echo "  --output-dir   Output directory (default: /tmp/ocp-operator-scan-VERSION)"
            echo "  --parallel N   Number of parallel clone/scan jobs (default: 8)"
            echo "  --skip-clone   Reuse existing clones, skip git operations"
            echo "  --json-only    Produce JSON only, skip HTML report generation"
            exit 0
            ;;
        -*)
            echo "ERROR: Unknown option: $1" >&2
            exit 1
            ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"
            else
                echo "ERROR: Unexpected argument: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    echo "ERROR: OCP version required. Usage: $0 VERSION [options]" >&2
    exit 1
fi

RELEASE_IMAGE="${RELEASE_REGISTRY}:${VERSION}-x86_64"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="/tmp/ocp-operator-scan-${VERSION}"
CLONES_DIR="$OUTPUT_DIR/repos"
RESULTS_DIR="$OUTPUT_DIR/results"
MANIFEST="$OUTPUT_DIR/manifest.tsv"
UNIQUE_REPOS="$OUTPUT_DIR/unique-repos.tsv"
MERGED_JSON="$OUTPUT_DIR/release-scan-${VERSION}.json"
REPORT_HTML="$OUTPUT_DIR/release-scan-${VERSION}.html"

# -- Validate prerequisites ---------------------------------------------------
if ! command -v oc &>/dev/null; then
    echo "ERROR: oc CLI not found. Install it from https://mirror.openshift.com/pub/openshift-v4/clients/ocp/" >&2
    exit 1
fi

if ! command -v git &>/dev/null; then
    echo "ERROR: git not found" >&2
    exit 1
fi

if [[ ! -x "$SCANNER" ]]; then
    echo "ERROR: Scanner not found: $SCANNER" >&2
    exit 1
fi

echo "========================================================================"
echo "  OCP Release Operator Anti-Pattern Scanner"
echo "  Release: $VERSION"
echo "  Image:   $RELEASE_IMAGE"
echo "========================================================================"
echo ""

# -- Step 1: Extract operator list from release image -------------------------
echo "[1/5] Extracting operator list from release image..."
mkdir -p "$OUTPUT_DIR" "$CLONES_DIR" "$RESULTS_DIR"

RAW_INFO=$(oc adm release info --commits "$RELEASE_IMAGE" 2>&1)
if [[ $? -ne 0 ]]; then
    echo "ERROR: Failed to query release image: $RELEASE_IMAGE" >&2
    echo "$RAW_INFO" >&2
    exit 1
fi

echo "$RAW_INFO" | grep -i operator | awk '{print $1, $2, $3}' | \
    grep -E '^[a-z]' > "$MANIFEST"

TOTAL_ENTRIES=$(wc -l < "$MANIFEST")
echo "  Found $TOTAL_ENTRIES operator entries"

if [[ "$TOTAL_ENTRIES" -eq 0 ]]; then
    echo "ERROR: No operator entries found in release $VERSION" >&2
    exit 1
fi

# -- Step 2: Deduplicate by repo URL -----------------------------------------
echo "[2/5] Deduplicating repos..."

awk '{
    url = $2; sha = $3; comp = $1
    if (!(url in seen)) {
        seen[url] = sha
        order[++n] = url
    }
    components[url] = (components[url] ? components[url] "," comp : comp)
}
END {
    for (i = 1; i <= n; i++) {
        url = order[i]
        print components[url] "\t" url "\t" seen[url]
    }
}' "$MANIFEST" > "$UNIQUE_REPOS"

UNIQUE_COUNT=$(wc -l < "$UNIQUE_REPOS")
echo "  $TOTAL_ENTRIES entries → $UNIQUE_COUNT unique repos"

# -- Step 3: Clone repos at exact commit --------------------------------------
# If GH_TOKEN or GITHUB_TOKEN is set, inject it into HTTPS URLs for higher rate limits
AUTH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [[ -n "$AUTH_TOKEN" ]]; then
    echo "  Using GH_TOKEN for authenticated clones (5,000 req/hr rate limit)"
else
    echo "  No GH_TOKEN set — unauthenticated clones (60 req/hr rate limit)"
    echo "  Tip: export GH_TOKEN=\$(gh auth token) to avoid rate limiting"
fi

if $SKIP_CLONE; then
    echo "[3/5] Skipping clone (--skip-clone)"
else
    echo "[3/5] Cloning $UNIQUE_COUNT repos (parallel=$PARALLEL)..."

    clone_repo() {
        local components="$1" url="$2" sha="$3"
        local repo_name
        repo_name=$(basename "$url" .git)
        local target="$CLONES_DIR/$repo_name"

        if [[ -d "$target" ]] && [[ "$(git -C "$target" rev-parse HEAD 2>/dev/null)" == "$sha" ]]; then
            echo "  [skip] $repo_name (already at $sha)"
            return 0
        fi

        # Inject token into HTTPS URL if available
        local clone_url="$url"
        if [[ -n "$AUTH_TOKEN" ]] && [[ "$url" == https://github.com/* ]]; then
            clone_url="https://x-access-token:${AUTH_TOKEN}@github.com/${url#https://github.com/}"
        fi

        local attempt max_attempts=3
        for attempt in $(seq 1 $max_attempts); do
            rm -rf "$target"
            if git init -q "$target" && \
               git -C "$target" remote add origin "$clone_url" && \
               git -C "$target" config core.sparseCheckout true && \
               mkdir -p "$target/.git/info" && \
               printf '/*\n!vendor/\n!third_party/\n' > "$target/.git/info/sparse-checkout" && \
               git -C "$target" fetch --depth 1 -q origin "$sha" 2>/dev/null && \
               git -C "$target" checkout -q FETCH_HEAD 2>/dev/null; then
                echo "  [ok]   $repo_name"
                return 0
            fi
            if [[ $attempt -lt $max_attempts ]]; then
                sleep $((attempt * 3))
            fi
        done
        echo "  [FAIL] $repo_name ($url @ $sha) after $max_attempts attempts" >&2
        rm -rf "$target"
        echo "$repo_name" >> "$OUTPUT_DIR/clone-failures.txt"
    }
    export -f clone_repo
    export CLONES_DIR OUTPUT_DIR AUTH_TOKEN

    while IFS=$'\t' read -r components url sha; do
        echo "$components	$url	$sha"
    done < "$UNIQUE_REPOS" | xargs -P "$PARALLEL" -I {} bash -c '
        IFS=$'"'"'\t'"'"' read -r c u s <<< "{}"
        clone_repo "$c" "$u" "$s"
    '

    CLONED=$(find "$CLONES_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)
    FAILED=0
    [[ -f "$OUTPUT_DIR/clone-failures.txt" ]] && FAILED=$(wc -l < "$OUTPUT_DIR/clone-failures.txt")
    echo "  Cloned: $CLONED  Failed: $FAILED"
fi

# -- Step 4: Scan each repo ---------------------------------------------------
echo "[4/5] Scanning repos (parallel=$PARALLEL)..."

scan_repo() {
    local repo_dir="$1" results_dir="$2" scanner="$3"
    local repo_name
    repo_name=$(basename "$repo_dir")
    local result_file="$results_dir/${repo_name}.json"
    local err_file="$results_dir/${repo_name}.err"

    if bash "$scanner" "$repo_dir" --json > "$result_file" 2>"$err_file"; then
        local count
        count=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('findings_summary',{}).get('total',0))" "$result_file" 2>/dev/null || echo "?")
        echo "  [done] $repo_name ($count findings)"
    else
        echo "  [done] $repo_name (scanner returned non-zero, check $err_file)"
    fi
}
export -f scan_repo

find "$CLONES_DIR" -mindepth 1 -maxdepth 1 -type d -print0 | \
    xargs -0 -P "$PARALLEL" -I {} bash -c "scan_repo \"{}\" \"$RESULTS_DIR\" \"$SCANNER\""

# -- Step 5: Merge results into aggregate JSON --------------------------------
echo "[5/5] Merging results..."

python3 - "$VERSION" "$RELEASE_IMAGE" "$UNIQUE_REPOS" "$RESULTS_DIR" "$CLONES_DIR" "$MERGED_JSON" << 'PYEOF'
import json, sys, os
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path

version = sys.argv[1]
release_image = sys.argv[2]
unique_repos_file = sys.argv[3]
results_dir = sys.argv[4]
clones_dir = sys.argv[5]
output_file = sys.argv[6]

operators = []
repo_lookup = {}

with open(unique_repos_file) as f:
    for line in f:
        parts = line.strip().split('\t')
        if len(parts) != 3:
            continue
        components_str, url, sha = parts
        repo_name = os.path.basename(url).replace('.git', '')
        repo_lookup[repo_name] = {
            "repo_url": url,
            "components": components_str.split(','),
            "commit": sha,
        }

clone_failures = set()
fail_file = os.path.join(os.path.dirname(results_dir), "clone-failures.txt")
if os.path.exists(fail_file):
    with open(fail_file) as f:
        clone_failures = {line.strip() for line in f if line.strip()}

total_findings = 0
total_critical = 0
total_high = 0
total_medium = 0
total_low = 0
operators_with_findings = 0
ap_counts = defaultdict(int)

for repo_name, info in sorted(repo_lookup.items()):
    entry = {
        "repo_url": info["repo_url"],
        "repo_name": repo_name,
        "components": info["components"],
        "commit": info["commit"],
        "clone_failed": repo_name in clone_failures,
        "scan_result": None,
    }

    result_file = os.path.join(results_dir, f"{repo_name}.json")
    if os.path.exists(result_file):
        try:
            with open(result_file) as f:
                scan_result = json.load(f)
            entry["scan_result"] = scan_result

            summary = scan_result.get("findings_summary", {})
            t = summary.get("total", 0)
            if t > 0:
                operators_with_findings += 1
            total_findings += t
            total_critical += summary.get("critical", 0)
            total_high += summary.get("high", 0)
            total_medium += summary.get("medium", 0)
            total_low += summary.get("low", 0)

            for finding in scan_result.get("findings", []):
                ap_id = finding.get("id", "")
                if ap_id:
                    ap_counts[ap_id] += 1
        except (json.JSONDecodeError, KeyError) as e:
            entry["scan_error"] = str(e)

    operators.append(entry)

by_ap = {}
for i in range(1, 11):
    key = f"AP-{i}"
    by_ap[key] = ap_counts.get(key, 0)

result = {
    "ocp_version": version,
    "release_image": release_image,
    "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "scanner_version": "1.0.0",
    "summary": {
        "operators_scanned": len(operators),
        "operators_with_findings": operators_with_findings,
        "clone_failures": len(clone_failures),
        "total_findings": total_findings,
        "critical": total_critical,
        "high": total_high,
        "medium": total_medium,
        "low": total_low,
        "by_anti_pattern": by_ap,
    },
    "operators": operators,
}

with open(output_file, 'w') as f:
    json.dump(result, f, indent=2)

print(f"  Merged JSON: {output_file}")
print(f"  Operators: {len(operators)} scanned, {operators_with_findings} with findings")
print(f"  Findings:  {total_findings} total ({total_critical}C / {total_high}H / {total_medium}M / {total_low}L)")
PYEOF

# -- Step 6: Generate HTML report --------------------------------------------
if $JSON_ONLY; then
    echo ""
    echo "JSON output: $MERGED_JSON"
else
    echo ""
    echo "Generating HTML report..."
    if [[ -f "$REPORT_GEN" ]]; then
        python3 "$REPORT_GEN" "$MERGED_JSON" --output "$REPORT_HTML"
        echo "HTML report: $REPORT_HTML"
    else
        echo "WARNING: Report generator not found: $REPORT_GEN" >&2
        echo "Run: python3 generate-release-report.py $MERGED_JSON --output $REPORT_HTML"
    fi
fi

echo ""
echo "========================================================================"
echo "  Done. Output: $OUTPUT_DIR"
echo "========================================================================"
