#!/usr/bin/env python3
"""Generate a self-contained HTML report from a release scan JSON file.

Usage:
    python3 generate-release-report.py release-scan-4.21.21.json
    python3 generate-release-report.py release-scan-4.21.21.json --output report.html
"""

import argparse
import html
import json
import sys
from collections import defaultdict
from pathlib import Path

AP_TITLES = {
    "AP-1": "Predicate filters don't limit cache",
    "AP-2": "DisableFor doesn't affect Owns/Watches informers",
    "AP-3": "Invisible informer from client.Get()",
    "AP-4": "No DefaultNamespaces — everything is cluster-wide",
    "AP-5": "Typed/unstructured cache trap",
    "AP-6": "Unfiltered ByObject entries",
    "AP-7": "Operator-created resources missing cache labels",
    "AP-8": "No upgrade path for pre-existing unlabeled resources",
    "AP-9": "Labels not propagated during resource updates",
    "AP-10": "No DefaultTransform to strip managedFields",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def render_css():
    return """
<style>
:root {
    --critical: #c9190b;
    --critical-bg: #fce4e4;
    --high: #ec7a08;
    --high-bg: #fef3e0;
    --medium: #f0ab00;
    --medium-bg: #fef9e5;
    --low: #3e8635;
    --low-bg: #e8f5e3;
    --bg: #f5f5f5;
    --card-bg: #ffffff;
    --text: #151515;
    --text-muted: #6a6e73;
    --border: #d2d2d2;
    --header-bg: #151515;
    --header-text: #ffffff;
    --link: #0066cc;
    --code-bg: #f0f0f0;
    --row-hover: #f0f4ff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Red Hat Text', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }
.container { max-width: 1400px; margin: 0 auto; padding: 0 24px; }
header { background: var(--header-bg); color: var(--header-text); padding: 24px 0; margin-bottom: 24px; }
header h1 { font-size: 1.5rem; font-weight: 600; }
header .subtitle { color: #c9c9c9; font-size: 0.875rem; margin-top: 4px; }
h2 { font-size: 1.25rem; font-weight: 600; margin: 24px 0 12px; }
a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Summary cards */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: var(--card-bg); border-radius: 8px; padding: 16px 20px; border-left: 4px solid var(--border); box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.card.critical { border-left-color: var(--critical); }
.card.high { border-left-color: var(--high); }
.card.medium { border-left-color: var(--medium); }
.card.low { border-left-color: var(--low); }
.card.info { border-left-color: var(--link); }
.card-value { font-size: 2rem; font-weight: 700; line-height: 1.2; }
.card.critical .card-value { color: var(--critical); }
.card.high .card-value { color: var(--high); }
.card.medium .card-value { color: var(--medium); }
.card.low .card-value { color: var(--low); }
.card.info .card-value { color: var(--link); }
.card-label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }

/* Heatmap */
.heatmap { background: var(--card-bg); border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 24px; }
.heatmap-row { display: flex; align-items: center; margin-bottom: 8px; gap: 8px; }
.heatmap-label { width: 60px; font-size: 0.8rem; font-weight: 600; text-align: right; flex-shrink: 0; }
.heatmap-bar-bg { flex: 1; background: #e8e8e8; border-radius: 4px; height: 22px; overflow: hidden; }
.heatmap-bar { height: 100%; border-radius: 4px; min-width: 2px; transition: width 0.3s; display: flex; align-items: center; padding-left: 8px; font-size: 0.75rem; color: white; font-weight: 600; }
.heatmap-count { width: 40px; font-size: 0.8rem; text-align: left; color: var(--text-muted); flex-shrink: 0; }

/* Filters */
.filters { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 16px; background: var(--card-bg); padding: 12px 16px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.filters label { font-size: 0.8rem; font-weight: 600; color: var(--text-muted); }
.filters select, .filters input { padding: 6px 10px; border: 1px solid var(--border); border-radius: 4px; font-size: 0.875rem; background: white; }
.filters input[type="text"] { min-width: 220px; }
.filter-count { font-size: 0.8rem; color: var(--text-muted); margin-left: auto; }

/* Operator table */
.op-table { width: 100%; border-collapse: separate; border-spacing: 0; background: var(--card-bg); border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 32px; }
.op-table th { background: #f0f0f0; padding: 10px 12px; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); border-bottom: 2px solid var(--border); cursor: pointer; user-select: none; white-space: nowrap; }
.op-table th:hover { background: #e0e0e0; }
.op-table th .sort-arrow { margin-left: 4px; font-size: 0.7rem; }
.op-table td { padding: 0; border-bottom: 1px solid #eee; }
.op-row { display: none; }
.op-row.visible { display: table-row; }

/* Operator detail (details/summary) */
details.op-detail { width: 100%; }
details.op-detail > summary { display: flex; align-items: center; padding: 10px 12px; cursor: pointer; list-style: none; gap: 12px; }
details.op-detail > summary::-webkit-details-marker { display: none; }
details.op-detail > summary::before { content: '▸'; font-size: 0.9rem; color: var(--text-muted); transition: transform 0.15s; flex-shrink: 0; width: 12px; }
details.op-detail[open] > summary::before { transform: rotate(90deg); }
details.op-detail > summary:hover { background: var(--row-hover); }
.op-name { font-weight: 600; min-width: 280px; flex-shrink: 0; }
.op-name .components { font-weight: 400; font-size: 0.75rem; color: var(--text-muted); display: block; }
.op-counts { display: flex; gap: 8px; align-items: center; }
.op-counts .count { display: inline-flex; align-items: center; justify-content: center; min-width: 28px; padding: 2px 6px; border-radius: 10px; font-size: 0.75rem; font-weight: 700; }
.count.critical { background: var(--critical-bg); color: var(--critical); }
.count.high { background: var(--high-bg); color: var(--high); }
.count.medium { background: var(--medium-bg); color: var(--medium); }
.count.low { background: var(--low-bg); color: var(--low); }
.count.zero { background: transparent; color: #ccc; }
.op-total { font-weight: 700; min-width: 40px; text-align: right; }
.op-aps { font-size: 0.75rem; color: var(--text-muted); }
.op-link { font-size: 0.75rem; }

/* Findings detail panel */
.findings-panel { padding: 12px 16px 16px 36px; background: #fafafa; border-top: 1px solid #eee; }
.finding-group { margin-bottom: 16px; }
.finding-group-header { font-weight: 600; font-size: 0.9rem; margin-bottom: 8px; padding: 4px 8px; border-radius: 4px; display: inline-block; }
.finding-group-header.critical { background: var(--critical-bg); color: var(--critical); }
.finding-group-header.high { background: var(--high-bg); color: var(--high); }
.finding-group-header.medium { background: var(--medium-bg); color: var(--medium); }
.finding-group-header.low { background: var(--low-bg); color: var(--low); }
.finding-item { margin: 8px 0; padding: 8px 12px; border-left: 3px solid var(--border); background: white; border-radius: 0 4px 4px 0; }
.finding-item.critical { border-left-color: var(--critical); }
.finding-item.high { border-left-color: var(--high); }
.finding-item.medium { border-left-color: var(--medium); }
.finding-item.low { border-left-color: var(--low); }
.finding-file { font-family: 'Red Hat Mono', monospace; font-size: 0.8rem; color: var(--link); }
.finding-snippet { font-family: 'Red Hat Mono', monospace; font-size: 0.8rem; background: var(--code-bg); padding: 6px 10px; border-radius: 4px; margin: 4px 0; overflow-x: auto; white-space: pre; display: block; }
.finding-desc { font-size: 0.8rem; color: var(--text-muted); margin-top: 4px; }
.finding-rec { font-size: 0.8rem; color: var(--low); margin-top: 2px; }
.finding-rec::before { content: 'Fix: '; font-weight: 600; }

/* Clean / no-findings */
.clean-badge { color: var(--low); font-size: 0.8rem; padding: 10px 12px 10px 36px; }
.clone-failed { color: var(--critical); font-size: 0.8rem; padding: 10px 12px 10px 36px; }

/* Footer */
footer { text-align: center; padding: 24px 0; font-size: 0.8rem; color: var(--text-muted); border-top: 1px solid var(--border); margin-top: 32px; }

@media print {
    body { background: white; }
    .filters { display: none; }
    details.op-detail { break-inside: avoid; }
    .op-row { display: table-row !important; }
    header { background: white; color: black; border-bottom: 2px solid black; }
    header .subtitle { color: #666; }
}
@media (max-width: 768px) {
    .cards { grid-template-columns: repeat(2, 1fr); }
    .op-name { min-width: 180px; }
    .filters { flex-direction: column; }
}
</style>
"""


def render_js():
    return """
<script>
(function() {
    const rows = document.querySelectorAll('.op-row');
    const filterSev = document.getElementById('filter-severity');
    const filterAP = document.getElementById('filter-ap');
    const filterSearch = document.getElementById('filter-search');
    const countEl = document.getElementById('filter-count');

    function applyFilters() {
        const sev = filterSev.value;
        const ap = filterAP.value;
        const search = filterSearch.value.toLowerCase();
        let visible = 0;

        rows.forEach(row => {
            let show = true;
            const name = row.dataset.name || '';
            const aps = row.dataset.aps || '';
            const c = parseInt(row.dataset.critical || '0');
            const h = parseInt(row.dataset.high || '0');
            const m = parseInt(row.dataset.medium || '0');
            const l = parseInt(row.dataset.low || '0');

            if (search && !name.toLowerCase().includes(search)) show = false;
            if (ap && !aps.includes(ap)) show = false;
            if (sev === 'CRITICAL' && c === 0) show = false;
            if (sev === 'HIGH' && (c + h) === 0) show = false;
            if (sev === 'MEDIUM' && (c + h + m) === 0) show = false;
            if (sev === 'LOW' && (c + h + m + l) === 0) show = false;
            if (sev === 'CLEAN' && (c + h + m + l) !== 0) show = false;

            row.classList.toggle('visible', show);
            if (show) visible++;
        });
        countEl.textContent = visible + ' / ' + rows.length + ' operators';
    }

    filterSev.addEventListener('change', applyFilters);
    filterAP.addEventListener('change', applyFilters);
    filterSearch.addEventListener('input', applyFilters);

    // Sorting
    const headers = document.querySelectorAll('.op-table th[data-sort]');
    let currentSort = 'total';
    let sortDir = -1;

    headers.forEach(th => {
        th.addEventListener('click', () => {
            const key = th.dataset.sort;
            if (currentSort === key) { sortDir *= -1; }
            else { currentSort = key; sortDir = -1; }

            const tbody = document.getElementById('op-tbody');
            const rowArr = Array.from(rows);
            rowArr.sort((a, b) => {
                let va, vb;
                if (key === 'name') {
                    va = a.dataset.name || '';
                    vb = b.dataset.name || '';
                    return sortDir * va.localeCompare(vb);
                }
                va = parseInt(a.dataset[key] || '0');
                vb = parseInt(b.dataset[key] || '0');
                return sortDir * (va - vb);
            });
            rowArr.forEach(r => tbody.appendChild(r));

            headers.forEach(h => {
                const arrow = h.querySelector('.sort-arrow');
                if (h.dataset.sort === key) {
                    arrow.textContent = sortDir === -1 ? '▼' : '▲';
                } else {
                    arrow.textContent = '⇅';
                }
            });
        });
    });

    // Initialize
    applyFilters();
})();
</script>
"""


def severity_class(sev):
    return sev.lower() if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else ""


def count_badge(n, sev):
    cls = severity_class(sev) if n > 0 else "zero"
    return f'<span class="count {cls}">{n}</span>'


def render_header(data):
    version = html.escape(data["ocp_version"])
    image = html.escape(data["release_image"])
    scan_date = html.escape(data.get("scan_date", ""))
    return f"""
<header>
  <div class="container">
    <h1>OCP {version} Operator Anti-Pattern Report</h1>
    <div class="subtitle">{image} &middot; Scanned {scan_date} &middot; Scanner v{html.escape(data.get("scanner_version", "1.0.0"))}</div>
  </div>
</header>
"""


def render_summary(data):
    s = data["summary"]
    return f"""
<div class="container">
  <div class="cards">
    <div class="card critical"><div class="card-value">{s['critical']}</div><div class="card-label">Critical</div></div>
    <div class="card high"><div class="card-value">{s['high']}</div><div class="card-label">High</div></div>
    <div class="card medium"><div class="card-value">{s['medium']}</div><div class="card-label">Medium</div></div>
    <div class="card low"><div class="card-value">{s['low']}</div><div class="card-label">Low</div></div>
    <div class="card info"><div class="card-value">{s['total_findings']}</div><div class="card-label">Total Findings</div></div>
    <div class="card info"><div class="card-value">{s['operators_with_findings']}/{s['operators_scanned']}</div><div class="card-label">Operators Affected</div></div>
  </div>
"""


def render_heatmap(data):
    by_ap = data["summary"].get("by_anti_pattern", {})
    max_count = max(by_ap.values()) if by_ap else 1
    if max_count == 0:
        max_count = 1

    colors = {
        "AP-1": "#ec7a08", "AP-2": "#ec7a08", "AP-3": "#c9190b",
        "AP-4": "#ec7a08", "AP-5": "#ec7a08", "AP-6": "#c9190b",
        "AP-7": "#f0ab00", "AP-8": "#3e8635", "AP-9": "#f0ab00",
        "AP-10": "#f0ab00",
    }

    rows_html = ""
    for i in range(1, 11):
        ap = f"AP-{i}"
        count = by_ap.get(ap, 0)
        pct = (count / max_count) * 100 if count > 0 else 0
        color = colors.get(ap, "#888")
        title = html.escape(AP_TITLES.get(ap, ""))
        bar_label = str(count) if pct > 15 else ""
        rows_html += f"""
    <div class="heatmap-row">
      <div class="heatmap-label">{ap}</div>
      <div class="heatmap-bar-bg" title="{title}">
        <div class="heatmap-bar" style="width:{pct:.1f}%;background:{color}">{bar_label}</div>
      </div>
      <div class="heatmap-count">{count}</div>
    </div>"""

    return f"""
  <h2>Anti-Pattern Distribution</h2>
  <div class="heatmap">{rows_html}
  </div>
"""


def render_filters():
    ap_options = ''.join(
        f'<option value="{ap}">{ap}: {html.escape(AP_TITLES[ap][:40])}</option>'
        for ap in sorted(AP_TITLES.keys(), key=lambda x: int(x.split("-")[1]))
    )
    return """
  <div class="filters">
    <label>Severity:</label>
    <select id="filter-severity">
      <option value="">All</option>
      <option value="CRITICAL">Critical+</option>
      <option value="HIGH">High+</option>
      <option value="MEDIUM">Medium+</option>
      <option value="LOW">Any findings</option>
      <option value="CLEAN">Clean only</option>
    </select>
    <label>Anti-Pattern:</label>
    <select id="filter-ap">
      <option value="">All</option>
      """ + ap_options + """
    </select>
    <label>Search:</label>
    <input type="text" id="filter-search" placeholder="Operator name...">
    <span class="filter-count" id="filter-count"></span>
  </div>
"""


def github_blob_url(repo_url, commit, file_path, line):
    base = repo_url.rstrip("/")
    if base.endswith(".git"):
        base = base[:-4]
    return f"{base}/blob/{commit}/{file_path}#L{line}"


def render_operator_row(op):
    sr = op.get("scan_result")
    repo_name = html.escape(op.get("repo_name", ""))
    repo_url = html.escape(op.get("repo_url", ""))
    raw_repo_url = op.get("repo_url", "")
    raw_commit = op.get("commit", "")
    commit = html.escape(raw_commit[:12])
    components = op.get("components", [])
    clone_failed = op.get("clone_failed", False)

    if clone_failed:
        return f"""
<tr class="op-row visible" data-name="{repo_name}" data-total="0" data-critical="0" data-high="0" data-medium="0" data-low="0" data-aps="">
  <td colspan="7">
    <details class="op-detail">
      <summary>
        <span class="op-name">{repo_name}<span class="components">{', '.join(html.escape(c) for c in components)}</span></span>
        <span class="op-counts">{count_badge(0, 'CRITICAL')}{count_badge(0, 'HIGH')}{count_badge(0, 'MEDIUM')}{count_badge(0, 'LOW')}</span>
        <span class="op-total">-</span>
        <span class="op-aps">CLONE FAILED</span>
      </summary>
      <div class="clone-failed">Could not clone <a href="{repo_url}">{repo_url}</a></div>
    </details>
  </td>
</tr>"""

    if not sr:
        return f"""
<tr class="op-row visible" data-name="{repo_name}" data-total="0" data-critical="0" data-high="0" data-medium="0" data-low="0" data-aps="">
  <td colspan="7">
    <details class="op-detail">
      <summary>
        <span class="op-name">{repo_name}<span class="components">{', '.join(html.escape(c) for c in components)}</span></span>
        <span class="op-counts">{count_badge(0, 'CRITICAL')}{count_badge(0, 'HIGH')}{count_badge(0, 'MEDIUM')}{count_badge(0, 'LOW')}</span>
        <span class="op-total">0</span>
        <span class="op-aps">No scan data</span>
      </summary>
    </details>
  </td>
</tr>"""

    s = sr.get("findings_summary", {})
    total = s.get("total", 0)
    c = s.get("critical", 0)
    h = s.get("high", 0)
    m = s.get("medium", 0)
    l = s.get("low", 0)

    findings = sr.get("findings", [])
    detected_aps = sorted(set(f.get("id", "") for f in findings))
    aps_str = ", ".join(detected_aps)

    findings_html = ""
    if total > 0:
        grouped = defaultdict(list)
        for f in findings:
            grouped[f.get("id", "unknown")].append(f)

        for ap_id in sorted(grouped.keys(), key=lambda x: (SEVERITY_ORDER.get(grouped[x][0].get("severity", ""), 99), x)):
            ap_findings = grouped[ap_id]
            sev = ap_findings[0].get("severity", "MEDIUM")
            sev_cls = severity_class(sev)
            title = html.escape(AP_TITLES.get(ap_id, ap_id))
            findings_html += f'<div class="finding-group"><div class="finding-group-header {sev_cls}">{html.escape(ap_id)}: {title} ({len(ap_findings)})</div>'

            for f in ap_findings:
                ffile_raw = f.get("file", "")
                ffile = html.escape(ffile_raw)
                fline = f.get("line", 0)
                fsnippet = html.escape(f.get("code_snippet", ""))
                fdesc = html.escape(f.get("description", ""))
                frec = html.escape(f.get("recommendation", ""))
                fsev_cls = severity_class(f.get("severity", ""))
                blob_url = html.escape(github_blob_url(raw_repo_url, raw_commit, ffile_raw, fline))
                findings_html += f"""
      <div class="finding-item {fsev_cls}">
        <div class="finding-file"><a href="{blob_url}" target="_blank" rel="noopener">{ffile}:{fline}</a></div>
        <code class="finding-snippet">{fsnippet}</code>
        <div class="finding-desc">{fdesc}</div>
        <div class="finding-rec">{frec}</div>
      </div>"""
            findings_html += "</div>"
    else:
        findings_html = '<div class="clean-badge">No anti-patterns detected</div>'

    comp_html = ", ".join(html.escape(c) for c in components)

    return f"""
<tr class="op-row visible" data-name="{repo_name}" data-total="{total}" data-critical="{c}" data-high="{h}" data-medium="{m}" data-low="{l}" data-aps="{html.escape(aps_str)}">
  <td colspan="7">
    <details class="op-detail">
      <summary>
        <span class="op-name">{repo_name}<span class="components">{comp_html}</span></span>
        <span class="op-counts">{count_badge(c, 'CRITICAL')}{count_badge(h, 'HIGH')}{count_badge(m, 'MEDIUM')}{count_badge(l, 'LOW')}</span>
        <span class="op-total">{total}</span>
        <span class="op-aps">{html.escape(aps_str)}</span>
        <span class="op-link"><a href="{repo_url}" target="_blank">{commit}</a></span>
      </summary>
      <div class="findings-panel">{findings_html}</div>
    </details>
  </td>
</tr>"""


def render_table(data):
    operators = data.get("operators", [])
    operators.sort(key=lambda o: (
        -(o.get("scan_result", {}) or {}).get("findings_summary", {}).get("total", 0),
        -(o.get("scan_result", {}) or {}).get("findings_summary", {}).get("critical", 0),
        o.get("repo_name", ""),
    ))

    rows = "".join(render_operator_row(op) for op in operators)

    return f"""
  <h2>Operator Results</h2>
  <table class="op-table">
    <thead>
      <tr>
        <th data-sort="name">Operator <span class="sort-arrow">⇅</span></th>
        <th data-sort="critical">C <span class="sort-arrow">⇅</span></th>
        <th data-sort="high">H <span class="sort-arrow">⇅</span></th>
        <th data-sort="medium">M <span class="sort-arrow">⇅</span></th>
        <th data-sort="low">L <span class="sort-arrow">⇅</span></th>
        <th data-sort="total">Total <span class="sort-arrow">▼</span></th>
        <th>APs</th>
      </tr>
    </thead>
    <tbody id="op-tbody">
{rows}
    </tbody>
  </table>
"""


def render_footer(data):
    return f"""
  <footer>
    Generated by Operator Anti-Pattern Scanner v{html.escape(data.get('scanner_version', '1.0.0'))} &middot;
    Based on <a href="https://developers.redhat.com/articles/2026/07/06/5-anti-patterns-cause-kubernetes-operator-vulnerabilities">5 anti-patterns that cause K8s operator vulnerabilities</a> and
    <a href="https://developers.redhat.com/articles/2026/06/01/protect-your-kubernetes-operator-oomkill">Protect your Kubernetes Operator from OOMKill</a>
  </footer>
</div>
"""


def main():
    parser = argparse.ArgumentParser(description="Generate HTML report from release scan JSON")
    parser.add_argument("json_file", help="Path to release-scan-VERSION.json")
    parser.add_argument("--output", "-o", default=None, help="Output HTML file (default: same dir as JSON)")
    args = parser.parse_args()

    with open(args.json_file) as f:
        data = json.load(f)

    output = args.output
    if not output:
        p = Path(args.json_file)
        output = str(p.with_suffix(".html"))

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
        f"<title>OCP {html.escape(data['ocp_version'])} Anti-Pattern Report</title>",
        render_css(),
        "</head>",
        "<body>",
        render_header(data),
        render_summary(data),
        render_heatmap(data),
        render_filters(),
        render_table(data),
        render_footer(data),
        render_js(),
        "</body>",
        "</html>",
    ]

    with open(output, "w") as f:
        f.write("\n".join(parts))

    print(f"Report written to {output}")


if __name__ == "__main__":
    main()
