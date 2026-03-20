"""
scanner/report.py — Terminal, JSON, and HTML report generation
"""

import json
import sys
from datetime import datetime

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH":     "\033[91m",  # bright red
    "MEDIUM":   "\033[93m",  # yellow
    "LOW":      "\033[94m",  # blue
    "INFO":     "\033[96m",  # cyan
    "PASS":     "\033[92m",  # green
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _color(sev, text):
    return f"{SEVERITY_COLORS.get(sev, '')}{text}{RESET}"


def generate_report(results, fmt, outfile, elapsed, target, verbose=False):
    if fmt == "terminal":
        _print_terminal(results, elapsed, target, verbose)
    elif fmt == "json":
        output = _build_json(results, elapsed, target)
        if outfile:
            with open(outfile, "w") as f:
                json.dump(output, f, indent=2)
            print(f"  [+] JSON report saved to: {outfile}")
        else:
            print(json.dumps(output, indent=2))
    elif fmt == "html":
        html = _build_html(results, elapsed, target)
        if outfile:
            with open(outfile, "w") as f:
                f.write(html)
            print(f"  [+] HTML report saved to: {outfile}")
        else:
            print(html)


def _print_terminal(results, elapsed, target, verbose):
    counts = {}
    for r in results:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1

    findings = [r for r in results if r["severity"] != "PASS"]

    print(f"\n{'─'*60}")
    print(f"{BOLD}  SCAN RESULTS — {target}{RESET}")
    print(f"{'─'*60}")
    print(f"  Completed in {elapsed}s  |  "
          f"{_color('HIGH', str(counts.get('HIGH', 0)) + ' HIGH')}  "
          f"{_color('MEDIUM', str(counts.get('MEDIUM', 0)) + ' MEDIUM')}  "
          f"{_color('LOW', str(counts.get('LOW', 0)) + ' LOW')}  "
          f"{_color('INFO', str(counts.get('INFO', 0)) + ' INFO')}")
    print(f"{'─'*60}\n")

    if not findings:
        print(f"  {_color('PASS', '[+] No issues found.')}\n")
        return

    last_check = None
    for r in results:
        if r["severity"] == "PASS" and not verbose:
            continue
        if r["check"] != last_check:
            print(f"\n{BOLD}  [{r['check']}]{RESET}")
            last_check = r["check"]

        sev_label = _color(r["severity"], f"[{r['severity']:8}]")
        print(f"  {sev_label}  {r['title']}")
        if r.get("description"):
            print(f"              {r['description']}")
        if r.get("evidence") and verbose:
            print(f"              Evidence: {r['evidence']}")
        if r.get("recommendation") and r["severity"] not in ("PASS",):
            print(f"              Fix: {r['recommendation']}")
        print()


def _build_json(results, elapsed, target):
    return {
        "scanner": "WebScan",
        "target": target,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "elapsed_seconds": elapsed,
        "summary": {
            sev: sum(1 for r in results if r["severity"] == sev)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS")
        },
        "findings": [r for r in results if r["severity"] != "PASS"],
        "passed": [r for r in results if r["severity"] == "PASS"],
    }


def _build_html(results, elapsed, target):
    findings = [r for r in results if r["severity"] != "PASS"]
    sev_color = {"CRITICAL": "#e74c3c", "HIGH": "#e74c3c", "MEDIUM": "#f39c12",
                 "LOW": "#3498db", "INFO": "#1abc9c", "PASS": "#2ecc71"}

    rows = ""
    for r in findings:
        color = sev_color.get(r["severity"], "#888")
        rows += f"""
        <tr>
          <td><span style="color:{color};font-weight:bold;">{r['severity']}</span></td>
          <td>{r['check']}</td>
          <td>{r['title']}</td>
          <td>{r.get('description','')}</td>
          <td style="font-size:0.85em;color:#888;">{r.get('recommendation','')}</td>
        </tr>"""

    counts = {sev: sum(1 for r in results if r["severity"] == sev)
              for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>WebScan Report — {target}</title>
  <style>
    body {{ font-family: monospace; background: #1a1a2e; color: #eee; padding: 2rem; }}
    h1 {{ color: #00d4ff; }}
    .meta {{ color: #888; margin-bottom: 2rem; }}
    .stats {{ display: flex; gap: 1rem; margin-bottom: 2rem; }}
    .stat {{ background: #16213e; padding: 0.75rem 1.25rem; border-radius: 6px; }}
    .stat span {{ font-size: 1.5rem; font-weight: bold; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ background: #16213e; padding: 0.75rem; text-align: left; }}
    td {{ padding: 0.75rem; border-bottom: 1px solid #333; vertical-align: top; }}
    tr:hover td {{ background: #16213e; }}
  </style>
</head>
<body>
  <h1>WebScan Report</h1>
  <p class="meta">Target: {target} | Scanned: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC | Elapsed: {elapsed}s</p>
  <div class="stats">
    <div class="stat"><div style="color:#888;font-size:0.8em;">HIGH</div><span style="color:#e74c3c;">{counts['HIGH']}</span></div>
    <div class="stat"><div style="color:#888;font-size:0.8em;">MEDIUM</div><span style="color:#f39c12;">{counts['MEDIUM']}</span></div>
    <div class="stat"><div style="color:#888;font-size:0.8em;">LOW</div><span style="color:#3498db;">{counts['LOW']}</span></div>
    <div class="stat"><div style="color:#888;font-size:0.8em;">INFO</div><span style="color:#1abc9c;">{counts['INFO']}</span></div>
  </div>
  <table>
    <tr><th>Severity</th><th>Check</th><th>Title</th><th>Description</th><th>Recommendation</th></tr>
    {rows if rows else '<tr><td colspan="5" style="color:#2ecc71;">No findings</td></tr>'}
  </table>
</body>
</html>"""
