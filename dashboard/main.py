"""
dashboard/main.py
Lightweight FastAPI dashboard — PR-centric security scan results viewer.
Complements DefectDojo with a real-time per-scan view.
"""
import json
import logging
import os
from datetime import datetime
from typing import List, Optional

import boto3
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

log = logging.getLogger("dashboard")
app = FastAPI(title="DevSecOps Dashboard", version="1.0.0")

RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")
STORAGE_PROVIDER = os.environ.get("STORAGE_PROVIDER", "s3")

# In-memory scan index (production: use Redis or a DB)
_scans: dict = {}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan/{scan_id}")
async def ingest_scan(scan_id: str, payload: dict):
    """Called by aggregator to register a completed scan."""
    _scans[scan_id] = {
        "scan_id": scan_id,
        "repo": payload.get("repo_full_name", ""),
        "pr_number": payload.get("pr_number", ""),
        "branch": payload.get("branch", ""),
        "result": payload.get("result", "UNKNOWN"),
        "total_findings": payload.get("total_findings", 0),
        "critical_high_count": payload.get("critical_high_count", 0),
        "failed_tools": payload.get("failed_tools", []),
        "tool_summary": payload.get("tool_summary", {}),
        "report_url": payload.get("report_url", ""),
        "timestamp": payload.get("timestamp", datetime.utcnow().isoformat()),
    }
    return JSONResponse({"status": "registered"})


@app.get("/scan/{scan_id}", response_class=JSONResponse)
async def get_scan(scan_id: str):
    if scan_id not in _scans:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    return _scans[scan_id]


@app.get("/scans", response_class=JSONResponse)
async def list_scans(repo: Optional[str] = None, limit: int = 50):
    scans = list(_scans.values())
    if repo:
        scans = [s for s in scans if s["repo"] == repo]
    scans.sort(key=lambda s: s.get("timestamp", ""), reverse=True)
    return scans[:limit]


@app.get("/", response_class=HTMLResponse)
async def dashboard_ui():
    """Serve the dashboard HTML UI."""
    return HTMLResponse(_render_dashboard())


def _render_dashboard() -> str:
    scans = list(_scans.values())
    scans.sort(key=lambda s: s.get("timestamp", ""), reverse=True)

    rows = ""
    for s in scans[:100]:
        status_class = "pass" if s["result"] == "PASS" else "fail"
        status_label = (
            "✅ PASS — Awaiting Approval" if s["result"] == "PASS"
            else f"❌ FAIL ({s['critical_high_count']} critical/high)"
        )
        rows += f"""
        <tr class="{status_class}">
          <td><code>{s['scan_id']}</code></td>
          <td>{s['repo']}</td>
          <td>#{s['pr_number']}</td>
          <td><code>{s['branch']}</code></td>
          <td>{status_label}</td>
          <td>{s['total_findings']}</td>
          <td>{s.get('timestamp', '')[:19]}</td>
          <td><a href="{s.get('report_url', '#')}">JSON Report</a></td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><title>DevSecOps Dashboard</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: monospace; background: #0a0c0f; color: #c8d4e0; margin: 0; padding: 20px; }}
  h1 {{ color: #00e87a; font-size: 28px; margin-bottom: 4px; }}
  h2 {{ color: #4da6ff; font-size: 16px; margin-bottom: 24px; font-weight: 300; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #141820; color: #00e87a; padding: 10px 14px; text-align: left; border-bottom: 2px solid #2a3545; text-transform: uppercase; letter-spacing: 1px; }}
  td {{ padding: 9px 14px; border-bottom: 1px solid #1e2530; }}
  tr.pass td {{ border-left: 3px solid #00e87a; }}
  tr.fail td {{ border-left: 3px solid #ff4545; }}
  a {{ color: #4da6ff; text-decoration: none; }}
  code {{ background: rgba(0,232,122,0.1); padding: 1px 6px; border-radius: 2px; color: #00d4ff; }}
  .meta {{ color: #6a7a8e; font-size: 12px; margin-bottom: 20px; }}
  .refresh {{ color: #6a7a8e; font-size: 11px; float: right; margin-top: -36px; }}
</style>
</head>
<body>
<h1>DevSecOps Security Dashboard</h1>
<h2>CI/CD Security Gate — Pull Request Scan Results</h2>
<div class="meta">Showing {len(scans)} scans. Refresh page for latest results.</div>
<div class="refresh">Auto-refresh: <a href="javascript:location.reload()">↻ Reload</a></div>
<table>
<thead>
  <tr>
    <th>Scan ID</th><th>Repository</th><th>PR</th><th>Branch</th>
    <th>Status</th><th>Findings</th><th>Timestamp</th><th>Report</th>
  </tr>
</thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"""
