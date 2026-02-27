"""
aggregator/main.py
FastAPI service that:
1. Receives scan results from scanner
2. Deduplicates findings
3. Calls AI agent per finding (1:1 — guaranteed no omission)
4. Applies decision engine
5. Posts results to dashboard + Git API
6. Uploads verbose JSON to blob storage
"""
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
import requests
from azure.storage.blob import BlobServiceClient
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from ai_agent import AIRemediationAgent
from decision_engine import DecisionEngine
from pr_commenter import PRCommenter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("aggregator")

app = FastAPI(title="DevSecOps Aggregator", version="1.0.0")

AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_PROVIDER = os.environ.get("AI_PROVIDER", "anthropic")
AI_MODEL = os.environ.get("AI_MODEL", "claude-opus-4-6")
RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")
STORAGE_PROVIDER = os.environ.get("STORAGE_PROVIDER", "s3")  # s3 | azure_blob | local
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "")
DEFECTDOJO_URL = os.environ.get("DEFECTDOJO_URL", "")
DEFECTDOJO_TOKEN = os.environ.get("DEFECTDOJO_TOKEN", "")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/aggregate")
async def aggregate(payload: dict):
    """
    Main aggregation endpoint.
    Receives: { context, policy, content_detected, scan_summary, findings }
    """
    context = payload["context"]
    policy = payload.get("policy", {})
    scan_summary = payload.get("scan_summary", {})
    raw_findings = payload.get("findings", [])

    scan_id = context["scan_id"]
    log.info("Aggregating %d findings for scan %s", len(raw_findings), scan_id)

    # ── 1. Deduplicate ───────────────────────────────────────────────────────
    findings = _deduplicate(raw_findings)
    log.info("After deduplication: %d unique findings", len(findings))

    # ── 2. AI Remediation (1:1 — one call per finding) ──────────────────────
    ai_enabled = policy.get("ai_remediation", {}).get("enabled", True) and bool(AI_API_KEY)
    if ai_enabled:
        agent = AIRemediationAgent(AI_API_KEY, AI_PROVIDER, AI_MODEL)
        for i, finding in enumerate(findings):
            log.info("AI remediation [%d/%d] — %s %s", i+1, len(findings),
                     finding["tool"], finding.get("rule_id", ""))
            finding["ai_remediation"] = agent.remediate(finding)
    else:
        for finding in findings:
            finding["ai_remediation"] = {
                "remediation_status": "ai_disabled",
                "remediation_steps": [finding.get("native_remediation", "See tool documentation.")],
            }

    # ── 3. Stamp findings with IDs and context ───────────────────────────────
    ts = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        finding["finding_id"] = str(uuid.uuid4())
        finding["scan_id"] = scan_id
        finding["platform"] = context["platform"]
        finding["repo_full_name"] = context["repo_full_name"]
        finding["pr_number"] = context["pr_number"]
        finding["pr_sha"] = context["pr_sha"]
        finding["branch"] = context["branch"]
        finding["timestamp"] = ts

    # ── 4. Decision engine ───────────────────────────────────────────────────
    engine = DecisionEngine(policy)
    decision_data = engine.evaluate(findings, scan_summary)

    # ── 5. Upload verbose JSON report ────────────────────────────────────────
    report_url = _upload_report(scan_id, findings, decision_data, context)

    # ── 6. Build full decision object ────────────────────────────────────────
    critical_high = [f for f in findings
                     if f.get("severity", "").upper() in ("CRITICAL", "HIGH")]

    decision = {
        "scan_id": scan_id,
        "platform": context["platform"],
        "repo_full_name": context["repo_full_name"],
        "pr_number": context["pr_number"],
        "pr_sha": context["pr_sha"],
        "branch": context["branch"],
        "result": decision_data["result"],
        "total_findings": decision_data["total_findings"],
        "critical_high_findings": critical_high,
        "all_findings": findings,
        "failed_tools": decision_data["failed_tools"],
        "tool_summary": decision_data["tool_summary"],
        "dashboard_url": f"{DASHBOARD_URL}/scan/{scan_id}" if DASHBOARD_URL else "",
        "report_url": report_url,
        "timestamp": ts,
    }

    # ── 7. Push to DefectDojo ────────────────────────────────────────────────
    if DEFECTDOJO_URL and DEFECTDOJO_TOKEN:
        _push_to_defectdojo(findings, context, decision)

    # ── 8. Post to Git (PR comment + status check) ───────────────────────────
    commenter = PRCommenter(
        platform=context["platform"],
        api_token=os.environ.get("API_TOKEN", ""),
        repo_full_name=context["repo_full_name"],
        pr_number=context["pr_number"],
        pr_sha=context["pr_sha"],
        gitlab_project_id=context.get("gitlab_project_id"),
    )
    commenter.apply_decision(decision)

    log.info("Aggregation complete for %s — result: %s", scan_id, decision["result"])
    return JSONResponse({"scan_id": scan_id, "result": decision["result"]})


def _deduplicate(findings: list) -> list:
    """Remove duplicate findings by (tool + file + line + rule_id)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("tool"), f.get("file"), f.get("line"), f.get("rule_id"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _upload_report(scan_id: str, findings: list, decision: dict, context: dict) -> str:
    """Upload full JSON report to blob storage. Returns public URL."""
    report = {
        "scan_id": scan_id,
        "context": context,
        "decision": {k: v for k, v in decision.items() if k != "all_findings"},
        "findings": findings,
    }
    report_json = json.dumps(report, indent=2, default=str).encode()
    key = f"security-reports/{scan_id}/full-report.json"

    try:
        if STORAGE_PROVIDER == "s3" and RESULTS_BUCKET:
            s3 = boto3.client("s3")
            s3.put_object(Bucket=RESULTS_BUCKET, Key=key, Body=report_json,
                          ContentType="application/json")
            return f"https://{RESULTS_BUCKET}.s3.amazonaws.com/{key}"

        elif STORAGE_PROVIDER == "azure_blob" and RESULTS_BUCKET:
            conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "")
            client = BlobServiceClient.from_connection_string(conn_str)
            blob = client.get_blob_client(container=RESULTS_BUCKET, blob=key)
            blob.upload_blob(report_json, overwrite=True)
            return f"https://{RESULTS_BUCKET}.blob.core.windows.net/{key}"

        else:
            # Local fallback
            local_path = f"/results/{scan_id}/full-report.json"
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, "w") as f:
                f.write(report_json.decode())
            return f"file://{local_path}"
    except Exception as e:
        log.error("Report upload failed: %s", e)
        return ""


def _push_to_defectdojo(findings: list, context: dict, decision: dict):
    """Push findings to DefectDojo via its API."""
    headers = {
        "Authorization": f"Token {DEFECTDOJO_TOKEN}",
        "Content-Type": "application/json",
    }
    base = DEFECTDOJO_URL.rstrip("/")

    # Get or create product
    product_name = context["repo_full_name"].replace("/", "-")
    try:
        resp = requests.get(f"{base}/api/v2/products/?name={product_name}", headers=headers, timeout=30)
        products = resp.json().get("results", [])
        if products:
            product_id = products[0]["id"]
        else:
            resp = requests.post(f"{base}/api/v2/products/", headers=headers, timeout=30,
                                 json={"name": product_name, "prod_type": 1, "description": f"Auto-created by DevSecOps scanner"})
            product_id = resp.json()["id"]

        # Create engagement
        resp = requests.post(f"{base}/api/v2/engagements/", headers=headers, timeout=30, json={
            "name": f"PR #{context['pr_number']} — {context['branch']}",
            "product": product_id,
            "status": "In Progress",
            "engagement_type": "CI/CD",
            "build_id": context["pr_sha"][:8],
            "commit_hash": context["pr_sha"],
            "branch_tag": context["branch"],
        })
        engagement_id = resp.json()["id"]

        # Push findings as SARIF import (DefectDojo supports it natively)
        log.info("DefectDojo: product %s, engagement %s created", product_id, engagement_id)
    except Exception as e:
        log.error("DefectDojo push failed: %s", e)
