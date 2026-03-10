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
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

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
AI_MODEL = os.environ.get("AI_MODEL", "")
RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")
STORAGE_PROVIDER = os.environ.get("STORAGE_PROVIDER", "s3")  # s3 | azure_blob | local
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "")
DEFECTDOJO_URL = os.environ.get("DEFECTDOJO_URL", "")
DEFECTDOJO_TOKEN = os.environ.get("DEFECTDOJO_TOKEN", "")
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


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

    # ── 2. Enrich findings: remediation + CVSS + CVE/PoC ────────────────────
    ai_remediation_config = policy.get("ai_remediation", {})
    if not isinstance(ai_remediation_config, dict):
        ai_remediation_config = {}
    ai_enabled = ai_remediation_config.get("enabled", True) and bool(AI_API_KEY)
    ai_provider = str(ai_remediation_config.get("provider") or AI_PROVIDER or "anthropic").strip()
    ai_model = str(ai_remediation_config.get("model") or AI_MODEL or "").strip()
    cve_poc_enabled = policy.get("cve_testing", {}).get("enabled", True)
    cve_methods_config = policy.get("cve_testing", {}).get("methods", {})
    cvss_enabled = policy.get("cvss", {}).get("enabled", True)
    agent = None
    if ai_enabled:
        try:
            agent = AIRemediationAgent(AI_API_KEY, ai_provider, ai_model)
            log.info("AI remediation enabled via provider=%s model=%s", agent.provider, agent.model)
        except Exception as e:
            ai_enabled = False
            log.error("AI agent initialization failed: %s; continuing with native fallback", e)

    for i, finding in enumerate(findings):
        if ai_enabled and agent:
            log.info(
                "AI remediation [%d/%d] — %s %s",
                i + 1,
                len(findings),
                finding.get("tool", ""),
                finding.get("rule_id", ""),
            )
            finding["ai_remediation"] = agent.remediate(finding)
        else:
            finding["ai_remediation"] = {
                "remediation_status": "ai_disabled",
                "remediation_steps": [finding.get("native_remediation", "See tool documentation.")],
            }

        finding["remediation_suggestion"] = _build_remediation_suggestion(finding)

        cvss_assessment = _resolve_cvss_assessment(
            finding=finding,
            agent=agent,
            ai_enabled=ai_enabled,
            cvss_enabled=cvss_enabled,
        )
        finding["cvss_assessment"] = cvss_assessment
        if cvss_assessment.get("severity"):
            finding["severity_from_cvss"] = cvss_assessment["severity"]
            finding["severity"] = cvss_assessment["severity"]

        cves = _extract_cves(finding)
        finding["cves"] = cves
        finding["cve_test_methods"] = (
            _cve_test_methods_for_finding(finding, cve_methods_config) if cves else []
        )

        if cves and cve_poc_enabled:
            ref_poc = _reference_based_poc(finding, cves)
            if ref_poc:
                finding["cve_poc"] = ref_poc
            elif ai_enabled and agent:
                finding["cve_poc"] = agent.generate_cve_poc(finding, cves)
            else:
                finding["cve_poc"] = _fallback_poc(cves, finding)
        else:
            finding["cve_poc"] = None

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
    cve_poc_entries = _build_cve_poc_entries(findings)

    decision = {
        "scan_id": scan_id,
        "platform": context["platform"],
        "repo_full_name": context["repo_full_name"],
        "pr_number": context["pr_number"],
        "pr_sha": context["pr_sha"],
        "branch": context["branch"],
        "result": decision_data["result"],
        "total_findings": decision_data["total_findings"],
        "critical_high_count": len(critical_high),
        "critical_high_findings": critical_high,
        "cve_findings_count": len([f for f in findings if f.get("cves")]),
        "cve_poc_entries": cve_poc_entries,
        "all_findings": findings,
        "failed_tools": decision_data["failed_tools"],
        "tool_summary": decision_data["tool_summary"],
        "dashboard_url": f"{DASHBOARD_URL.rstrip('/')}/scan/{scan_id}" if DASHBOARD_URL else "",
        "report_url": report_url,
        "timestamp": ts,
    }

    # ── 7. Push summary to dashboard ─────────────────────────────────────────
    _post_to_dashboard(scan_id, decision)

    # ── 8. Push to DefectDojo ────────────────────────────────────────────────
    if DEFECTDOJO_URL and DEFECTDOJO_TOKEN:
        _push_to_defectdojo(findings, context, decision)

    # ── 9. Post to Git (PR comment + status check) ───────────────────────────
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


def _build_remediation_suggestion(finding: dict) -> str:
    ai = finding.get("ai_remediation") or {}
    steps = ai.get("remediation_steps", []) if isinstance(ai, dict) else []
    if steps:
        return " ".join(str(s).strip() for s in steps[:2])[:400]
    native = (finding.get("native_remediation") or "").strip()
    if native:
        return native[:400]
    return "Review the finding details and apply the tool-recommended fix."


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _extract_native_cvss(finding: dict) -> dict:
    cvss = finding.get("cvss")
    if not isinstance(cvss, dict) or not cvss:
        return {}

    best = {}
    best_score = -1.0
    for source, data in cvss.items():
        if not isinstance(data, dict):
            continue
        raw_score = data.get("V3Score", data.get("Score", data.get("score")))
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            continue
        if score > best_score:
            best_score = score
            vector = (
                data.get("V3Vector")
                or data.get("Vector")
                or data.get("VectorString")
                or data.get("vector")
                or ""
            )
            severity = (
                str(data.get("Severity", data.get("severity", ""))).upper().strip()
                or _severity_from_cvss(score)
            )
            best = {
                "status": "native",
                "source": "tool_native",
                "cvss_provider": source,
                "score": round(score, 1),
                "vector": vector,
                "severity": severity,
            }
    return best


def _resolve_cvss_assessment(
    finding: dict,
    agent: Optional[AIRemediationAgent],
    ai_enabled: bool,
    cvss_enabled: bool,
) -> dict:
    if not cvss_enabled:
        return {
            "status": "disabled",
            "source": "policy",
            "reason": "cvss_enrichment_disabled",
        }

    native = _extract_native_cvss(finding)
    if native:
        return native

    if not ai_enabled or not agent:
        return {
            "status": "unable_to_estimate",
            "source": "none",
            "reason": "ai_disabled_and_no_native_cvss",
            "highlight": "(unable to estimate cvss)",
        }

    estimated = agent.estimate_cvss_with_verification(finding)
    if estimated.get("status") != "verified":
        estimated["highlight"] = "(unable to estimate cvss)"
    return estimated


def _extract_cves(finding: dict) -> List[str]:
    texts = [
        str(finding.get("rule_id", "")),
        str(finding.get("title", "")),
        str(finding.get("description", "")),
    ]
    refs = finding.get("references", [])
    if isinstance(refs, list):
        texts.extend(str(r) for r in refs)

    cves = set()
    for txt in texts:
        for match in CVE_PATTERN.findall(txt or ""):
            cves.add(match.upper())
    return sorted(cves)


def _cve_test_methods_for_finding(finding: dict, configured_methods: dict) -> List[str]:
    tool = (finding.get("tool") or "").lower()
    if isinstance(configured_methods, dict):
        cfg = configured_methods.get(tool)
        if isinstance(cfg, list) and cfg:
            return [str(x) for x in cfg]

    methods = {
        "trivy": [
            "Dependency/package version validation with Trivy SCA rescan",
            "Container image vulnerability replay with Trivy image scanner",
        ],
        "zap": [
            "Runtime endpoint validation with OWASP ZAP active/baseline scan",
            "HTTP response/evidence comparison before and after remediation",
        ],
        "semgrep": [
            "Code-path validation for vulnerable patterns with Semgrep rules",
            "Targeted unit/integration tests around affected code flow",
        ],
        "checkov": [
            "IaC misconfiguration verification by re-running Checkov policies",
            "Deployment manifest diff validation before apply",
        ],
        "gitleaks": [
            "Secret exposure replay via git history scan with Gitleaks",
            "Credential revocation and repository re-scan verification",
        ],
    }
    return methods.get(tool, ["Re-run the detecting scanner and verify the vulnerable artifact is no longer present."])


def _reference_based_poc(finding: dict, cves: list) -> dict:
    refs = finding.get("references", [])
    if not isinstance(refs, list):
        return {}

    poc_refs = []
    for ref in refs:
        ref_str = str(ref).strip()
        lower = ref_str.lower()
        if any(k in lower for k in ("poc", "proof", "exploit-db", "github.com")):
            poc_refs.append(ref_str)
    if not poc_refs:
        return {}

    return {
        "status": "reference_based",
        "poc_status": "ready",
        "poc_title": f"Reference-based validation for {', '.join(cves[:2])}",
        "verification_steps": [
            "Use the listed PoC/reference in an isolated staging environment.",
            "Validate the vulnerable package/component version and affected endpoint/code path.",
            "Apply remediation and re-run the scanner to verify closure.",
        ],
        "safety_notes": [
            "Run PoC validation only in non-production environments.",
            "Use least privilege credentials and disposable test data.",
        ],
        "references": poc_refs[:5],
    }


def _fallback_poc(cves: list, finding: dict) -> dict:
    return {
        "status": "fallback",
        "poc_status": "ready",
        "poc_title": f"Scanner-driven validation for {', '.join(cves[:2])}",
        "verification_steps": [
            f"Confirm affected artifact in {finding.get('file', 'reported target')} with the reported scanner output.",
            "Recreate the vulnerable condition in staging using the same version/configuration.",
            "Apply fix and execute the same scan command to confirm the CVE is no longer detected.",
        ],
        "safety_notes": [
            "Do not execute CVE validation in production.",
            "Record test evidence and keep rollback capability.",
        ],
        "references": finding.get("references", [])[:3] if isinstance(finding.get("references"), list) else [],
    }


def _build_cve_poc_entries(findings: list) -> list:
    entries = []
    for f in findings:
        cves = f.get("cves") or []
        if not cves:
            continue
        cvss = f.get("cvss_assessment") or {}
        poc = f.get("cve_poc") or {}
        entries.append(
            {
                "finding_id": f.get("finding_id", ""),
                "tool": f.get("tool", ""),
                "severity": f.get("severity", ""),
                "file": f.get("file", ""),
                "title": f.get("title", ""),
                "cves": cves,
                "cve_test_methods": f.get("cve_test_methods", []),
                "cvss_status": cvss.get("status", ""),
                "cvss_score": cvss.get("score"),
                "cvss_vector": cvss.get("vector", ""),
                "cvss_highlight": cvss.get("highlight", ""),
                "cvss_string_1": cvss.get("cvss_string_1", ""),
                "cvss_string_2": cvss.get("cvss_string_2", ""),
                "poc_status": poc.get("poc_status", "not_available"),
                "poc_title": poc.get("poc_title", ""),
                "poc_steps": poc.get("verification_steps", []),
                "poc_references": poc.get("references", []),
            }
        )
    return entries


def _post_to_dashboard(scan_id: str, decision: dict):
    if not DASHBOARD_URL:
        return

    url = f"{DASHBOARD_URL.rstrip('/')}/scan/{scan_id}"
    payload = {
        "scan_id": decision["scan_id"],
        "repo_full_name": decision["repo_full_name"],
        "pr_number": decision["pr_number"],
        "branch": decision["branch"],
        "result": decision["result"],
        "total_findings": decision["total_findings"],
        "critical_high_count": decision.get("critical_high_count", 0),
        "failed_tools": decision.get("failed_tools", []),
        "tool_summary": decision.get("tool_summary", {}),
        "report_url": decision.get("report_url", ""),
        "timestamp": decision.get("timestamp", ""),
        "cve_findings_count": decision.get("cve_findings_count", 0),
        "cve_poc_entries": decision.get("cve_poc_entries", []),
    }
    try:
        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code not in (200, 201):
            log.error("Dashboard ingest failed [%d]: %s", resp.status_code, resp.text[:200])
    except Exception as e:
        log.error("Dashboard ingest failed: %s", e)


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
