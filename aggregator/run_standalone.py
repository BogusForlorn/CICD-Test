#!/usr/bin/env python3
"""
aggregator/run_standalone.py
Standalone runner for use inside GitHub Actions / GitLab CI jobs.
Reads scan JSON files from RESULTS_INPUT_DIR, runs AI remediation,
posts PR decision, uploads report.
"""
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Add aggregator to path
sys.path.insert(0, os.path.dirname(__file__))

from ai_agent import AIRemediationAgent
from decision_engine import DecisionEngine
from pr_commenter import PRCommenter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("standalone-aggregator")

INPUT_DIR = os.environ.get("RESULTS_INPUT_DIR", "all-results")
OUTPUT_DIR = os.environ.get("RESULTS_OUTPUT_DIR", "output")

# Context from environment (set by CI)
SCAN_ID = os.environ.get("SCAN_ID", f"scan-{str(uuid.uuid4())[:8]}")
PLATFORM = os.environ.get("PLATFORM", "github")
REPO_FULL_NAME = os.environ.get("REPO_FULL_NAME", "")
PR_NUMBER = os.environ.get("PR_NUMBER", "")
PR_SHA = os.environ.get("PR_SHA", "")
BRANCH = os.environ.get("BRANCH", "")
BASE_BRANCH = os.environ.get("BASE_BRANCH", "main")
PR_LABELS = os.environ.get("PR_LABELS", "").split(",")
API_TOKEN = os.environ.get("API_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "") or os.environ.get("GITLAB_TOKEN", "")
AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_PROVIDER = os.environ.get("AI_PROVIDER", "anthropic")
AI_MODEL = os.environ.get("AI_MODEL", "claude-opus-4-6")
RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")
STORAGE_PROVIDER = os.environ.get("STORAGE_PROVIDER", "local")
DEFECTDOJO_URL = os.environ.get("DEFECTDOJO_URL", "")
DEFECTDOJO_TOKEN = os.environ.get("DEFECTDOJO_TOKEN", "")
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "")
GITLAB_PROJECT_ID = os.environ.get("GITLAB_PROJECT_ID", "")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ── Parse all scan result files ──────────────────────────────────────────
    raw_findings, scan_summary = parse_all_results(INPUT_DIR)
    log.info("Parsed %d raw findings from %s", len(raw_findings), INPUT_DIR)

    # ── Deduplicate ──────────────────────────────────────────────────────────
    findings = deduplicate(raw_findings)
    log.info("After dedup: %d unique findings", len(findings))

    # ── AI Remediation (1:1 per finding) ────────────────────────────────────
    if AI_API_KEY:
        agent = AIRemediationAgent(AI_API_KEY, AI_PROVIDER, AI_MODEL)
        for i, finding in enumerate(findings):
            log.info("[%d/%d] AI remediation: %s — %s",
                     i + 1, len(findings), finding["tool"], finding.get("rule_id", ""))
            finding["ai_remediation"] = agent.remediate(finding)
    else:
        log.warning("AI_API_KEY not set — using native remediation fallback")
        for finding in findings:
            finding["ai_remediation"] = {
                "remediation_status": "ai_disabled",
                "remediation_steps": [finding.get("native_remediation", "See tool documentation.")],
                "explanation": "",
                "estimated_effort": "unknown",
                "references": finding.get("references", []),
            }

    # ── Stamp findings ───────────────────────────────────────────────────────
    ts = datetime.now(timezone.utc).isoformat()
    context = {
        "scan_id": SCAN_ID, "platform": PLATFORM,
        "repo_full_name": REPO_FULL_NAME, "pr_number": PR_NUMBER,
        "pr_sha": PR_SHA, "branch": BRANCH, "gitlab_project_id": GITLAB_PROJECT_ID,
    }
    for finding in findings:
        finding.update({
            "finding_id": str(uuid.uuid4()),
            "scan_id": SCAN_ID,
            "platform": PLATFORM,
            "repo_full_name": REPO_FULL_NAME,
            "pr_number": PR_NUMBER,
            "pr_sha": PR_SHA,
            "branch": BRANCH,
            "timestamp": ts,
        })

    # ── Decision ─────────────────────────────────────────────────────────────
    policy = {"fail_on": ["CRITICAL", "HIGH"]}
    engine = DecisionEngine(policy)
    decision_data = engine.evaluate(findings, scan_summary)

    critical_high = [f for f in findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH")]

    # ── Upload report ─────────────────────────────────────────────────────────
    report_url = upload_report(findings, decision_data, context)

    decision = {
        "scan_id": SCAN_ID,
        "platform": PLATFORM,
        "repo_full_name": REPO_FULL_NAME,
        "pr_number": PR_NUMBER,
        "pr_sha": PR_SHA,
        "branch": BRANCH,
        "result": decision_data["result"],
        "total_findings": decision_data["total_findings"],
        "critical_high_count": len(critical_high),
        "critical_high_findings": critical_high,
        "all_findings": findings,
        "failed_tools": decision_data["failed_tools"],
        "tool_summary": decision_data["tool_summary"],
        "dashboard_url": f"{DASHBOARD_URL}/scan/{SCAN_ID}" if DASHBOARD_URL else "",
        "report_url": report_url,
        "timestamp": ts,
    }

    # ── Save decision JSON locally ────────────────────────────────────────────
    decision_path = os.path.join(OUTPUT_DIR, "decision.json")
    with open(decision_path, "w") as f:
        json.dump({k: v for k, v in decision.items() if k != "all_findings"}, f, indent=2, default=str)

    findings_path = os.path.join(OUTPUT_DIR, "all_findings.json")
    with open(findings_path, "w") as f:
        json.dump(findings, f, indent=2, default=str)

    log.info("Decision: %s | %d total findings | %d critical/high",
             decision["result"], len(findings), len(critical_high))

    # ── Post to Git ───────────────────────────────────────────────────────────
    if API_TOKEN and PR_NUMBER:
        commenter = PRCommenter(
            platform=PLATFORM,
            api_token=API_TOKEN,
            repo_full_name=REPO_FULL_NAME,
            pr_number=PR_NUMBER,
            pr_sha=PR_SHA,
            gitlab_project_id=GITLAB_PROJECT_ID,
        )
        commenter.apply_decision(decision)
    else:
        log.warning("Skipping PR comment — API_TOKEN or PR_NUMBER not set")

    # Return non-zero only if we want CI to fail hard (optional — the Git status check handles blocking)
    # We return 0 always — blocking is done via Git status checks, not CI exit code
    sys.exit(0)


def parse_all_results(input_dir: str):
    """Walk the results directory and parse all known tool outputs."""
    # Import parsers
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
    from parsers.trivy_parser import parse_trivy_fs, parse_trivy_image
    from parsers.semgrep_parser import parse_semgrep
    from parsers.gitleaks_parser import parse_gitleaks
    from parsers.checkov_parser import parse_checkov
    from parsers.zap_parser import parse_zap

    findings = []
    scan_summary = {}
    input_path = Path(input_dir)

    PARSERS = [
        ("trivy_fs.json",       parse_trivy_fs,    "trivy"),
        ("trivy_image.json",    parse_trivy_image,  "trivy"),
        ("semgrep.json",        parse_semgrep,      "semgrep"),
        ("gitleaks.json",       parse_gitleaks,     "gitleaks"),
        ("results_json.json",   parse_checkov,      "checkov"),
        ("checkov_results.json",parse_checkov,      "checkov"),
        ("zap.json",            parse_zap,          "zap"),
    ]

    for filename, parser_fn, tool in PARSERS:
        for result_file in input_path.rglob(filename):
            log.info("Parsing %s with %s", result_file, parser_fn.__name__)
            try:
                tool_findings = parser_fn(str(result_file))
                findings.extend(tool_findings)
                # Build summary per tool
                sev_counts = {}
                for f in tool_findings:
                    sev = f.get("severity", "UNKNOWN")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                max_sev = max(sev_counts, key=lambda s: ["CRITICAL","HIGH","MEDIUM","LOW","INFO","UNKNOWN"].index(s)
                              if s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","UNKNOWN"] else 999) if sev_counts else "NONE"
                fail_sevs = {"CRITICAL", "HIGH"}
                scan_summary[tool] = {
                    "tool": tool,
                    "status": "FAIL" if any(s in fail_sevs for s in sev_counts) else "PASS",
                    "total_findings": len(tool_findings),
                    "severity_counts": sev_counts,
                    "max_severity": max_sev,
                }
            except Exception as e:
                log.error("Failed to parse %s: %s", result_file, e)

    return findings, scan_summary


def deduplicate(findings: list) -> list:
    seen, unique = set(), []
    for f in findings:
        key = (f.get("tool"), f.get("file"), f.get("line"), f.get("rule_id"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def upload_report(findings: list, decision: dict, context: dict) -> str:
    report = {"scan_id": SCAN_ID, "context": context,
              "decision_summary": decision, "findings": findings}
    report_json = json.dumps(report, indent=2, default=str).encode()
    key = f"security-reports/{SCAN_ID}/full-report.json"

    try:
        if STORAGE_PROVIDER == "s3" and RESULTS_BUCKET:
            import boto3
            s3 = boto3.client("s3")
            s3.put_object(Bucket=RESULTS_BUCKET, Key=key, Body=report_json,
                          ContentType="application/json")
            return f"https://{RESULTS_BUCKET}.s3.amazonaws.com/{key}"
        elif STORAGE_PROVIDER == "azure_blob" and RESULTS_BUCKET:
            from azure.storage.blob import BlobServiceClient
            conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "")
            client = BlobServiceClient.from_connection_string(conn_str)
            blob = client.get_blob_client(container=RESULTS_BUCKET, blob=key)
            blob.upload_blob(report_json, overwrite=True)
            return f"https://{RESULTS_BUCKET}.blob.core.windows.net/{key}"
    except Exception as e:
        log.error("Upload failed: %s", e)

    # Local fallback
    local_path = os.path.join(OUTPUT_DIR, "full-report.json")
    with open(local_path, "w") as f:
        f.write(report_json.decode())
    return f"file://{os.path.abspath(local_path)}"


if __name__ == "__main__":
    main()
