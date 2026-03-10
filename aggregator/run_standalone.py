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
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

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
AI_MODEL = os.environ.get("AI_MODEL", "")
RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET", "")
STORAGE_PROVIDER = os.environ.get("STORAGE_PROVIDER", "local")
DEFECTDOJO_URL = os.environ.get("DEFECTDOJO_URL", "")
DEFECTDOJO_TOKEN = os.environ.get("DEFECTDOJO_TOKEN", "")
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "")
GITLAB_PROJECT_ID = os.environ.get("GITLAB_PROJECT_ID", "")
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CVSS_ENABLED = os.environ.get("CVSS_ENABLED", "true").lower() == "true"


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ── Parse all scan result files ──────────────────────────────────────────
    raw_findings, scan_summary = parse_all_results(INPUT_DIR)
    log.info("Parsed %d raw findings from %s", len(raw_findings), INPUT_DIR)

    # ── Deduplicate ──────────────────────────────────────────────────────────
    findings = deduplicate(raw_findings)
    log.info("After dedup: %d unique findings", len(findings))

    # ── Enrich findings: remediation + CVSS + CVE/PoC ──────────────────────
    ai_enabled = bool(AI_API_KEY)
    cve_poc_enabled = os.environ.get("CVE_POC_ENABLED", "true").lower() == "true"
    agent = None
    if ai_enabled:
        try:
            agent = AIRemediationAgent(AI_API_KEY, AI_PROVIDER, AI_MODEL)
            log.info("AI remediation enabled via provider=%s model=%s", agent.provider, agent.model)
        except Exception as e:
            ai_enabled = False
            log.error("AI agent initialization failed: %s; continuing with native fallback", e)

    if not ai_enabled:
        log.warning(
            "AI remediation disabled — missing AI_API_KEY or invalid AI provider/model config"
        )

    for i, finding in enumerate(findings):
        if ai_enabled and agent:
            log.info(
                "[%d/%d] AI remediation: %s — %s",
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
                "explanation": "",
                "estimated_effort": "unknown",
                "references": finding.get("references", []),
            }

        finding["remediation_suggestion"] = build_remediation_suggestion(finding)

        cvss_assessment = resolve_cvss_assessment(
            finding=finding,
            agent=agent,
            ai_enabled=ai_enabled,
            cvss_enabled=CVSS_ENABLED,
        )
        finding["cvss_assessment"] = cvss_assessment
        if cvss_assessment.get("severity"):
            finding["severity_from_cvss"] = cvss_assessment["severity"]
            finding["severity"] = cvss_assessment["severity"]

        cves = extract_cves(finding)
        finding["cves"] = cves
        finding["cve_test_methods"] = cve_test_methods_for_finding(finding) if cves else []

        if cves and cve_poc_enabled:
            ref_poc = reference_based_poc(finding, cves)
            if ref_poc:
                finding["cve_poc"] = ref_poc
            elif ai_enabled and agent:
                finding["cve_poc"] = agent.generate_cve_poc(finding, cves)
            else:
                finding["cve_poc"] = fallback_poc(cves, finding)
        else:
            finding["cve_poc"] = None

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
    cve_poc_entries = build_cve_poc_entries(findings)

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
        "cve_findings_count": len([f for f in findings if f.get("cves")]),
        "cve_poc_entries": cve_poc_entries,
        "all_findings": findings,
        "failed_tools": decision_data["failed_tools"],
        "tool_summary": decision_data["tool_summary"],
        "dashboard_url": f"{DASHBOARD_URL.rstrip('/')}/scan/{SCAN_ID}" if DASHBOARD_URL else "",
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

    post_to_dashboard(SCAN_ID, decision)

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


def build_remediation_suggestion(finding: dict) -> str:
    ai = finding.get("ai_remediation") or {}
    steps = ai.get("remediation_steps", []) if isinstance(ai, dict) else []
    if steps:
        return " ".join(str(s).strip() for s in steps[:2])[:400]
    native = (finding.get("native_remediation") or "").strip()
    if native:
        return native[:400]
    return "Review the finding details and apply the tool-recommended fix."


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def extract_native_cvss(finding: dict) -> dict:
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
                or severity_from_cvss(score)
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


def resolve_cvss_assessment(
    finding: dict,
    agent,
    ai_enabled: bool,
    cvss_enabled: bool,
) -> dict:
    if not cvss_enabled:
        return {
            "status": "disabled",
            "source": "policy",
            "reason": "cvss_enrichment_disabled",
        }

    native = extract_native_cvss(finding)
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


def extract_cves(finding: dict) -> list:
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


def cve_test_methods_for_finding(finding: dict) -> list:
    tool = (finding.get("tool") or "").lower()
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


def reference_based_poc(finding: dict, cves: list) -> dict:
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


def fallback_poc(cves: list, finding: dict) -> dict:
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


def build_cve_poc_entries(findings: list) -> list:
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


def post_to_dashboard(scan_id: str, decision: dict):
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
