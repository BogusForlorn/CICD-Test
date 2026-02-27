#!/usr/bin/env python3
"""
scanner/run_scans.py
Master scan runner - detects repo content and runs appropriate tools.
Trivy covers: SCA, Container, IaC, Secrets.
Semgrep covers: SAST for all languages.
Gitleaks covers: git history secrets.
Checkov covers: comprehensive IaC.
ZAP covers: DAST (if deployable label present).
"""
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import yaml

from scanners.semgrep_scanner import SemgrepScanner
from scanners.trivy_scanner import TrivyScanner
from scanners.gitleaks_scanner import GitleaksScanner
from scanners.checkov_scanner import CheckovScanner
from scanners.zap_scanner import ZAPScanner
from aggregator_client import AggregatorClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("scan-runner")

WORKSPACE = os.environ.get("WORKSPACE", "/workspace")
RESULTS_DIR = os.environ.get("RESULTS_DIR", "/results")
SCAN_ID = os.environ["SCAN_ID"]
PLATFORM = os.environ["PLATFORM"]
REPO_URL = os.environ["REPO_URL"]
REPO_FULL_NAME = os.environ["REPO_FULL_NAME"]
PR_NUMBER = os.environ["PR_NUMBER"]
PR_SHA = os.environ["PR_SHA"]
BRANCH = os.environ["BRANCH"]
LABELS = os.environ.get("PR_LABELS", "").split(",")


def load_policy() -> dict:
    """Load repo-level security-policy.yaml if present, else use defaults."""
    policy_path = Path(WORKSPACE) / "security-policy.yaml"
    if policy_path.exists():
        with open(policy_path) as f:
            return yaml.safe_load(f).get("policy", {})
    # Default policy
    return {
        "fail_on": ["CRITICAL", "HIGH"],
        "tools": {
            "semgrep": {"enabled": True},
            "trivy": {"enabled": True},
            "gitleaks": {"enabled": True},
            "checkov": {"enabled": True},
            "zap": {"enabled": True},
        }
    }


def detect_repo_content(workspace: str) -> dict:
    """Detect what types of content exist in the repo."""
    ws = Path(workspace)
    content = {
        "has_dockerfile": bool(list(ws.rglob("Dockerfile")) + list(ws.rglob("*.dockerfile"))),
        "has_terraform": bool(list(ws.rglob("*.tf"))),
        "has_cloudformation": bool(list(ws.rglob("*.template")) + list(ws.rglob("template.yaml")) + list(ws.rglob("template.json"))),
        "has_helm": bool(list(ws.rglob("Chart.yaml"))),
        "has_k8s_yaml": bool(list(ws.rglob("*.yaml"))) or bool(list(ws.rglob("*.yml"))),
        "has_python": bool(list(ws.rglob("*.py"))),
        "has_java": bool(list(ws.rglob("*.java"))),
        "has_javascript": bool(list(ws.rglob("*.js")) + list(ws.rglob("*.ts"))),
        "has_go": bool(list(ws.rglob("*.go"))),
        "is_deployable": "deployable" in LABELS,
    }
    log.info("Repo content detected: %s", content)
    return content


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    policy = load_policy()
    content = detect_repo_content(WORKSPACE)
    tools_config = policy.get("tools", {})

    context = {
        "scan_id": SCAN_ID,
        "platform": PLATFORM,
        "repo_url": REPO_URL,
        "repo_full_name": REPO_FULL_NAME,
        "pr_number": PR_NUMBER,
        "pr_sha": PR_SHA,
        "branch": BRANCH,
        "labels": LABELS,
        "workspace": WORKSPACE,
    }

    all_results = []
    scan_summary = {}

    # ── 1. TRIVY — SCA + Container + IaC + Secrets ──────────────────────────
    if tools_config.get("trivy", {}).get("enabled", True):
        log.info("=== Running TRIVY (SCA + Container + IaC + Secrets) ===")
        scanner = TrivyScanner(WORKSPACE, RESULTS_DIR, tools_config.get("trivy", {}), content)
        results = scanner.run()
        all_results.extend(results)
        scan_summary["trivy"] = _summary(results, "trivy")
        log.info("Trivy complete: %d findings", len(results))

    # ── 2. SEMGREP — SAST (all languages) ───────────────────────────────────
    if tools_config.get("semgrep", {}).get("enabled", True):
        log.info("=== Running SEMGREP (SAST) ===")
        scanner = SemgrepScanner(WORKSPACE, RESULTS_DIR, tools_config.get("semgrep", {}), content)
        results = scanner.run()
        all_results.extend(results)
        scan_summary["semgrep"] = _summary(results, "semgrep")
        log.info("Semgrep complete: %d findings", len(results))

    # ── 3. GITLEAKS — Git history secrets ───────────────────────────────────
    if tools_config.get("gitleaks", {}).get("enabled", True):
        log.info("=== Running GITLEAKS (Secrets/Git History) ===")
        scanner = GitleaksScanner(WORKSPACE, RESULTS_DIR, tools_config.get("gitleaks", {}))
        results = scanner.run()
        all_results.extend(results)
        scan_summary["gitleaks"] = _summary(results, "gitleaks")
        log.info("Gitleaks complete: %d findings", len(results))

    # ── 4. CHECKOV — Comprehensive IaC ──────────────────────────────────────
    if tools_config.get("checkov", {}).get("enabled", True):
        if any([content["has_terraform"], content["has_cloudformation"],
                content["has_helm"], content["has_dockerfile"]]):
            log.info("=== Running CHECKOV (IaC) ===")
            scanner = CheckovScanner(WORKSPACE, RESULTS_DIR, tools_config.get("checkov", {}), content)
            results = scanner.run()
            all_results.extend(results)
            scan_summary["checkov"] = _summary(results, "checkov")
            log.info("Checkov complete: %d findings", len(results))
        else:
            log.info("Checkov skipped — no IaC files detected")
            scan_summary["checkov"] = {"status": "SKIPPED", "reason": "No IaC files detected"}

    # ── 5. ZAP — DAST (only if deployable) ──────────────────────────────────
    if tools_config.get("zap", {}).get("enabled", True) and content["is_deployable"]:
        log.info("=== Running OWASP ZAP (DAST) ===")
        scanner = ZAPScanner(WORKSPACE, RESULTS_DIR, tools_config.get("zap", {}))
        results = scanner.run()
        all_results.extend(results)
        scan_summary["zap"] = _summary(results, "zap")
        log.info("ZAP complete: %d findings", len(results))
    elif not content["is_deployable"]:
        log.info("ZAP skipped — PR does not have 'deployable' label")
        scan_summary["zap"] = {"status": "SKIPPED", "reason": "No deployable label on PR"}

    # ── Compile and send to aggregator ──────────────────────────────────────
    scan_data = {
        "context": context,
        "policy": policy,
        "content_detected": content,
        "scan_summary": scan_summary,
        "findings": all_results,
    }

    output_path = os.path.join(RESULTS_DIR, "scan_results.json")
    with open(output_path, "w") as f:
        json.dump(scan_data, f, indent=2, default=str)
    log.info("Scan results written to %s — %d total findings", output_path, len(all_results))

    # Send to aggregator service
    aggregator_url = os.environ.get("AGGREGATOR_URL", "http://aggregator:8001")
    client = AggregatorClient(aggregator_url)
    client.submit(scan_data)


def _summary(results: list, tool: str) -> dict:
    severity_counts = {}
    for r in results:
        sev = r.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    max_sev = _max_severity(severity_counts)
    fail_sevs = ["CRITICAL", "HIGH"]
    return {
        "tool": tool,
        "status": "FAIL" if max_sev in fail_sevs else "PASS",
        "total_findings": len(results),
        "severity_counts": severity_counts,
        "max_severity": max_sev,
    }


def _max_severity(counts: dict) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    for sev in order:
        if counts.get(sev, 0) > 0:
            return sev
    return "NONE"


if __name__ == "__main__":
    main()
