"""
scanner/scanners/checkov_scanner.py
Checkov — comprehensive IaC scanner (Terraform, CloudFormation, ARM, Helm, K8s, Ansible).
Complements Trivy by providing deeper IaC coverage with 1000+ policies.
"""
import json
import logging
import os
import subprocess
from typing import List, Dict, Any

log = logging.getLogger("checkov_scanner")


class CheckovScanner:
    TOOL = "checkov"
    CATEGORY = "IaC"

    # Map content flags to Checkov framework strings
    FRAMEWORK_MAP = {
        "has_terraform": "terraform",
        "has_cloudformation": "cloudformation",
        "has_helm": "helm",
        "has_k8s_yaml": "kubernetes",
        "has_dockerfile": "dockerfile",
    }

    def __init__(self, workspace: str, results_dir: str, config: dict, content: dict):
        self.workspace = workspace
        self.results_dir = results_dir
        self.config = config
        self.content = content
        self.output_file = os.path.join(results_dir, "checkov.json")

    def run(self) -> List[Dict[str, Any]]:
        frameworks = self._detect_frameworks()
        if not frameworks:
            log.info("No applicable Checkov frameworks detected")
            return []

        skip_ids = ",".join(self.config.get("skip_check_ids", []))
        cmd = [
            "checkov",
            "--directory", self.workspace,
            "--framework", ",".join(frameworks),
            "--output", "json",
            "--output-file-path", self.results_dir,
            "--quiet",
            "--compact",
        ]
        if skip_ids:
            cmd += ["--skip-check", skip_ids]

        log.info("Checkov command: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        # Checkov exits non-zero when failures found
        if result.returncode not in (0, 1):
            log.error("Checkov error: %s", result.stderr[:300])

        return self._parse()

    def _detect_frameworks(self) -> List[str]:
        frameworks = []
        for content_key, framework in self.FRAMEWORK_MAP.items():
            if self.content.get(content_key):
                frameworks.append(framework)
        # Filter by configured frameworks if specified
        configured = self.config.get("frameworks", [])
        if configured:
            frameworks = [f for f in frameworks if f in configured]
        return list(set(frameworks))

    def _parse(self) -> List[Dict[str, Any]]:
        # Checkov writes results.json in the output dir
        result_file = os.path.join(self.results_dir, "results_json.json")
        if not os.path.exists(result_file):
            result_file = self.output_file
        if not os.path.exists(result_file):
            log.warning("Checkov output file not found")
            return []

        with open(result_file) as f:
            data = json.load(f)

        findings = []
        # Handle both list (multi-framework) and dict (single) responses
        results_list = data if isinstance(data, list) else [data]

        for result_block in results_list:
            if not isinstance(result_block, dict):
                continue
            check_results = result_block.get("results", {})
            failed_checks = check_results.get("failed_checks", [])

            for check in failed_checks:
                severity = self._map_severity(check.get("severity") or check.get("check_type", "medium"))
                findings.append({
                    "tool": self.TOOL,
                    "category": self.CATEGORY,
                    "rule_id": check.get("check_id", ""),
                    "severity": severity,
                    "title": check.get("check_name", ""),
                    "description": check.get("check_name", ""),
                    "file": check.get("repo_file_path") or check.get("file_path", ""),
                    "line": check.get("file_line_range", [None])[0],
                    "code_snippet": json.dumps(check.get("code_block", ""))[:500],
                    "guideline": check.get("guideline", ""),
                    "native_remediation": check.get("guideline", "Refer to Checkov documentation for remediation."),
                    "references": [check.get("guideline", "")] if check.get("guideline") else [],
                    "raw": check,
                })

        return findings

    def _map_severity(self, sev: str) -> str:
        return {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
        }.get(str(sev).lower(), "MEDIUM")
