"""
scanner/scanners/gitleaks_scanner.py
Gitleaks — scans full git history for secrets.
Complements Trivy filesystem secrets scan by covering git history.
"""
import json
import logging
import os
import subprocess
from typing import List, Dict, Any

log = logging.getLogger("gitleaks_scanner")


class GitleaksScanner:
    TOOL = "gitleaks"
    CATEGORY = "SECRETS"

    def __init__(self, workspace: str, results_dir: str, config: dict):
        self.workspace = workspace
        self.results_dir = results_dir
        self.config = config
        self.output_file = os.path.join(results_dir, "gitleaks.json")

    def run(self) -> List[Dict[str, Any]]:
        cmd = [
            "gitleaks", "detect",
            "--source", self.workspace,
            "--report-format", "json",
            "--report-path", self.output_file,
            "--no-banner",
        ]

        if self.config.get("redact", True):
            cmd.append("--redact")

        # Check for custom config
        gitleaks_cfg = os.path.join(self.workspace, ".gitleaks.toml")
        if os.path.exists(gitleaks_cfg):
            cmd += ["--config", gitleaks_cfg]

        log.info("Gitleaks command: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.workspace)
        # rc=1 means leaks found — that is normal
        if result.returncode not in (0, 1):
            log.error("Gitleaks error (rc=%d): %s", result.returncode, result.stderr[:300])

        return self._parse()

    def _parse(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.output_file):
            return []
        with open(self.output_file) as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return []

        if not data:
            return []

        findings = []
        for leak in data:
            findings.append({
                "tool": self.TOOL,
                "category": self.CATEGORY,
                "rule_id": leak.get("RuleID", ""),
                "severity": "CRITICAL",  # Secrets are always critical
                "title": f"{leak.get('Description', 'Secret detected')}: {leak.get('RuleID', '')}",
                "description": (
                    f"Secret type: {leak.get('RuleID', '')}\n"
                    f"Author: {leak.get('Author', '')}\n"
                    f"Commit: {leak.get('Commit', '')}\n"
                    f"Date: {leak.get('Date', '')}"
                ),
                "file": leak.get("File", ""),
                "line": leak.get("StartLine"),
                "code_snippet": leak.get("Secret", "")[:100] + "..." if leak.get("Secret") else "",
                "commit": leak.get("Commit", ""),
                "author": leak.get("Author", ""),
                "native_remediation": (
                    "1. Revoke the exposed credential immediately. "
                    "2. Remove from code and replace with env var or secrets manager reference. "
                    "3. Use git-filter-repo to purge from history if committed."
                ),
                "references": ["https://gitleaks.io/"],
                "raw": leak,
            })
        return findings
