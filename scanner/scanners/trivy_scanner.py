"""
scanner/scanners/trivy_scanner.py
Trivy — covers SCA (OS + language deps), Container, IaC, and Secrets.
Single tool replacing: Grype, OWASP Dep-Check, Hadolint (partially).
"""
import json
import logging
import os
import subprocess
from typing import List, Dict, Any

log = logging.getLogger("trivy_scanner")


class TrivyScanner:
    TOOL = "trivy"

    def __init__(self, workspace: str, results_dir: str, config: dict, content: dict):
        self.workspace = workspace
        self.results_dir = results_dir
        self.config = config
        self.content = content

    def run(self) -> List[Dict[str, Any]]:
        all_findings = []

        # 1. Filesystem scan (SCA + Secrets + IaC misconfigs)
        fs_output = os.path.join(self.results_dir, "trivy_fs.json")
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--output", fs_output,
            "--scanners", "vuln,secret,misconfig",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--quiet",
            self.workspace,
        ]
        log.info("Trivy FS scan: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode not in (0, 1):
            log.error("Trivy FS error: %s", result.stderr[:300])
        all_findings.extend(self._parse_fs(fs_output))

        # 2. Container image scan (if Dockerfile present and image built)
        if self.content.get("has_dockerfile"):
            image_tag = os.environ.get("BUILD_IMAGE_TAG", "")
            if image_tag:
                img_output = os.path.join(self.results_dir, "trivy_image.json")
                cmd_img = [
                    "trivy", "image",
                    "--format", "json",
                    "--output", img_output,
                    "--scanners", "vuln,secret,misconfig",
                    "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                    "--quiet",
                    image_tag,
                ]
                log.info("Trivy image scan: %s", image_tag)
                subprocess.run(cmd_img, capture_output=True, text=True)
                all_findings.extend(self._parse_image(img_output))
            else:
                log.info("Trivy image scan skipped — no BUILD_IMAGE_TAG env var")

        return all_findings

    def _parse_fs(self, output_file: str) -> List[Dict[str, Any]]:
        if not os.path.exists(output_file):
            return []
        with open(output_file) as f:
            data = json.load(f)

        findings = []
        for result in data.get("Results", []):
            target = result.get("Target", "")
            result_type = result.get("Type", "")

            # SCA Vulnerabilities
            for vuln in result.get("Vulnerabilities", []) or []:
                findings.append({
                    "tool": self.TOOL,
                    "category": "SCA",
                    "rule_id": vuln.get("VulnerabilityID", ""),
                    "severity": vuln.get("Severity", "UNKNOWN").upper(),
                    "title": f"{vuln.get('VulnerabilityID', '')} in {vuln.get('PkgName', '')}",
                    "description": vuln.get("Description", ""),
                    "file": target,
                    "line": None,
                    "code_snippet": f"Package: {vuln.get('PkgName','')} {vuln.get('InstalledVersion','')} -> Fixed: {vuln.get('FixedVersion','N/A')}",
                    "cwe": "",
                    "cvss": vuln.get("CVSS", {}),
                    "native_remediation": f"Upgrade {vuln.get('PkgName','')} to {vuln.get('FixedVersion', 'latest')}",
                    "references": vuln.get("References", [])[:5],
                    "raw": vuln,
                })

            # Secrets
            for secret in result.get("Secrets", []) or []:
                findings.append({
                    "tool": self.TOOL,
                    "category": "SECRETS",
                    "rule_id": secret.get("RuleID", ""),
                    "severity": secret.get("Severity", "CRITICAL").upper(),
                    "title": secret.get("Title", "Secret detected"),
                    "description": f"Secret type: {secret.get('Category', '')} — match: {secret.get('Match', '')}",
                    "file": target,
                    "line": secret.get("StartLine"),
                    "code_snippet": secret.get("Match", "")[:200],
                    "native_remediation": "Remove secret from code. Use environment variables or a secrets manager.",
                    "references": [],
                    "raw": secret,
                })

            # IaC Misconfigurations
            for misconfig in result.get("Misconfigurations", []) or []:
                findings.append({
                    "tool": self.TOOL,
                    "category": "IaC",
                    "rule_id": misconfig.get("ID", ""),
                    "severity": misconfig.get("Severity", "UNKNOWN").upper(),
                    "title": misconfig.get("Title", ""),
                    "description": misconfig.get("Description", ""),
                    "file": target,
                    "line": misconfig.get("CauseMetadata", {}).get("StartLine"),
                    "code_snippet": misconfig.get("Message", ""),
                    "native_remediation": misconfig.get("Resolution", ""),
                    "references": [ref.get("URL", "") for ref in misconfig.get("References", [])],
                    "raw": misconfig,
                })

        return findings

    def _parse_image(self, output_file: str) -> List[Dict[str, Any]]:
        """Same structure as FS scan but category tagged as CONTAINER."""
        findings = self._parse_fs(output_file)
        for f in findings:
            if f["category"] == "SCA":
                f["category"] = "CONTAINER"
        return findings
