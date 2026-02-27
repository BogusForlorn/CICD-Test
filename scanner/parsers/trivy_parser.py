"""Trivy JSON output parser."""
import json
from typing import Any, Dict, List


def _load(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def parse_trivy_fs(path: str) -> List[Dict[str, Any]]:
    return _parse_trivy(path, default_category="SCA")


def parse_trivy_image(path: str) -> List[Dict[str, Any]]:
    return _parse_trivy(path, default_category="CONTAINER")


def _parse_trivy(path: str, default_category: str) -> List[Dict[str, Any]]:
    data = _load(path)
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "tool": "trivy", "category": default_category,
                "rule_id": vuln.get("VulnerabilityID", ""),
                "severity": vuln.get("Severity", "UNKNOWN").upper(),
                "title": f"{vuln.get('VulnerabilityID','')} in {vuln.get('PkgName','')}",
                "description": vuln.get("Description", ""),
                "file": target, "line": None,
                "code_snippet": f"Package: {vuln.get('PkgName','')} {vuln.get('InstalledVersion','')} -> Fix: {vuln.get('FixedVersion','N/A')}",
                "native_remediation": f"Upgrade {vuln.get('PkgName','')} to {vuln.get('FixedVersion', 'latest')}",
                "references": vuln.get("References", [])[:5],
                "raw": vuln,
            })
        for secret in result.get("Secrets", []) or []:
            findings.append({
                "tool": "trivy", "category": "SECRETS",
                "rule_id": secret.get("RuleID", ""),
                "severity": secret.get("Severity", "CRITICAL").upper(),
                "title": secret.get("Title", "Secret detected"),
                "description": f"Secret match: {secret.get('Match', '')}",
                "file": target, "line": secret.get("StartLine"),
                "code_snippet": secret.get("Match", "")[:200],
                "native_remediation": "Remove secret from code. Use env vars or a secrets manager.",
                "references": [], "raw": secret,
            })
        for mc in result.get("Misconfigurations", []) or []:
            findings.append({
                "tool": "trivy", "category": "IaC",
                "rule_id": mc.get("ID", ""),
                "severity": mc.get("Severity", "UNKNOWN").upper(),
                "title": mc.get("Title", ""),
                "description": mc.get("Description", ""),
                "file": target,
                "line": mc.get("CauseMetadata", {}).get("StartLine"),
                "code_snippet": mc.get("Message", ""),
                "native_remediation": mc.get("Resolution", ""),
                "references": [r.get("URL", "") for r in mc.get("References", [])],
                "raw": mc,
            })
    return findings
