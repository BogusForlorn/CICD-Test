"""Checkov JSON output parser."""
import json
from typing import Any, Dict, List

SEV_MAP = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def parse_checkov(path: str) -> List[Dict[str, Any]]:
    with open(path) as f:
        data = json.load(f)
    results_list = data if isinstance(data, list) else [data]
    findings = []
    for block in results_list:
        if not isinstance(block, dict):
            continue
        for check in block.get("results", {}).get("failed_checks", []):
            sev = SEV_MAP.get(str(check.get("severity") or "").lower(), "MEDIUM")
            findings.append({
                "tool": "checkov", "category": "IaC",
                "rule_id": check.get("check_id", ""),
                "severity": sev,
                "title": check.get("check_name", ""),
                "description": check.get("check_name", ""),
                "file": check.get("repo_file_path") or check.get("file_path", ""),
                "line": (check.get("file_line_range") or [None])[0],
                "code_snippet": json.dumps(check.get("code_block", ""))[:500],
                "native_remediation": check.get("guideline", "Refer to Checkov documentation."),
                "references": [check.get("guideline", "")] if check.get("guideline") else [],
                "raw": check,
            })
    return findings
