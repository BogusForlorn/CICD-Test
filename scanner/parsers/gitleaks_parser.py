"""Gitleaks JSON output parser."""
import json
from typing import Any, Dict, List


def parse_gitleaks(path: str) -> List[Dict[str, Any]]:
    with open(path) as f:
        try:
            data = json.load(f)
        except (json.JSONDecodeError, ValueError):
            return []
    if not data:
        return []
    findings = []
    for leak in data:
        findings.append({
            "tool": "gitleaks", "category": "SECRETS",
            "rule_id": leak.get("RuleID", ""),
            "severity": "CRITICAL",
            "title": f"{leak.get('Description', 'Secret detected')}: {leak.get('RuleID', '')}",
            "description": (
                f"Secret type: {leak.get('RuleID', '')}\n"
                f"Author: {leak.get('Author', '')}\n"
                f"Commit: {leak.get('Commit', '')}\n"
                f"Date: {leak.get('Date', '')}"
            ),
            "file": leak.get("File", ""),
            "line": leak.get("StartLine"),
            "code_snippet": (leak.get("Secret") or "")[:100],
            "commit": leak.get("Commit", ""),
            "author": leak.get("Author", ""),
            "native_remediation": (
                "1. Revoke the exposed credential immediately. "
                "2. Remove from code and use env var or secrets manager. "
                "3. Purge from git history with git-filter-repo."
            ),
            "references": ["https://gitleaks.io/"],
            "raw": leak,
        })
    return findings
