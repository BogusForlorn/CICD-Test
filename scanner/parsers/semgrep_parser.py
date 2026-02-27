"""Semgrep JSON output parser."""
import json
from typing import Any, Dict, List

SEV_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "CRITICAL": "CRITICAL"}


def parse_semgrep(path: str) -> List[Dict[str, Any]]:
    with open(path) as f:
        data = json.load(f)
    findings = []
    for r in data.get("results", []):
        meta = r.get("extra", {})
        sev = SEV_MAP.get(meta.get("severity", "WARNING").upper(), "MEDIUM")
        cwe = meta.get("metadata", {}).get("cwe", "")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        findings.append({
            "tool": "semgrep", "category": "SAST",
            "rule_id": r.get("check_id", ""),
            "severity": sev,
            "title": meta.get("message", r.get("check_id", ""))[:200],
            "description": meta.get("message", ""),
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line"),
            "line_end": r.get("end", {}).get("line"),
            "code_snippet": meta.get("lines", "")[:500],
            "cwe": str(cwe),
            "owasp": meta.get("metadata", {}).get("owasp", ""),
            "native_remediation": meta.get("metadata", {}).get("fix", ""),
            "references": meta.get("metadata", {}).get("references", []),
            "raw": r,
        })
    return findings
