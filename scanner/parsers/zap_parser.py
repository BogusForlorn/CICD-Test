"""OWASP ZAP JSON output parser."""
import json
from typing import Any, Dict, List

RISK_MAP = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "informational": "INFO"}


def parse_zap(path: str) -> List[Dict[str, Any]]:
    with open(path) as f:
        data = json.load(f)
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "").split(" ")[0].lower()
            sev = RISK_MAP.get(risk, "MEDIUM")
            for instance in (alert.get("instances") or [{}]):
                findings.append({
                    "tool": "zap", "category": "DAST",
                    "rule_id": f"ZAP-{alert.get('pluginid', '')}",
                    "severity": sev,
                    "title": alert.get("alert", ""),
                    "description": (alert.get("desc") or "").replace("<p>", "").replace("</p>", ""),
                    "file": instance.get("uri", ""),
                    "line": None,
                    "code_snippet": (
                        f"URI: {instance.get('uri', '')}\n"
                        f"Method: {instance.get('method', '')}\n"
                        f"Evidence: {instance.get('evidence', '')}"
                    ),
                    "native_remediation": (alert.get("solution") or "").replace("<p>", "").replace("</p>", ""),
                    "references": [alert.get("reference", "")],
                    "raw": alert,
                })
    return findings
