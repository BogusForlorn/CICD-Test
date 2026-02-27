"""
aggregator/decision_engine.py
Evaluates aggregated findings against security policy and makes PASS/FAIL decision.
"""
import logging
from typing import Dict, List, Any

log = logging.getLogger("decision_engine")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN", "NONE"]


class DecisionEngine:
    def __init__(self, policy: dict):
        self.fail_on = [s.upper() for s in policy.get("fail_on", ["CRITICAL", "HIGH"])]

    def evaluate(self, findings: List[dict], scan_summary: Dict[str, dict]) -> dict:
        """
        Returns a decision dict with PASS | FAIL result and supporting data.
        """
        # Find all failing findings
        failing = [f for f in findings if f.get("severity", "").upper() in self.fail_on]
        failed_tools = list({f["tool"] for f in failing})

        # Build tool summary
        tool_summary = {}
        for tool, summary in scan_summary.items():
            tool_summary[tool] = {
                "tool": tool,
                "status": summary.get("status", "UNKNOWN"),
                "total_findings": summary.get("total_findings", 0),
                "severity_counts": summary.get("severity_counts", {}),
                "max_severity": summary.get("max_severity", "NONE"),
                "reason": summary.get("reason"),
            }

        result = "FAIL" if failing else "PASS"
        log.info(
            "Decision: %s — %d critical/high findings across %d tools",
            result, len(failing), len(failed_tools)
        )

        return {
            "result": result,
            "total_findings": len(findings),
            "critical_high_count": len(failing),
            "failed_tools": failed_tools,
            "tool_summary": tool_summary,
        }
