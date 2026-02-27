"""
aggregator/schemas.py
Pydantic schemas for findings and decisions.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class Finding(BaseModel):
    finding_id: str
    scan_id: str
    platform: str
    repo_full_name: str
    pr_number: str
    pr_sha: str
    branch: str
    tool: str
    category: str      # SAST | SCA | SECRETS | IaC | CONTAINER | DAST | IAST
    rule_id: str
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    description: str
    file: str
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    native_remediation: Optional[str] = None
    ai_remediation: Optional[Dict[str, Any]] = None
    cwe: Optional[str] = None
    cvss: Optional[Dict[str, Any]] = None
    references: List[str] = []
    raw: Optional[Dict[str, Any]] = None
    timestamp: str


class ToolSummary(BaseModel):
    tool: str
    status: str        # PASS | FAIL | SKIPPED | ERROR
    total_findings: int = 0
    severity_counts: Dict[str, int] = {}
    max_severity: str = "NONE"
    reason: Optional[str] = None


class Decision(BaseModel):
    scan_id: str
    platform: str
    repo_full_name: str
    pr_number: str
    pr_sha: str
    branch: str
    result: str                       # PASS | FAIL
    total_findings: int
    critical_high_findings: List[Finding]
    all_findings: List[Finding]
    failed_tools: List[str]
    tool_summary: Dict[str, ToolSummary]
    dashboard_url: str
    report_url: str
    timestamp: str
