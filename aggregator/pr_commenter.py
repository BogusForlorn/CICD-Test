"""
aggregator/pr_commenter.py
Posts PR/MR comments and updates commit status via GitHub/GitLab API.
NEVER approves or merges a PR — only comments and sets status checks.
"""
import logging
import os
import requests

log = logging.getLogger("pr_commenter")

GITHUB_API = "https://api.github.com"


class PRCommenter:
    def __init__(self, platform: str, api_token: str, repo_full_name: str,
                 pr_number: str, pr_sha: str, gitlab_project_id: str = None):
        self.platform = platform
        self.token = api_token
        self.repo = repo_full_name
        self.pr_number = pr_number
        self.pr_sha = pr_sha
        self.gitlab_project_id = gitlab_project_id
        self.gitlab_api = os.environ.get("GITLAB_API_URL", "https://gitlab.com/api/v4")

    def apply_decision(self, decision: dict):
        if decision["result"] == "FAIL":
            self._apply_fail(decision)
        else:
            self._apply_pass(decision)

    def _apply_fail(self, decision: dict):
        comment = self._build_fail_comment(decision)
        self._post_comment(comment)
        self._set_status("failure",
            f"Security Gate FAILED — {decision['critical_high_count']} HIGH/CRITICAL issue(s) found",
            decision.get("dashboard_url", ""))

    def _apply_pass(self, decision: dict):
        comment = self._build_pass_comment(decision)
        self._post_comment(comment)
        # NOTE: Status set to success but PR is NEVER auto-merged.
        # Human operator must manually approve in GitHub/GitLab UI.
        self._set_status("success",
            "All security tools passed. Awaiting human approval — NOT auto-merged.",
            decision.get("dashboard_url", ""))

    def _post_comment(self, body: str):
        if self.platform == "github":
            url = f"{GITHUB_API}/repos/{self.repo}/issues/{self.pr_number}/comments"
            headers = {"Authorization": f"token {self.token}", "Accept": "application/vnd.github.v3+json"}
            resp = requests.post(url, json={"body": body}, headers=headers, timeout=30)
        else:  # gitlab
            url = f"{self.gitlab_api}/projects/{self.gitlab_project_id}/merge_requests/{self.pr_number}/notes"
            headers = {"PRIVATE-TOKEN": self.token}
            resp = requests.post(url, json={"body": body}, headers=headers, timeout=30)

        if resp.status_code not in (200, 201):
            log.error("Comment post failed [%d]: %s", resp.status_code, resp.text[:200])
        else:
            log.info("PR comment posted (%s)", self.platform)

    def _set_status(self, state: str, description: str, target_url: str):
        if self.platform == "github":
            url = f"{GITHUB_API}/repos/{self.repo}/statuses/{self.pr_sha}"
            headers = {"Authorization": f"token {self.token}", "Accept": "application/vnd.github.v3+json"}
            payload = {
                "state": state,              # pending | success | failure | error
                "description": description[:140],
                "context": "devsecops/security-gate",
                "target_url": target_url,
            }
            resp = requests.post(url, json=payload, headers=headers, timeout=30)
        else:  # gitlab: failure -> failed
            gl_state = {"failure": "failed", "success": "success"}.get(state, state)
            url = f"{self.gitlab_api}/projects/{self.gitlab_project_id}/statuses/{self.pr_sha}"
            headers = {"PRIVATE-TOKEN": self.token}
            payload = {
                "state": gl_state,
                "description": description[:140],
                "name": "devsecops/security-gate",
                "target_url": target_url,
            }
            resp = requests.post(url, json=payload, headers=headers, timeout=30)

        if resp.status_code not in (200, 201):
            log.error("Status set failed [%d]: %s", resp.status_code, resp.text[:200])
        else:
            log.info("Commit status set to %s (%s)", state, self.platform)

    def _build_fail_comment(self, decision: dict) -> str:
        failed_tools = ", ".join(decision.get("failed_tools", []))
        lines = [
            "## ❌ DevSecOps Security Gate — **FAILED**
",
            f"**Scan ID:** `{decision['scan_id']}`  
",
            f"**Branch:** `{decision['branch']}`  
",
            f"**Tools Failed:** {failed_tools}  

",
            "---
",
            "### 🔴 Critical / High Findings

",
            "| # | Severity | Tool | Category | File | Line | Issue | AI Remediation Summary |
",
            "|---|---|---|---|---|---|---|---|
",
        ]

        for i, f in enumerate(decision.get("critical_high_findings", []), 1):
            ai = f.get("ai_remediation", {})
            steps = ai.get("remediation_steps", [])
            # Show first step as inline summary; full steps in JSON report
            first_step = steps[0] if steps else (f.get("native_remediation") or "See full report")[:120]
            file_short = (f.get("file") or "")[-60:]  # Truncate long paths
            lines.append(
                f"| {i} | **{f['severity']}** | {f['tool']} | {f['category']} "
                f"| `{file_short}` | {f.get('line') or '—'} "
                f"| {(f.get('title') or '')[:80]} | {first_step[:100]} |
"
            )

        lines += [
            "
---
",
            "### 📋 Tool Results Summary

",
            "| Tool | Status | Findings | Max Severity |
",
            "|---|---|---|---|
",
        ]
        for tool, summary in decision.get("tool_summary", {}).items():
            status_icon = "❌" if summary["status"] == "FAIL" else ("⏭️" if summary["status"] == "SKIPPED" else "✅")
            lines.append(
                f"| {tool} | {status_icon} {summary['status']} "
                f"| {summary['total_findings']} | {summary['max_severity']} |
"
            )

        lines += [
            "
---
",
            f"📊 **[View Full Report & AI Remediation Steps]({decision.get('report_url', '')})**  
",
            f"🔍 **[Dashboard]({decision.get('dashboard_url', '')})**  

",
            "> ⚠️ **This PR has been blocked.** Fix all HIGH/CRITICAL findings and push a new commit.
",
            "> All remediation steps are in the full report JSON linked above.
",
        ]
        return "".join(lines)

    def _build_pass_comment(self, decision: dict) -> str:
        tool_rows = []
        for tool, summary in decision.get("tool_summary", {}).items():
            icon = "⏭️" if summary["status"] == "SKIPPED" else "✅"
            tool_rows.append(
                f"| {tool} | {icon} {summary['status']} "
                f"| {summary['total_findings']} | {summary['max_severity']} |
"
            )

        return (
            "## ✅ DevSecOps Security Gate — **PASSED**

"
            f"**Scan ID:** `{decision['scan_id']}`  
"
            f"**Branch:** `{decision['branch']}`  

"
            "All security tools completed with **no HIGH or CRITICAL findings**.

"
            "---
"
            "### 🛡️ Tool Results

"
            "| Tool | Status | Findings | Max Severity |
"
            "|---|---|---|---|
"
            + "".join(tool_rows) +
            "
---
"
            "### 🔒 Status: Awaiting Human Approval

"
            "> ✋ **This PR has NOT been auto-merged.** A security team member must review
"
            "> the full report and approve this PR manually in the GitHub/GitLab UI.

"
            f"📊 **[View Full Scan Report]({decision.get('report_url', '')})**  
"
            f"🔍 **[Dashboard]({decision.get('dashboard_url', '')})**  
"
        )
