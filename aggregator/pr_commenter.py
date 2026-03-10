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
            "## ❌ DevSecOps Security Gate — **FAILED**\n",
            f"**Scan ID:** `{decision['scan_id']}`\n",
            f"**Branch:** `{decision['branch']}`\n",
            f"**Tools Failed:** {failed_tools}\n\n",
            "---\n",
            "### 🔴 Critical / High Findings\n\n",
            "| # | Severity | Tool | Category | File | Line | Issue | Remediation Suggestion | CVSS | CVE / PoC |\n",
            "|---|---|---|---|---|---|---|---|---|---|\n",
        ]

        mismatched_cvss = []
        for i, f in enumerate(decision.get("critical_high_findings", []), 1):
            suggestion = (f.get("remediation_suggestion") or f.get("native_remediation") or "See full report")[:100]
            file_short = (f.get("file") or "")[-60:]  # Truncate long paths
            cvss = f.get("cvss_assessment", {}) or {}
            cvss_status = cvss.get("status", "")
            if cvss_status in ("native", "verified"):
                cvss_str = f"{cvss.get('score', 'n/a')} ({cvss.get('severity', '')})"
            else:
                cvss_str = cvss.get("highlight", "(unable to estimate cvss)")
                if cvss.get("cvss_string_1") or cvss.get("cvss_string_2"):
                    mismatched_cvss.append(
                        {
                            "id": i,
                            "cvss_string_1": cvss.get("cvss_string_1", ""),
                            "cvss_string_2": cvss.get("cvss_string_2", ""),
                        }
                    )

            cves = f.get("cves") or []
            poc = f.get("cve_poc") or {}
            cve_cell = "—"
            if cves:
                cve_cell = f"{', '.join(cves[:2])} | PoC: {poc.get('poc_status', 'not_available')}"
            lines.append(
                f"| {i} | **{f['severity']}** | {f['tool']} | {f['category']} "
                f"| `{file_short}` | {f.get('line') or '—'} "
                f"| {(f.get('title') or '')[:80]} | {suggestion} | {cvss_str[:60]} | {cve_cell[:60]} |\n"
            )

        if mismatched_cvss:
            lines += [
                "\n### ⚠️ CVSS Verification Mismatch\n",
                "The following findings are marked **(unable to estimate cvss)** because the two API CVSS strings did not match.\n\n",
            ]
            for mismatch in mismatched_cvss:
                lines.append(
                    f"- Finding #{mismatch['id']}: `cvss_string_1={mismatch['cvss_string_1'][:120]}` "
                    f"`cvss_string_2={mismatch['cvss_string_2'][:120]}`\n"
                )

        lines += [
            "\n---\n",
            "### 📋 Tool Results Summary\n\n",
            "| Tool | Status | Findings | Max Severity |\n",
            "|---|---|---|---|\n",
        ]
        for tool, summary in decision.get("tool_summary", {}).items():
            status_icon = "❌" if summary["status"] == "FAIL" else ("⏭️" if summary["status"] == "SKIPPED" else "✅")
            lines.append(
                f"| {tool} | {status_icon} {summary['status']} "
                f"| {summary['total_findings']} | {summary['max_severity']} |\n"
            )

        lines += [
            "\n---\n",
            f"📊 **[View Full Report & AI Remediation Steps]({decision.get('report_url', '')})**\n",
            f"🔍 **[Dashboard]({decision.get('dashboard_url', '')})**\n\n",
            "> ⚠️ **This PR has been blocked.** Fix all HIGH/CRITICAL findings and push a new commit.\n",
            "> The full report includes remediation suggestions, CVSS verification details, and CVE PoC data.\n",
        ]
        return "".join(lines)

    def _build_pass_comment(self, decision: dict) -> str:
        tool_rows = []
        for tool, summary in decision.get("tool_summary", {}).items():
            icon = "⏭️" if summary["status"] == "SKIPPED" else "✅"
            tool_rows.append(
                f"| {tool} | {icon} {summary['status']} "
                f"| {summary['total_findings']} | {summary['max_severity']} |\n"
            )

        return (
            "## ✅ DevSecOps Security Gate — **PASSED**\n\n"
            f"**Scan ID:** `{decision['scan_id']}`\n"
            f"**Branch:** `{decision['branch']}`\n\n"
            "All security tools completed with **no HIGH or CRITICAL findings**.\n\n"
            "---\n"
            "### 🛡️ Tool Results\n\n"
            "| Tool | Status | Findings | Max Severity |\n"
            "|---|---|---|---|\n"
            + "".join(tool_rows) +
            "\n---\n"
            "### 🔒 Status: Awaiting Human Approval\n\n"
            "> ✋ **This PR has NOT been auto-merged.** A security team member must review\n"
            "> the full report and approve this PR manually in the GitHub/GitLab UI.\n\n"
            f"**CVE findings with PoC in this scan:** {decision.get('cve_findings_count', 0)}\n\n"
            f"📊 **[View Full Scan Report]({decision.get('report_url', '')})**\n"
            f"🔍 **[Dashboard]({decision.get('dashboard_url', '')})**\n"
        )
