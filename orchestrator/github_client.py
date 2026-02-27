"""
orchestrator/github_client.py
GitHub API client for status checks and PR comments.
"""
import logging
import os
import requests

log = logging.getLogger("github_client")

GITHUB_API = "https://api.github.com"


class GitHubClient:
    def __init__(self, token: str, repo_full_name: str):
        self.token = token
        self.repo = repo_full_name
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        }

    def set_commit_status(self, sha: str, state: str, description: str,
                          context: str = "devsecops/security-gate",
                          target_url: str = ""):
        """state: pending | success | failure | error"""
        url = f"{GITHUB_API}/repos/{self.repo}/statuses/{sha}"
        payload = {
            "state": state,
            "description": description[:140],
            "context": context,
            "target_url": target_url,
        }
        resp = requests.post(url, json=payload, headers=self.headers)
        if resp.status_code not in (200, 201):
            log.error("GitHub status update failed [%s]: %s", resp.status_code, resp.text)
            resp.raise_for_status()
        log.info("GitHub commit status set to %s for %s", state, sha[:8])
        return resp.json()

    def post_pr_comment(self, pr_number: str, body: str):
        """Post a markdown comment on the PR."""
        url = f"{GITHUB_API}/repos/{self.repo}/issues/{pr_number}/comments"
        resp = requests.post(url, json={"body": body}, headers=self.headers)
        if resp.status_code not in (200, 201):
            log.error("GitHub comment failed [%s]: %s", resp.status_code, resp.text)
            resp.raise_for_status()
        log.info("GitHub PR comment posted on PR #%s", pr_number)
        return resp.json()

    def get_pr_files(self, pr_number: str):
        """Get list of files changed in a PR."""
        url = f"{GITHUB_API}/repos/{self.repo}/pulls/{pr_number}/files"
        resp = requests.get(url, headers=self.headers)
        resp.raise_for_status()
        return resp.json()
