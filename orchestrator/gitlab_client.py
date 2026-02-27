"""
orchestrator/gitlab_client.py
GitLab API client for commit statuses and MR comments.
"""
import logging
import requests

log = logging.getLogger("gitlab_client")
GITLAB_API = os.environ.get("GITLAB_API_URL", "https://gitlab.com/api/v4")


class GitLabClient:
    def __init__(self, token: str, project_id: str):
        self.token = token
        self.project_id = project_id
        self.headers = {
            "PRIVATE-TOKEN": token,
            "Content-Type": "application/json",
        }

    def set_commit_status(self, sha: str, state: str, description: str,
                          name: str = "devsecops/security-gate",
                          target_url: str = ""):
        """state: pending | running | success | failed | canceled"""
        url = f"{GITLAB_API}/projects/{self.project_id}/statuses/{sha}"
        payload = {
            "state": state,
            "description": description[:140],
            "name": name,
            "target_url": target_url,
        }
        resp = requests.post(url, json=payload, headers=self.headers)
        if resp.status_code not in (200, 201):
            log.error("GitLab status update failed [%s]: %s", resp.status_code, resp.text)
            resp.raise_for_status()
        log.info("GitLab commit status set to %s for %s", state, sha[:8])
        return resp.json()

    def post_mr_comment(self, mr_iid: str, body: str):
        """Post a note on the Merge Request."""
        url = f"{GITLAB_API}/projects/{self.project_id}/merge_requests/{mr_iid}/notes"
        resp = requests.post(url, json={"body": body}, headers=self.headers)
        if resp.status_code not in (200, 201):
            log.error("GitLab comment failed [%s]: %s", resp.status_code, resp.text)
            resp.raise_for_status()
        log.info("GitLab MR comment posted on MR !%s", mr_iid)
        return resp.json()
