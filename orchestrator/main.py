"""
orchestrator/main.py
FastAPI webhook handler - receives GitHub/GitLab PR/MR events and launches scan jobs.
"""
import hashlib, hmac, json, logging, os, uuid
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from job_launcher import launch_scan_job, JobConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("orchestrator")
app = FastAPI(title="DevSecOps Orchestrator", version="1.0.0")

GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
GITLAB_WEBHOOK_SECRET = os.environ.get("GITLAB_WEBHOOK_SECRET", "")
RUNNER_MODE = os.environ.get("RUNNER_MODE", "kubernetes")  # kubernetes | docker


@app.get("/health")
def health():
    return {"status": "ok", "mode": RUNNER_MODE}


@app.post("/webhook/github")
async def github_webhook(
    request: Request, background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None),
):
    body = await request.body()
    if GITHUB_WEBHOOK_SECRET:
        _verify_github_sig(body, x_hub_signature_256)
    if x_github_event != "pull_request":
        return JSONResponse({"skipped": f"event {x_github_event!r} not handled"})
    payload = json.loads(body)
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return JSONResponse({"skipped": f"action {action!r} not handled"})

    pr, repo = payload["pull_request"], payload["repository"]
    config = JobConfig(
        scan_id=f"scan-{repo['name']}-pr{pr['number']}-{str(uuid.uuid4())[:8]}",
        platform="github",
        repo_url=repo["clone_url"],
        repo_full_name=repo["full_name"],
        pr_number=str(pr["number"]),
        pr_sha=pr["head"]["sha"],
        branch=pr["head"]["ref"],
        base_branch=pr["base"]["ref"],
        labels=[lbl["name"] for lbl in pr.get("labels", [])],
        api_token=os.environ["GITHUB_TOKEN"],
        results_bucket=os.environ.get("RESULTS_BUCKET", ""),
        defectdojo_url=os.environ.get("DEFECTDOJO_URL", ""),
        defectdojo_token=os.environ.get("DEFECTDOJO_TOKEN", ""),
        ai_api_key=os.environ.get("AI_API_KEY", ""),
        dashboard_url=os.environ.get("DASHBOARD_URL", ""),
        runner_mode=RUNNER_MODE,
    )
    log.info("GitHub PR #%s on %s -> scan %s", pr["number"], repo["full_name"], config.scan_id)
    background_tasks.add_task(launch_scan_job, config)
    return JSONResponse({"scan_id": config.scan_id, "status": "triggered"})


@app.post("/webhook/gitlab")
async def gitlab_webhook(
    request: Request, background_tasks: BackgroundTasks,
    x_gitlab_token: Optional[str] = Header(None),
    x_gitlab_event: Optional[str] = Header(None),
):
    body = await request.body()
    if GITLAB_WEBHOOK_SECRET and x_gitlab_token != GITLAB_WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="Invalid GitLab token")
    if x_gitlab_event != "Merge Request Hook":
        return JSONResponse({"skipped": f"event {x_gitlab_event!r} not handled"})
    payload = json.loads(body)
    attrs = payload.get("object_attributes", {})
    if attrs.get("action", "") not in ("open", "update", "reopen"):
        return JSONResponse({"skipped": "action not handled"})

    project = payload["project"]
    config = JobConfig(
        scan_id=f"scan-{project['name']}-mr{attrs['iid']}-{str(uuid.uuid4())[:8]}",
        platform="gitlab",
        repo_url=project["git_http_url"],
        repo_full_name=f"{payload['user']['username']}/{project['name']}",
        pr_number=str(attrs["iid"]),
        pr_sha=attrs["last_commit"]["id"],
        branch=attrs["source_branch"],
        base_branch=attrs["target_branch"],
        labels=[lbl.get("title", "") for lbl in attrs.get("labels", [])],
        api_token=os.environ["GITLAB_TOKEN"],
        results_bucket=os.environ.get("RESULTS_BUCKET", ""),
        defectdojo_url=os.environ.get("DEFECTDOJO_URL", ""),
        defectdojo_token=os.environ.get("DEFECTDOJO_TOKEN", ""),
        ai_api_key=os.environ.get("AI_API_KEY", ""),
        dashboard_url=os.environ.get("DASHBOARD_URL", ""),
        runner_mode=RUNNER_MODE,
        gitlab_project_id=str(project["id"]),
    )
    log.info("GitLab MR !%s on %s -> scan %s", attrs["iid"], config.repo_full_name, config.scan_id)
    background_tasks.add_task(launch_scan_job, config)
    return JSONResponse({"scan_id": config.scan_id, "status": "triggered"})


def _verify_github_sig(body: bytes, sig_header: Optional[str]):
    if not sig_header:
        raise HTTPException(status_code=403, detail="Missing X-Hub-Signature-256")
    _, sig = sig_header.split("=", 1)
    mac = hmac.new(GITHUB_WEBHOOK_SECRET.encode(), msg=body, digestmod=hashlib.sha256)
    if not hmac.compare_digest(mac.hexdigest(), sig):
        raise HTTPException(status_code=403, detail="Invalid signature")
