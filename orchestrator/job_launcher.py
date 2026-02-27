"""
orchestrator/job_launcher.py
Launches scan jobs on Kubernetes or Docker depending on RUNNER_MODE.
"""
import dataclasses
import logging
import os
import subprocess
import tempfile
from typing import List, Optional

import yaml

log = logging.getLogger("job_launcher")


@dataclasses.dataclass
class JobConfig:
    scan_id: str
    platform: str          # github | gitlab
    repo_url: str
    repo_full_name: str
    pr_number: str
    pr_sha: str
    branch: str
    base_branch: str
    labels: List[str]
    api_token: str
    results_bucket: str
    defectdojo_url: str
    defectdojo_token: str
    ai_api_key: str
    dashboard_url: str
    runner_mode: str       # kubernetes | docker
    gitlab_project_id: Optional[str] = None


def launch_scan_job(config: JobConfig):
    if config.runner_mode == "kubernetes":
        _launch_k8s_job(config)
    else:
        _launch_docker_job(config)


def _launch_k8s_job(config: JobConfig):
    """Render and apply a K8s Job manifest for the scan."""
    job_manifest = _render_k8s_job(config)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(job_manifest, f)
        manifest_path = f.name

    result = subprocess.run(
        ["kubectl", "apply", "-f", manifest_path],
        capture_output=True, text=True
    )
    os.unlink(manifest_path)

    if result.returncode != 0:
        log.error("kubectl apply failed: %s", result.stderr)
        raise RuntimeError(f"K8s job launch failed: {result.stderr}")
    log.info("K8s Job launched: %s", config.scan_id)


def _launch_docker_job(config: JobConfig):
    """Run the scanner container via docker run (dev/local mode)."""
    env_args = _build_env_args(config)
    cmd = [
        "docker", "run", "--rm",
        "--name", config.scan_id,
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
    ] + env_args + ["devsecops/scanner:latest"]

    log.info("Docker scan command: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log.error("Docker scan failed: %s", result.stderr)
    else:
        log.info("Docker scan complete: %s", config.scan_id)


def _build_env_args(config: JobConfig) -> List[str]:
    env = {
        "SCAN_ID": config.scan_id,
        "PLATFORM": config.platform,
        "REPO_URL": config.repo_url,
        "REPO_FULL_NAME": config.repo_full_name,
        "PR_NUMBER": config.pr_number,
        "PR_SHA": config.pr_sha,
        "BRANCH": config.branch,
        "BASE_BRANCH": config.base_branch,
        "PR_LABELS": ",".join(config.labels),
        "API_TOKEN": config.api_token,
        "RESULTS_BUCKET": config.results_bucket,
        "DEFECTDOJO_URL": config.defectdojo_url,
        "DEFECTDOJO_TOKEN": config.defectdojo_token,
        "AI_API_KEY": config.ai_api_key,
        "DASHBOARD_URL": config.dashboard_url,
        "GITLAB_PROJECT_ID": config.gitlab_project_id or "",
    }
    args = []
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    return args


def _render_k8s_job(config: JobConfig) -> dict:
    env_vars = [
        {"name": k, "value": v} for k, v in {
            "SCAN_ID": config.scan_id,
            "PLATFORM": config.platform,
            "REPO_URL": config.repo_url,
            "REPO_FULL_NAME": config.repo_full_name,
            "PR_NUMBER": config.pr_number,
            "PR_SHA": config.pr_sha,
            "BRANCH": config.branch,
            "BASE_BRANCH": config.base_branch,
            "PR_LABELS": ",".join(config.labels),
            "RESULTS_BUCKET": config.results_bucket,
            "DEFECTDOJO_URL": config.defectdojo_url,
            "DEFECTDOJO_TOKEN": config.defectdojo_token,
            "DASHBOARD_URL": config.dashboard_url,
            "GITLAB_PROJECT_ID": config.gitlab_project_id or "",
        }.items()
    ] + [
        {"name": "API_TOKEN", "valueFrom": {"secretKeyRef": {"name": "devsecops-secrets", "key": "api-token"}}},
        {"name": "AI_API_KEY", "valueFrom": {"secretKeyRef": {"name": "devsecops-secrets", "key": "ai-api-key"}}},
    ]

    # Sanitise name for K8s (lowercase, no underscores)
    job_name = config.scan_id.lower().replace("_", "-")[:63]

    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": "devsecops",
            "labels": {"app": "devsecops-scanner", "scan_id": config.scan_id},
        },
        "spec": {
            "ttlSecondsAfterFinished": 3600,
            "backoffLimit": 1,
            "template": {
                "metadata": {"labels": {"app": "devsecops-scanner"}},
                "spec": {
                    "serviceAccountName": "devsecops-scanner",
                    "restartPolicy": "Never",
                    "initContainers": [{
                        "name": "git-clone",
                        "image": "alpine/git:latest",
                        "command": ["sh", "-c",
                            f"git clone --depth=50 {config.repo_url} /workspace && "
                            f"cd /workspace && git checkout {config.pr_sha}"],
                        "volumeMounts": [{"name": "workspace", "mountPath": "/workspace"}],
                        "env": [{"name": "GIT_TOKEN", "value": config.api_token}],
                    }],
                    "containers": [{
                        "name": "scanner",
                        "image": "devsecops/scanner:latest",
                        "imagePullPolicy": "Always",
                        "env": env_vars,
                        "volumeMounts": [
                            {"name": "workspace", "mountPath": "/workspace"},
                            {"name": "results", "mountPath": "/results"},
                        ],
                        "resources": {
                            "requests": {"cpu": "500m", "memory": "512Mi"},
                            "limits": {"cpu": "2", "memory": "3Gi"},
                        },
                        "securityContext": {"runAsNonRoot": False},  # Tools need root
                    }],
                    "volumes": [
                        {"name": "workspace", "emptyDir": {}},
                        {"name": "results", "emptyDir": {}},
                    ],
                },
            },
        },
    }
