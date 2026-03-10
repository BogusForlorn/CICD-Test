# DevSecOps CI/CD Security Framework

Automated security testing pipeline for pull requests. Runs parallel
security scans on every PR, posts AI-generated remediation to the PR,
and enforces a human-approval gate before any merge to main.

## Tool Stack (100% Open Source)

| Category | Tool | What it covers |
|---|---|---|
| SAST | Semgrep | Python, Java, JS/TS, Go, PHP, Ruby — replaces Bandit & SpotBugs |
| SCA + IaC + Secrets + Container | Trivy | OS/language CVEs, Dockerfile, K8s YAML, filesystem secrets |
| Secrets (Git history) | Gitleaks | Full commit history secret scanning |
| IaC (comprehensive) | Checkov | Terraform, CloudFormation, ARM, Helm, Ansible — 1000+ policies |
| DAST | OWASP ZAP | Runtime attack simulation against staging app |
| IAST | OpenTelemetry | Runtime agent correlating DAST traffic with app internals |

## Quick Start

### GitHub Actions (recommended for most teams)

1. Copy `.github/workflows/devsecops.yml` to your repo.
2. Add GitHub Actions secrets:
   - `AI_API_KEY` — API key for your selected AI provider (`anthropic`, `openai`, or `gemini`)
   - `RESULTS_BUCKET` — S3 bucket name (or skip for local)
   - `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
   - `DEFECTDOJO_URL` / `DEFECTDOJO_TOKEN` (optional)
3. Set provider/model env vars (repository variables or workflow env):
   - `AI_PROVIDER` — `anthropic` (default) | `openai` | `gemini`
   - `AI_MODEL` — optional override; leave empty to use provider defaults
4. Set branch protection on `main`:
   - Require status check: `devsecops/security-gate`
   - Block merges until check passes
5. Push a PR — scans run automatically.

### Self-hosted on Kubernetes

```bash
# 1. Clone this repo
git clone <this-repo>
cd devsecops-framework

# 2. Configure environment
cp .env.example .env
# Edit .env with your tokens and bucket details

# 3. Build and push images
export IMAGE_REGISTRY=your-registry.io/devsecops
make build push

# 4. Deploy via Helm
make deploy-k8s

# 5. Register webhooks in GitHub/GitLab
#    URL: https://YOUR_INGRESS_HOST/webhook/github (or /webhook/gitlab)
```

### Local / Docker Compose

```bash
cp .env.example .env  # Fill in values
make local
# Orchestrator: http://localhost:8000
# Dashboard:    http://localhost:8080
# Use ngrok or similar to expose /webhook/github for testing
```

## System Flow

```
Developer opens PR
       ↓
Webhook → Orchestrator → K8s Job (or Docker)
                              ↓
              ┌───────────────┼───────────────┐
           Trivy           Semgrep         Gitleaks
        (SCA+IaC+          (SAST)         (Secrets)
      Secrets+Container)
              └───────────────┼───────────────┘
                         Checkov            ZAP
                          (IaC)           (DAST)
                              ↓
                   Aggregator Service
                   AI Remediation (1:1)
                   Decision Engine
                              ↓
              ┌───────────────┼───────────────┐
           FAIL                            PASS
             ↓                               ↓
    Git API: status=failure      Git API: status=success
    PR comment with findings     PR comment: "Awaiting approval"
    Verbose JSON to S3           Verbose JSON to S3
    Dashboard updated            Dashboard updated
             ↓                               ↓
    PR BLOCKED — cannot merge    Human operator reviews + approves
```

## Findings Enrichment

- Remediation suggestion is included per finding, prioritising AI remediation steps with native-tool fallback.
- CVSS severity is normalised per finding:
  - Uses native tool CVSS when available.
  - If missing, calls the LLM API twice to estimate CVSS and performs strict string comparison.
  - If both CVSS strings match, the verified score/vector/severity are used.
  - If they do not match, the finding is marked `(unable to estimate cvss)` and both returned CVSS strings are kept in the report.
- CVE handling includes:
  - CVE ID extraction from scanner findings.
  - CVE test methods mapped to the detecting tool.
  - PoC guidance per CVE finding (reference-based when available, otherwise generated/fallback).
- Dashboard reporting includes CVE + PoC entries for each scan and exposes a JSON endpoint at `/scan/{scan_id}/cves`.

## Configuration

Each repo can override defaults by committing `security-policy.yaml` to its root.
See the included `security-policy.yaml` for all options.

AI provider selection can be configured in either place:
- Environment variables (`AI_PROVIDER`, `AI_MODEL`)
- Repo policy (`policy.ai_remediation.provider`, `policy.ai_remediation.model`)

If `model` is omitted/empty, provider defaults are used:
- `anthropic` -> `claude-opus-4-6`
- `openai` -> `gpt-4o-mini`
- `gemini` -> `gemini-1.5-pro`

## Secrets Required

| Variable | Description |
|---|---|
| `GITHUB_TOKEN` / `GITLAB_TOKEN` | Personal Access Token with repo + PR write access |
| `GITHUB_WEBHOOK_SECRET` | HMAC secret for webhook validation |
| `AI_API_KEY` | API key used for AI remediation, CVSS estimation, and CVE PoC generation |
| `RESULTS_BUCKET` | S3 bucket or Azure container for JSON reports |
| `DEFECTDOJO_URL` + `DEFECTDOJO_TOKEN` | Optional DefectDojo integration |

## Architecture

- **Orchestrator** — FastAPI webhook receiver; launches scan jobs
- **Scanner** — Docker image with all tools; runs on K8s Jobs or Docker
- **Aggregator** — Deduplicates findings, calls AI per finding, makes decision
- **Dashboard** — Lightweight real-time PR scan viewer
- All services are stateless and horizontally scalable
