# ============================================================
# DevSecOps Framework — Makefile
# ============================================================

.PHONY: build push deploy-k8s local test help

IMAGE_REGISTRY ?= your-registry.io/devsecops
TAG ?= latest

## Build all Docker images
build:
	docker build -t $(IMAGE_REGISTRY)/orchestrator:$(TAG) ./orchestrator
	docker build -t $(IMAGE_REGISTRY)/aggregator:$(TAG)   ./aggregator
	docker build -t $(IMAGE_REGISTRY)/dashboard:$(TAG)    ./dashboard
	docker build -t $(IMAGE_REGISTRY)/scanner:$(TAG)      ./scanner
	@echo "All images built."

## Push images to registry
push: build
	docker push $(IMAGE_REGISTRY)/orchestrator:$(TAG)
	docker push $(IMAGE_REGISTRY)/aggregator:$(TAG)
	docker push $(IMAGE_REGISTRY)/dashboard:$(TAG)
	docker push $(IMAGE_REGISTRY)/scanner:$(TAG)
	@echo "All images pushed."

## Deploy to Kubernetes via Helm
deploy-k8s:
	@echo "Deploying DevSecOps framework to Kubernetes..."
	helm upgrade --install devsecops-framework ./helm \
		--namespace devsecops \
		--create-namespace \
		--set secrets.githubToken=$${GITHUB_TOKEN} \
		--set secrets.gitlabToken=$${GITLAB_TOKEN} \
		--set secrets.githubWebhookSecret=$${GITHUB_WEBHOOK_SECRET} \
		--set secrets.aiApiKey=$${AI_API_KEY} \
		--set secrets.resultsBucket=$${RESULTS_BUCKET} \
		--set secrets.awsAccessKeyId=$${AWS_ACCESS_KEY_ID} \
		--set secrets.awsSecretAccessKey=$${AWS_SECRET_ACCESS_KEY} \
		--set secrets.defectdojoUrl=$${DEFECTDOJO_URL} \
		--set secrets.defectdojoToken=$${DEFECTDOJO_TOKEN} \
		--values helm/values.yaml
	@echo "Deployed."

## Start locally with Docker Compose
local:
	cp .env.example .env 2>/dev/null || true
	docker compose up --build -d
	@echo "Services running:"
	@echo "  Orchestrator: http://localhost:8000"
	@echo "  Aggregator:   http://localhost:8001"
	@echo "  Dashboard:    http://localhost:8080"

## Stop local services
down:
	docker compose down --volumes

## Test webhook locally (requires ngrok or similar)
test-webhook:
	@echo "Register GitHub webhook:"
	@echo "  URL: http://YOUR_NGROK_URL/webhook/github"
	@echo "  Content-Type: application/json"
	@echo "  Events: Pull requests"
	@echo "  Secret: $${GITHUB_WEBHOOK_SECRET}"

help:
	@grep -E '^## ' Makefile | sed 's/## //'
