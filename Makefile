SHELL := /bin/bash
.DEFAULT_GOAL := help

# ── Config ───────────────────────────────────────────────────────────
SCANNER        := ./scan-operator-antipatterns.sh
SEMGREP_RULES  := .semgrep-operator-antipatterns.yml
TESTDATA       := testdata
EVAL_RUNNER    := evaluations/run_eval.py

# Scan target — override with: make scan TARGET=/path/to/operator
TARGET         ?= $(TESTDATA)

# Container image for CI / Hermes deployment
IMAGE_REGISTRY ?= quay.io
IMAGE_REPO     ?= $(IMAGE_REGISTRY)/$(USER)/operator-anti-pattern-scanner
IMAGE_TAG      ?= latest
IMAGE          := $(IMAGE_REPO):$(IMAGE_TAG)

# Hermes / OpenShift deployment
NAMESPACE      ?= hermes
SKILL_NAME     := operator-anti-pattern-scanner

# ── Help ─────────────────────────────────────────────────────────────
.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Scan ─────────────────────────────────────────────────────────────
.PHONY: scan scan-json scan-semgrep
scan: ## Scan a repo for anti-patterns (TARGET=/path/to/repo)
	@$(SCANNER) $(TARGET)

scan-json: ## Scan and output JSON (TARGET=/path/to/repo)
	@$(SCANNER) $(TARGET) --json

scan-semgrep: check-semgrep ## Scan with ripgrep + semgrep SAST rules
	@$(SCANNER) $(TARGET) --semgrep

# ── Eval ─────────────────────────────────────────────────────────────
.PHONY: eval eval-json eval-verbose
eval: ## Run evaluation against test fixtures
	@python3 $(EVAL_RUNNER)

eval-verbose: ## Run evaluation with per-case details
	@python3 $(EVAL_RUNNER) -v

eval-json: ## Run evaluation and output JSON
	@python3 $(EVAL_RUNNER) --json

# ── Test ─────────────────────────────────────────────────────────────
.PHONY: test test-quick lint shellcheck
test: eval ## Run full test suite (alias for eval)

test-quick: ## Smoke test — expect all 10 APs detected in testdata
	@echo "Smoke test: scanning testdata..."
	@$(SCANNER) $(TESTDATA) --json 2>/dev/null | \
		python3 -c "import sys,json; d=json.load(sys.stdin); \
		cov=d['anti_pattern_coverage']; \
		detected=sum(1 for v in cov.values() if v['detected']); \
		print(f'Detected {detected}/10 anti-patterns'); \
		sys.exit(0 if detected == 10 else 1)"
	@echo "PASS"

shellcheck: ## Lint the scanner script with shellcheck
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not found"; exit 1; }
	shellcheck -x $(SCANNER)

lint: shellcheck ## Run all linters

# ── Dependencies ─────────────────────────────────────────────────────
.PHONY: check-deps check-semgrep install-semgrep
check-deps: ## Verify required tools are installed
	@echo "Checking dependencies..."
	@command -v rg      >/dev/null 2>&1 && echo "  rg:       $$(rg --version | head -1)"       || echo "  rg:       MISSING (required)"
	@command -v python3 >/dev/null 2>&1 && echo "  python3:  $$(python3 --version)"             || echo "  python3:  MISSING (required)"
	@command -v semgrep >/dev/null 2>&1 && echo "  semgrep:  $$(semgrep --version 2>/dev/null)" || echo "  semgrep:  not installed (optional)"
	@command -v podman  >/dev/null 2>&1 && echo "  podman:   $$(podman --version)"              || echo "  podman:   not installed (for container builds)"
	@command -v oc      >/dev/null 2>&1 && echo "  oc:       $$(oc version --client 2>/dev/null | head -1)" || echo "  oc:       not installed (for deploy)"

check-semgrep:
	@command -v semgrep >/dev/null 2>&1 || { echo "semgrep not found — run: make install-semgrep"; exit 1; }

install-semgrep: ## Install semgrep via pip
	pip install semgrep

# ── Container ────────────────────────────────────────────────────────
.PHONY: image image-build image-push image-run
image-build: ## Build container image
	podman build -t $(IMAGE) -f Containerfile .

image-push: image-build ## Build and push container image
	podman push $(IMAGE)

image-run: ## Run scanner in container (TARGET=/path/to/repo)
	podman run --rm -v $(realpath $(TARGET)):/repo:ro,Z $(IMAGE) /repo

image: image-build ## Alias for image-build

# ── Deploy (Hermes / OpenShift) ──────────────────────────────────────
.PHONY: deploy deploy-skill deploy-configmap undeploy
deploy-configmap: ## Create/update the skill ConfigMap in OpenShift
	@echo "Deploying skill ConfigMap to namespace $(NAMESPACE)..."
	oc create configmap $(SKILL_NAME)-skill \
		--from-file=SKILL.md=SKILL.md \
		--dry-run=client -o yaml | oc apply -n $(NAMESPACE) -f -

deploy-skill: deploy-configmap ## Deploy scanner as a Hermes skill
	@echo "Deploying scanner script ConfigMap..."
	oc create configmap $(SKILL_NAME)-scripts \
		--from-file=scan-operator-antipatterns.sh \
		--from-file=.semgrep-operator-antipatterns.yml \
		--dry-run=client -o yaml | oc apply -n $(NAMESPACE) -f -
	@echo ""
	@echo "Skill deployed. Mount these ConfigMaps into the Hermes pod:"
	@echo "  $(SKILL_NAME)-skill   → /opt/data/skills/$(SKILL_NAME)/SKILL.md"
	@echo "  $(SKILL_NAME)-scripts → /opt/data/skills/$(SKILL_NAME)/"

deploy: deploy-skill ## Full deploy (alias for deploy-skill)

undeploy: ## Remove skill ConfigMaps from OpenShift
	oc delete configmap $(SKILL_NAME)-skill $(SKILL_NAME)-scripts -n $(NAMESPACE) --ignore-not-found

# ── Scan remote repos ───────────────────────────────────────────────
.PHONY: scan-repo scan-repo-json
scan-repo: ## Clone and scan a remote repo (REPO=https://...)
ifndef REPO
	$(error Set REPO=https://github.com/org/operator-repo)
endif
	@tmpdir=$$(mktemp -d) && \
	echo "Cloning $(REPO) → $$tmpdir..." && \
	git clone --depth 1 $(REPO) "$$tmpdir/repo" 2>/dev/null && \
	$(SCANNER) "$$tmpdir/repo" && \
	rm -rf "$$tmpdir"

scan-repo-json: ## Clone and scan a remote repo, JSON output (REPO=...)
ifndef REPO
	$(error Set REPO=https://github.com/org/operator-repo)
endif
	@tmpdir=$$(mktemp -d) && \
	git clone --depth 1 $(REPO) "$$tmpdir/repo" 2>/dev/null && \
	$(SCANNER) "$$tmpdir/repo" --json && \
	rm -rf "$$tmpdir"

# ── Clean ────────────────────────────────────────────────────────────
.PHONY: clean
clean: ## Remove generated files
	rm -rf evaluations/__pycache__
