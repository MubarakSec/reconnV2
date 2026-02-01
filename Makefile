# ╔═══════════════════════════════════════════════════════════╗
# ║                  ReconnV2 Makefile                        ║
# ╚═══════════════════════════════════════════════════════════╝

.PHONY: help install clean test scan doctor deps

PYTHON := python3
VENV := .venv
PIP := $(VENV)/bin/pip
RECON := $(VENV)/bin/python -m recon_cli

# Colors
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m

help: ## Show this help
	@echo ""
	@echo "$(CYAN)ReconnV2 - Available Commands$(NC)"
	@echo "════════════════════════════════════════"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""

install: ## Install ReconnV2 and dependencies
	@echo "$(CYAN)[*] Installing ReconnV2...$(NC)"
	@$(PYTHON) -m venv $(VENV)
	@$(PIP) install --upgrade pip -q
	@$(PIP) install -e . -q
	@echo "$(GREEN)[✓] Installation complete$(NC)"

deps: ## Install external tools (requires sudo)
	@echo "$(CYAN)[*] Installing external dependencies...$(NC)"
	@sudo apt update -qq
	@sudo apt install -y subfinder amass nuclei httpx-toolkit
	@echo "$(GREEN)[✓] Dependencies installed$(NC)"

clean: ## Clean temporary files and caches
	@echo "$(CYAN)[*] Cleaning...$(NC)"
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf .pytest_cache build *.egg-info dist
	@echo "$(GREEN)[✓] Cleaned$(NC)"

test: ## Run tests
	@echo "$(CYAN)[*] Running tests...$(NC)"
	@$(VENV)/bin/pytest tests/ -v

doctor: ## Check system and tools
	@$(RECON) doctor

# Scan targets
scan: ## Run a scan (use: make scan TARGET=example.com)
ifndef TARGET
	@echo "$(YELLOW)Usage: make scan TARGET=example.com [PROFILE=passive]$(NC)"
else
	@$(RECON) scan $(TARGET) --profile $(or $(PROFILE),passive) --inline
endif

scan-passive: ## Passive scan (use: make scan-passive TARGET=example.com)
ifndef TARGET
	@echo "$(YELLOW)Usage: make scan-passive TARGET=example.com$(NC)"
else
	@$(RECON) scan $(TARGET) --profile passive --inline
endif

scan-full: ## Full scan (use: make scan-full TARGET=example.com)
ifndef TARGET
	@echo "$(YELLOW)Usage: make scan-full TARGET=example.com$(NC)"
else
	@$(RECON) scan $(TARGET) --profile full --scanner nuclei --inline
endif

scan-quick: ## Quick scan (use: make scan-quick TARGET=example.com)
ifndef TARGET
	@echo "$(YELLOW)Usage: make scan-quick TARGET=example.com$(NC)"
else
	@$(RECON) scan $(TARGET) --profile quick --inline
endif

# Job management
jobs: ## List all jobs
	@$(RECON) list-jobs

status: ## Show job status (use: make status JOB=<job-id>)
ifndef JOB
	@$(RECON) list-jobs --status running
else
	@$(RECON) status $(JOB)
endif

logs: ## Tail job logs (use: make logs JOB=<job-id>)
ifndef JOB
	@echo "$(YELLOW)Usage: make logs JOB=<job-id>$(NC)"
else
	@$(RECON) tail-logs $(JOB)
endif

export: ## Export job results (use: make export JOB=<job-id>)
ifndef JOB
	@echo "$(YELLOW)Usage: make export JOB=<job-id>$(NC)"
else
	@$(RECON) export $(JOB)
endif

report: ## Generate report (use: make report JOB=<job-id>)
ifndef JOB
	@echo "$(YELLOW)Usage: make report JOB=<job-id>$(NC)"
else
	@$(RECON) report $(JOB)
endif

# Maintenance
prune: ## Delete old jobs (older than 7 days)
	@$(RECON) prune --days 7

archive: ## Archive old jobs
	@$(RECON) prune --days 30 --archive

# ════════════════════════════════════════════════════════════
# Docker Commands (Easiest Installation!)
# ════════════════════════════════════════════════════════════

docker-build: ## Build Docker image
	@echo "$(CYAN)[*] Building Docker image...$(NC)"
	@docker build -t reconnv2:latest .
	@echo "$(GREEN)[✓] Docker image built$(NC)"

docker-up: ## Start all services (CLI + Web Dashboard)
	@echo "$(CYAN)[*] Starting ReconnV2 with Docker...$(NC)"
	@docker-compose up -d
	@echo "$(GREEN)[✓] Services started$(NC)"
	@echo "$(CYAN)    Web Dashboard: http://localhost:8080$(NC)"
	@echo "$(CYAN)    CLI: docker-compose exec recon recon interactive$(NC)"

docker-down: ## Stop all services
	@docker-compose down

docker-logs: ## View Docker logs
	@docker-compose logs -f

docker-shell: ## Open shell in container
	@docker-compose exec recon bash

docker-scan: ## Run scan in Docker (use: make docker-scan TARGET=example.com)
ifndef TARGET
	@echo "$(YELLOW)Usage: make docker-scan TARGET=example.com [PROFILE=passive]$(NC)"
else
	@docker-compose exec recon recon scan $(TARGET) --profile $(or $(PROFILE),passive) --inline
endif

docker-interactive: ## Start interactive mode in Docker
	@docker-compose exec recon recon interactive

docker-wizard: ## Start wizard in Docker
	@docker-compose exec recon recon wizard

docker-web: ## Open web dashboard URL
	@echo "$(CYAN)Opening http://localhost:8080$(NC)"
	@xdg-open http://localhost:8080 2>/dev/null || open http://localhost:8080 2>/dev/null || echo "Open http://localhost:8080 in your browser"

docker-clean: ## Remove Docker containers and images
	@docker-compose down -v --rmi local
