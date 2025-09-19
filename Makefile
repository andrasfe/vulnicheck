# VulniCheck Makefile

.PHONY: help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: install
install: ## Install the package in development mode
	uv pip install -e .

.PHONY: install-dev
install-dev: ## Install development dependencies
	uv pip install -e ".[dev]"

.PHONY: install-local
install-local: ## Set up local development environment with venv and Claude integration
	@bash run-local.sh

.PHONY: test
test: ## Run all tests
	uv run pytest -v tests/

.PHONY: test-unit
test-unit: ## Run unit tests only
	uv run pytest -v tests/ -k "not integration"

.PHONY: test-integration
test-integration: ## Run integration tests only
	uv run pytest -v tests/integration/

.PHONY: test-mcp
test-mcp: ## Run MCP-related tests only
	uv run pytest -v tests/test_mcp*.py tests/integration/test_mcp*.py

.PHONY: test-security
test-security: ## Run security-related tests only
	uv run pytest -v tests/test_dangerous_commands*.py tests/test_secrets_scanner.py tests/test_mcp_validator.py

.PHONY: test-clients
test-clients: ## Run vulnerability client tests only
	uv run pytest -v tests/test_nvd_client.py tests/test_osv_client.py tests/test_github_client.py

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	uv run pytest --cov=vulnicheck --cov-report=html --cov-report=term-missing --cov-report=xml tests/

.PHONY: lint
lint: ## Run all linting checks (ruff, mypy)
	@echo "Running ruff..."
	uv run ruff check vulnicheck/ tests/
	@echo "\nRunning mypy..."
	uv run mypy vulnicheck/ tests/

.PHONY: lint-fix
lint-fix: ## Run ruff with auto-fix
	uv run ruff check --fix vulnicheck/ tests/

.PHONY: format
format: ## Format code with ruff
	uv run ruff format vulnicheck/ tests/

.PHONY: type-check
type-check: ## Run mypy type checking only
	uv run mypy vulnicheck/ tests/

.PHONY: clean
clean: ## Clean up build artifacts and cache files
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

.PHONY: build
build: clean ## Build distribution packages
	uv build


.PHONY: run
run: ## Run the VulniCheck server
	vulnicheck

.PHONY: debug
debug: ## Run server with debug logging
	VULNICHECK_DEBUG=true vulnicheck

.PHONY: check
check: lint test ## Run all checks (lint + test)

.PHONY: pre-commit
pre-commit: format lint test ## Run pre-commit checks

.PHONY: docs
docs: ## Generate documentation (placeholder for future)
	@echo "Documentation generation not yet implemented"

.PHONY: release
release: clean build ## Prepare for release (clean + build)
	@echo "Ready for release. Don't forget to:"
	@echo "  1. Update version in pyproject.toml"
	@echo "  2. Create git tag"
	@echo "  3. Push to PyPI"
