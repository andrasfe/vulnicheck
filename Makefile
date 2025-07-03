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

.PHONY: test
test: ## Run all tests (excluding deprecated cache tests)
	pytest -v tests/test_nvd_client.py tests/test_osv_client.py tests/test_scanner.py tests/integration/test_nvd_integration.py tests/integration/test_osv_integration.py

.PHONY: test-unit
test-unit: ## Run unit tests only (excluding deprecated cache tests)
	pytest -v tests/test_nvd_client.py tests/test_osv_client.py tests/test_scanner.py tests/test_lock_files.py tests/test_ghsa_cve_mapping.py

.PHONY: test-integration
test-integration: ## Run integration tests only (excluding deprecated cache tests)
	pytest -v tests/integration/test_nvd_integration.py tests/integration/test_osv_integration.py

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	pytest --cov=vulnicheck --cov-report=html --cov-report=term-missing

.PHONY: lint
lint: ## Run all linting checks (ruff, mypy)
	@echo "Running ruff..."
	ruff check vulnicheck/ tests/
	@echo "\nRunning mypy..."
	mypy vulnicheck/

.PHONY: lint-fix
lint-fix: ## Run ruff with auto-fix
	ruff check --fix vulnicheck/ tests/

.PHONY: format
format: ## Format code with ruff
	ruff format vulnicheck/ tests/

.PHONY: type-check
type-check: ## Run mypy type checking only
	mypy vulnicheck/

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