# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulniCheck is a Python-based MCP (Model Context Protocol) server that provides real-time security vulnerability checking for Python packages. It queries multiple authoritative vulnerability databases including OSV.dev, NVD (National Vulnerability Database), and GitHub Advisory Database.

## Key Commands

### Development Setup
```bash
# Install development dependencies with uv
uv pip install -e ".[dev]"

# Or traditional pip
pip install -e ".[dev]"
```

### Testing
```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests only (requires API credentials)
make test-integration

# Run tests with coverage
make test-coverage

# Run specific test categories
make test-mcp        # MCP-related tests
make test-security   # Security-related tests
make test-clients    # Client tests

# Run a single test file
pytest tests/test_scanner.py -v
```

**Note**: Integration tests for GitHub API require `GITHUB_TOKEN` environment variable to avoid rate limiting. Tests will be skipped if credentials are not available.

### Code Quality
```bash
# Run all linting and type checking
make lint

# Auto-fix linting issues
make lint-fix

# Format code with ruff
make format

# Type checking only
make type-check
```

### Pre-commit Hooks
The project uses pre-commit hooks to ensure code quality before commits:

```bash
# Install pre-commit hooks (one-time setup)
uv run pre-commit install

# Run pre-commit hooks manually on all files
uv run pre-commit run --all-files

# Skip pre-commit hooks temporarily (not recommended)
git commit --no-verify
```

**Pre-commit checks include:**
- Standard checks (trailing whitespace, file endings, yaml/json/toml validation)
- `make lint` - Runs ruff and mypy checks
- `make test-unit` - Runs unit tests
- Detects private keys and merge conflicts

### Running the Server
```bash
# Run server normally
make run

# Run with debug logging
make debug

# Or directly
vulnicheck
```

### Docker Operations
```bash
# Build and run with setup script
./setup.sh

# Build Docker images
make docker-build

# View logs
docker-compose logs -f

# Stop service
docker-compose down
```

## Architecture

### Core Components

1. **MCP Server** (`vulnicheck/server.py`): FastMCP-based server exposing vulnerability checking tools via Model Context Protocol
   - Tools: `check_package_vulnerabilities`, `scan_dependencies`, `scan_installed_packages`, `get_cve_details`, `scan_for_secrets`, `validate_mcp_security`, `mcp_passthrough_tool`, `scan_dockerfile`, `assess_operation_safety`, `comprehensive_security_check`, `get_mcp_conversations`
   - Runs on port 3000 by default (configurable via MCP_PORT env var)

2. **Vulnerability Clients**:
   - `osv_client.py`: Queries OSV.dev API for open source vulnerabilities (includes PyPI Advisory Database)
   - `nvd_client.py`: Queries NIST National Vulnerability Database (supports API key for higher rate limits)
   - `github_client.py`: Queries GitHub Advisory Database (supports token for higher rate limits)
   - `circl_client.py`: Queries CIRCL Vulnerability-Lookup API (aggregates multiple sources, no auth required)
   - `safety_db_client.py`: Queries Safety DB for Python-specific vulnerabilities (open source, updated monthly)

3. **MCP Client** (`mcp_client.py`):
   - Custom implementation instead of official MCP SDK for persistent connections
   - Supports both stdio and HTTP transports (with SSE response parsing)
   - Manages connection pooling for efficient passthrough operations
   - See module docstring for detailed explanation of why SDK wasn't suitable

4. **Scanner** (`scanner.py`):
   - Parses dependency files (requirements.txt, pyproject.toml, lock files)
   - Falls back to Python import scanning when no dependency file exists
   - Coordinates vulnerability checking across all clients

5. **Secrets Scanner** (`secrets_scanner.py`): Uses detect-secrets to find exposed credentials

6. **MCP Validator** (`mcp_validator.py`): Integrates mcp-scan for LLM self-validation of security posture

7. **MCP Passthrough** (`mcp_passthrough.py`, `mcp_passthrough_with_approval.py`, `mcp_passthrough_interactive.py`):
   - Provides secure proxying of MCP tool calls with risk assessment
   - **LLM-Based Risk Assessment**: Uses OpenAI/Anthropic APIs to intelligently assess risk
   - Pattern matching only used as fallback when LLM is unavailable
   - Supports approval workflows for high-risk operations
   - **Interactive Approval Mode**: Enhanced version with true interactive approval flow where execution pauses until explicit approval/denial
   - Logs all MCP interactions with full payloads (hourly rotation)
   - **HTTP Transport Support**: Can connect to HTTP/SSE MCP servers (e.g., context7)

8. **Docker Scanner** (`docker_scanner.py`):
   - Analyzes Dockerfiles for Python package installations
   - Supports multiple package managers (pip, poetry, pipenv, conda)
   - Extracts package versions and checks for vulnerabilities
   - Identifies referenced dependency files

9. **Rate Limiting** (`rate_limiter.py`): Handles API rate limits for external services

10. **Safety Advisor** (`safety_advisor.py`):
   - Pre-operation risk assessment tool for LLMs
   - Uses LLM-based assessment when API keys are available
   - Falls back to structured risk patterns when LLM unavailable
   - Provides risk levels, specific risks, recommendations, and approval requirements
   - Returns user-friendly guidance for risk evaluation when no LLM is available

11. **Comprehensive Security Check** (`comprehensive_security_check.py`):
   - Interactive security assessment tool that orchestrates all other security tools
   - **Requires LLM**: Only available when OPENAI_API_KEY or ANTHROPIC_API_KEY is configured
   - **Interactive Conversation**: Asks clarifying questions one at a time
   - **Automatic Discovery**: Finds dependencies, Dockerfiles, MCP configs, and Python files
   - **Selective Scanning**: Only runs scans confirmed by the user
   - **LLM Analysis**: Uses AI to analyze findings, prioritize risks, and generate recommendations
   - **Comprehensive Report**: Includes executive summary, risk scoring, and actionable recommendations

12. **Conversation Storage** (`conversation_storage.py`):
   - Stores all MCP passthrough interactions for audit and debugging
   - **Lazy Initialization**: Directory `.vulnicheck/conversations` created on first use
   - **Automatic Logging**: All passthrough operations (basic, with_approval, interactive) are logged
   - **Message Tracking**: Stores requests, responses, risk assessments, and errors
   - **Search Capability**: Find conversations by tool name, parameters, or results
   - **Active Sessions**: Conversations stay active for 1 hour for continuity
   - **Cleanup**: Old conversations (30+ days) can be automatically removed

### Key Implementation Details

- All clients are initialized lazily to avoid connection issues at startup
- Extensive caching using `@lru_cache` to minimize API calls
- Comprehensive error handling and fallback mechanisms
- Security-focused with file size limits and path validation
- Returns vulnerability data with disclaimers about "AS IS" warranty
- **LLM Risk Assessment** (`llm_risk_assessor.py`):
  - Supports both OpenAI and Anthropic APIs
  - Analyzes MCP requests/responses for security risks
  - Returns structured risk levels: BLOCKED, HIGH_RISK, REQUIRES_APPROVAL, LOW_RISK
  - Gracefully degrades to pattern matching when API unavailable

## Environment Variables

- `NVD_API_KEY`: API key for NVD (increases rate limit from 5 to 50 requests/30s)
- `GITHUB_TOKEN`: GitHub token for Advisory Database (increases rate limit to 5000 requests/hour)
- `OPENAI_API_KEY`: OpenAI API key for LLM-based risk assessment in MCP passthrough
- `ANTHROPIC_API_KEY`: Anthropic API key for LLM-based risk assessment (alternative to OpenAI)
- `MCP_PORT`: Port for MCP server (default: 3000)
- `CACHE_TTL`: Cache time-to-live in seconds (default: 900)
- `REQUEST_TIMEOUT`: API request timeout in seconds
- `VULNICHECK_DEBUG`: Enable debug logging
- `VULNICHECK_LOG_LEVEL`: Log level for MCP interactions (default: INFO)
- `VULNICHECK_LOG_CONSOLE`: Enable console logging for MCP interactions (default: false)

## Logging

### MCP Interaction Logging
- All MCP passthrough interactions are logged to `~/.vulnicheck/logs/mcp_interactions.log`
- Logs include full request/response payloads in JSON format
- Hourly log rotation is enabled with timestamp-based filenames
- Rotated logs follow pattern: `mcp_interactions.log.YYYYMMDD_HHMMSS.log`

## Architectural Decisions

### Why Custom MCP Client Instead of Official SDK?

While the official Anthropic MCP SDK provides persistent connections and high-level abstractions, we need a custom implementation to handle specific compatibility issues:

1. **HTTP/SSE Hybrid Servers**: Some MCP servers (like context7) return SSE-formatted responses to regular HTTP POST requests. The SDK's SSE client expects continuous streams and hangs, while the StreamableHTTP client can't parse SSE format.

2. **Unified Transport Interface**: Our implementation provides a single interface that automatically handles stdio, HTTP, and HTTP+SSE responses without requiring different client types.

3. **Passthrough Optimization**: Connection pooling and error handling optimized for the passthrough server use case.

See the docstring in `mcp_client.py` for more details.

## Testing Approach

- Unit tests focus on individual components (clients, scanner)
- Integration tests verify full workflows and API interactions
- Test data includes vulnerable packages for verification
- Uses pytest with async support via pytest-asyncio
- All tests run with `uv run` to ensure proper virtual environment usage
- Makefile includes targets for different test categories (unit, integration, MCP, security, clients)
- Type checking configured with mypy (strict for production code, relaxed for tests)
- **Test Status**: 294 unit tests passing, 2 skipped (integration tests requiring API credentials)

## Important Notes

- This is a defensive security tool - do not modify for malicious purposes
- All vulnerability data comes with legal disclaimers
- The server performs read-only operations
- Supports both exact version checking (via lock files) and version range checking
- When scanning directories without dependency files, imports are analyzed and latest versions checked
- The `validate_mcp_security` tool allows LLMs to self-assess their security posture before performing sensitive operations
- MCP passthrough includes intelligent LLM-based security validation to prevent dangerous operations
  - LLM assessment provides context-aware risk evaluation instead of rigid pattern matching
  - Falls back to pattern matching only when LLM APIs are unavailable
- Test order dependencies have been resolved to ensure consistent test results

## Recent Improvements (2025)

- **Added two new vulnerability databases** for comprehensive coverage:
  - CIRCL Vulnerability-Lookup API (aggregates data from multiple sources)
  - Safety DB (Python-specific vulnerabilities not always in CVE databases)
- Fixed integration tests to properly skip when API credentials are unavailable
- Updated Makefile to include all test files and proper linting coverage
- Resolved all type annotation and mypy issues
- Added comprehensive MCP interaction logging with full payload capture
- Implemented hourly log rotation for MCP logs
- Fixed test order dependencies that were causing intermittent failures
- All tests now pass (272 unit tests, 2 skipped) with clean linting and type checking
- Added pre-commit hooks that run `make lint` and `make test-unit` before commits
- Added `scan_dockerfile` tool to analyze Dockerfiles for Python dependency vulnerabilities
- **Implemented LLM-based risk assessment for MCP passthrough**:
  - Integrates with OpenAI/Anthropic APIs for intelligent security decisions
  - Provides context-aware risk evaluation instead of rigid pattern matching
  - Automatically falls back to pattern matching when LLM is unavailable
  - Significantly reduces false positives while maintaining security
- **Added safety advisor tool (`assess_operation_safety`)**:
  - Pre-operation risk assessment tool that LLMs can consult before performing potentially dangerous operations
  - Uses LLM-based assessment when OPENAI_API_KEY or ANTHROPIC_API_KEY is available
  - Falls back to structured risk patterns and user guidance when no LLM is available
  - Provides comprehensive risk assessment with specific risks, recommendations, and approval requirements
  - Returns guidance: "you should evaluate based on your risk aversion whether this is a safe thing to do. as a first step, enumerate the risks involved, then assess each risk. finally, if you identify risks, ask the human if they are willing to accept this risk."
- **Added HTTP/SSE transport support for MCP client**:
  - MCP passthrough can now connect to HTTP-based MCP servers like context7
  - Properly handles Server-Sent Events (SSE) responses
  - Supports both traditional HTTP and SSE-based MCP servers
- **Enhanced Interactive Approval Mechanism**:
  - Added `mcp_passthrough_interactive.py` for true interactive approval flows
  - Operations pause until user explicitly approves/denies via separate tool calls
  - Supports pre-approved operations to avoid repeated approval requests
  - 5-minute expiration for pending operations
- **Comprehensive Security Check Tool**:
  - Added `comprehensive_security_check` tool for interactive, AI-powered security assessment
  - Requires LLM configuration (OpenAI or Anthropic API key)
  - Discovers project resources automatically and asks for confirmation
  - Orchestrates all security tools (dependencies, Docker, secrets, MCP) based on user choices
  - Uses LLM to analyze findings, prioritize risks, and generate actionable recommendations
  - Produces executive summary with overall risk scoring
- **Conversation Storage and Retrieval**:
  - Added automatic conversation logging for all MCP passthrough operations
  - Conversations stored locally in `.vulnicheck/conversations` directory (created on first use)
  - Added `get_mcp_conversations` tool to retrieve and search past interactions
  - Tracks requests, responses, risk assessments, and errors for each conversation
  - Supports filtering by client, server, and search queries
  - Active conversations persist for 1 hour to maintain continuity
  - Includes conversation cleanup functionality for old conversations (30+ days)

## Memories

- No Docker for VulniCheck deployment. Remember that Docker is not used for deploying the VulniCheck service.
- Always do testing and linting before commit
- Never add claude as co-author
