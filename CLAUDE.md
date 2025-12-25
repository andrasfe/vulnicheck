# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulniCheck is a Python-based MCP (Model Context Protocol) HTTP server that provides real-time security vulnerability checking for Python packages. It runs as an HTTP-only service with support for both local file access and client-delegated file operations via the FileProvider architecture. The server queries multiple authoritative vulnerability databases including OSV.dev, NVD (National Vulnerability Database), and GitHub Advisory Database.

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

### Running the HTTP Server
```bash
# Run HTTP server normally (starts on port 3000 by default)
make run

# Run with debug logging
make debug

# Or directly
vulnicheck

# Run with Google OAuth authentication
vulnicheck --auth-mode google

# Server will be available at http://localhost:3000
# Use MCP_PORT environment variable to change port

# Authentication modes:
#   --auth-mode none    (default, no authentication)
#   --auth-mode google  (requires OAuth credentials in environment)
```

### Docker Operations
```bash
# Build and run with setup script
./setup.sh

# Build Docker images
make docker-build

# Run with Google OAuth authentication
docker run -p 3000:3000 \
  -e FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID="your-client-id" \
  -e FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET="your-secret" \
  -e FASTMCP_SERVER_BASE_URL="https://your-domain.com" \
  -v vulnicheck_tokens:/home/vulnicheck/.vulnicheck/tokens \
  andrasfe/vulnicheck:latest \
  python -m vulnicheck.server --auth-mode google

# View logs
docker-compose logs -f

# Stop service
docker-compose down

# See docker-compose.auth-example.yml for full configuration example
```

## Architecture

### Core Components

1. **MCP Server** (`vulnicheck/server.py`): FastMCP-based server exposing vulnerability checking tools via Model Context Protocol
   - Tools:
     - `check_package_vulnerabilities`: Check vulnerabilities for a specific Python package
     - `scan_dependencies`: Scan a dependency file (requirements.txt, pyproject.toml, setup.py, etc.)
     - `scan_installed_packages`: Scan currently installed Python packages
     - `get_cve_details`: Get detailed information about a specific CVE
     - `scan_for_secrets`: Scan files/directories for exposed secrets and credentials
     - `validate_mcp_security`: Validate MCP server security configuration
     - `mcp_passthrough_tool`: Securely proxy MCP tool calls with risk assessment
     - `approve_mcp_operation`: Approve a pending MCP operation (interactive mode)
     - `deny_mcp_operation`: Deny a pending MCP operation (interactive mode)
     - `list_mcp_servers`: List available MCP servers for an agent
     - `scan_dockerfile`: Analyze Dockerfiles for Python dependency vulnerabilities
     - `assess_operation_safety`: Pre-operation risk assessment for LLMs
     - `comprehensive_security_check`: Interactive AI-powered security assessment
     - `get_mcp_conversations`: Retrieve and search past MCP interactions
     - `scan_github_repo`: Comprehensive security analysis of GitHub repositories
     - `install_vulnicheck_guide`: Installation guide for Claude Code users
     - `manage_trust_store`: Manage MCP server trust store for configuration security
   - Runs on port 3000 by default (configurable via MCP_PORT env var)

2. **Vulnerability Clients**:
   - `osv_client.py`: Queries OSV.dev API for open source vulnerabilities (includes PyPI Advisory Database)
   - `nvd_client.py`: Queries NIST National Vulnerability Database (supports API key for higher rate limits)
   - `github_client.py`: Queries GitHub Advisory Database (supports token for higher rate limits)
   - `circl_client.py`: Queries CIRCL Vulnerability-Lookup API (aggregates multiple sources, no auth required)
   - `safety_db_client.py`: Queries Safety DB for Python-specific vulnerabilities (open source, updated monthly)

3. **MCP Client** (`mcp_client.py`):
   - Custom implementation instead of official MCP SDK for persistent connections
   - Supports HTTP transport only (with SSE response parsing)
   - Manages connection pooling for efficient passthrough operations
   - See module docstring for detailed explanation of why SDK wasn't suitable

4. **FileProvider Architecture** (`vulnicheck/providers/`):
   - **FileProvider Interface**: Abstract base class for file operations
   - **LocalFileProvider**: Direct filesystem access for server-side operations
   - **MCPClientFileProvider**: Client-delegated file operations for HTTP-only deployment
   - **FileProviderManager**: Factory and caching for provider instances
   - **Hybrid Deployment**: Local files for GitHub repos, client delegation for user files
   - **Security Features**: Path validation, size limits, permission checking, audit logging
   - **MCP Client Tools Required**: `read_file`, `read_file_binary`, `list_directory`, `file_exists`, `get_file_stats`

5. **Scanner** (`scanner.py`):
   - Parses dependency files (requirements.txt, pyproject.toml, setup.py, lock files)
   - Falls back to Python import scanning when no dependency file exists
   - Coordinates vulnerability checking across all clients

6. **Secrets Scanner** (`secrets_scanner.py`): Uses detect-secrets to find exposed credentials

7. **MCP Validator** (`mcp_validator.py`): Integrates mcp-scan for LLM self-validation of security posture

8. **Unified MCP Passthrough Architecture** (`vulnicheck/mcp/unified_passthrough.py`):
   - **Strategy Pattern Implementation**: Consolidated three separate passthrough implementations into unified architecture
   - **Backward Compatibility**: Wrapper classes maintain 100% API compatibility with legacy implementations
   - **40% Code Reduction**: Reduced from 2,121 lines across 3 files to ~900 lines unified implementation
   - **LLM-Based Risk Assessment**: Uses OpenAI/Anthropic APIs to intelligently assess risk
   - **Multiple Approval Modes**: AUTO (automatic), CALLBACK (custom approval functions), INTERACTIVE (manual approval)
   - **Security Integration**: Unified security layer with trust store validation and response sanitization
   - **HTTP Transport Support**: Can connect to HTTP/SSE MCP servers (e.g., context7)
   - **Conversation Logging**: All MCP interactions logged with full payloads (hourly rotation)

9. **Docker Scanner** (`docker_scanner.py`):
   - Analyzes Dockerfiles for Python package installations
   - Supports multiple package managers (pip, poetry, pipenv, conda)
   - Extracts package versions and checks for vulnerabilities
   - Identifies referenced dependency files

10. **Rate Limiting** (`rate_limiter.py`): Handles API rate limits for external services

11. **Safety Advisor** (`safety_advisor.py`):
   - Pre-operation risk assessment tool for LLMs
   - Uses LLM-based assessment when API keys are available
   - Falls back to structured risk patterns when LLM unavailable
   - Provides risk levels, specific risks, recommendations, and approval requirements
   - Returns user-friendly guidance for risk evaluation when no LLM is available

12. **Comprehensive Security Check** (`comprehensive_security_check.py`):
   - Interactive security assessment tool that orchestrates all other security tools
   - **Requires LLM**: Only available when OPENAI_API_KEY or ANTHROPIC_API_KEY is configured
   - **Interactive Conversation**: Asks clarifying questions one at a time
   - **Automatic Discovery**: Finds dependencies, Dockerfiles, MCP configs, and Python files
   - **Selective Scanning**: Only runs scans confirmed by the user
   - **LLM Analysis**: Uses AI to analyze findings, prioritize risks, and generate recommendations
   - **Comprehensive Report**: Includes executive summary, risk scoring, and actionable recommendations

13. **Conversation Storage** (`conversation_storage.py`):
   - Stores all MCP passthrough interactions for audit and debugging
   - **Lazy Initialization**: Directory `.vulnicheck/conversations` created on first use
   - **Automatic Logging**: All passthrough operations (basic, with_approval, interactive) are logged
   - **Message Tracking**: Stores requests, responses, risk assessments, and errors
   - **Search Capability**: Find conversations by tool name, parameters, or results
   - **Active Sessions**: Conversations stay active for 1 hour for continuity
   - **Cleanup**: Old conversations (30+ days) can be automatically removed

14. **GitHub Repository Scanner** (`github_scanner.py`):
   - Comprehensive security analysis of GitHub repositories
   - **URL Parsing**: Supports multiple GitHub URL formats (HTTPS, SSH, branches, commits)
   - **Repository Cloning**: Clones repositories with authentication support for private repos
   - **Parallel Scanning**: Runs dependency, secrets, and Dockerfile scans concurrently
   - **Smart Caching**: Caches results by commit SHA for 24 hours
   - **Remediation Recommendations**: Provides prioritized action items
   - **Integration**: Leverages existing scanners (DependencyScanner, SecretsScanner, DockerScanner)

15. **Core Utilities** (`vulnicheck/core/`):
   - `agent_detector.py`: Detects AI agent from environment and headers
   - `cache.py`: Configurable caching with TTL support
   - `logging_config.py`: Centralized logging configuration for MCP interactions
   - `mcp_paths.py`: Manages MCP configuration paths per agent
   - `rate_limiter.py`: Rate limiting for API calls to external services

16. **Context Protector Integration** (inspired by [Trail of Bits Context Protector](https://blog.trailofbits.com/2025/07/28/we-built-the-security-layer-mcp-always-needed/)):
   - **Trust Store** (`vulnicheck/mcp/trust_store.py`): Trust-on-first-use server configuration pinning
   - **Response Sanitizer** (`vulnicheck/security/response_sanitizer.py`): ANSI escape sequence removal and prompt injection detection
   - **Unified Security Layer** (`vulnicheck/security/unified_security.py`): Combines all security mechanisms into a single API
   - Features:
     - Server configuration validation blocks untrusted or modified servers
     - Pre-execution parameter sanitization
     - Post-execution response sanitization
     - Intelligent risk assessment using LLM when available, pattern matching as fallback
     - Risk levels: BLOCKED, HIGH_RISK, REQUIRES_APPROVAL, LOW_RISK, SAFE
   - All passthrough variants now use this unified security layer for consistent protection

17. **Trust Store Management** (`vulnicheck/tools/manage_trust_store.py`):
   - Manages trusted MCP server configurations to prevent unauthorized changes
   - Supports list, add, remove, and verify operations
   - Trust-on-first-use model for new server configurations
   - Prevents configuration tampering and unauthorized server modifications
   - Integrates with unified security layer for comprehensive protection

### Key Implementation Details

- All clients are initialized lazily to avoid connection issues at startup
- **Authentication modules use lazy imports** - FastMCP auth is only loaded when `--auth-mode google` is specified, ensuring the server works without auth configuration by default
- Extensive caching using `@lru_cache` to minimize API calls
- Comprehensive error handling and fallback mechanisms
- Security-focused with file size limits and path validation
- Returns vulnerability data with disclaimers about "AS IS" warranty
- **Unified Security Layer** (`unified_security.py`) - inspired by [Trail of Bits Context Protector](https://blog.trailofbits.com/2025/07/28/we-built-the-security-layer-mcp-always-needed/):
  - Combines all security mechanisms into a single, consistent API
  - Trust store validation blocks untrusted or modified server configurations
  - Pre-execution sanitization of parameters to prevent injection attacks
  - Post-execution response sanitization removes ANSI codes and prompt injections
  - Intelligent risk assessment using LLM when available, pattern matching as fallback
  - Unified risk scoring: BLOCKED, HIGH_RISK, REQUIRES_APPROVAL, LOW_RISK, SAFE
  - All passthrough variants use this unified layer for consistent security
- **LLM Risk Assessment** (`llm_risk_assessor.py`):
  - Supports both OpenAI and Anthropic APIs
  - Analyzes MCP requests/responses for security risks
  - Returns structured risk levels: BLOCKED, HIGH_RISK, REQUIRES_APPROVAL, LOW_RISK
  - Gracefully degrades to pattern matching when API unavailable

## Environment Variables

### Authentication
- `FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID`: Google OAuth 2.0 client ID (required for `--auth-mode google`)
- `FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET`: Google OAuth 2.0 client secret (required for `--auth-mode google`)
- `FASTMCP_SERVER_BASE_URL`: Base URL for OAuth callbacks (default: `http://localhost:3000`)

### Vulnerability Databases
- `NVD_API_KEY`: API key for NVD (increases rate limit from 5 to 50 requests/30s)
- `GITHUB_TOKEN`: GitHub token for Advisory Database (increases rate limit to 5000 requests/hour)

### AI-Powered Features
- `OPENAI_API_KEY`: OpenAI API key for LLM-based risk assessment in MCP passthrough
- `ANTHROPIC_API_KEY`: Anthropic API key for LLM-based risk assessment (alternative to OpenAI)

### Server Configuration
- `MCP_PORT`: Port for MCP server (default: 3000)
- `CACHE_TTL`: Cache time-to-live in seconds (default: 900)
- `REQUEST_TIMEOUT`: API request timeout in seconds
- `VULNICHECK_DEBUG`: Enable debug logging
- `VULNICHECK_LOG_LEVEL`: Log level for MCP interactions (default: INFO)
- `VULNICHECK_LOG_CONSOLE`: Enable console logging for MCP interactions (default: false)
- `VULNICHECK_HTTP_ONLY`: Enable HTTP-only mode with MCP client delegation ("true"/"false", default: auto-detect)
- `VULNICHECK_MCP_SERVER`: Default MCP server name for client file operations (default: "files")

## Logging

### MCP Interaction Logging
- All MCP passthrough interactions are logged to `~/.vulnicheck/logs/mcp_interactions.log`
- Logs include full request/response payloads in JSON format
- Hourly log rotation is enabled with timestamp-based filenames
- Rotated logs follow pattern: `mcp_interactions.log.YYYYMMDD_HHMMSS.log`

## Architectural Decisions

### Why HTTP-Only Architecture?

VulniCheck has transitioned to an HTTP-only architecture for several key reasons:

1. **Deployment Simplicity**: HTTP servers are easier to deploy, monitor, and scale compared to stdio-based processes
2. **Client Flexibility**: Supports both local and remote file operations through the FileProvider architecture
3. **Production Ready**: HTTP transport is more suitable for production environments with load balancing and monitoring
4. **MCP Client Compatibility**: Works seamlessly with MCP clients that support HTTP transport

### Why Custom MCP Client Instead of Official SDK?

While the official Anthropic MCP SDK provides persistent connections and high-level abstractions, we need a custom implementation to handle specific compatibility issues:

1. **HTTP/SSE Hybrid Servers**: Some MCP servers (like context7) return SSE-formatted responses to regular HTTP POST requests. The SDK's SSE client expects continuous streams and hangs, while the StreamableHTTP client can't parse SSE format.

2. **HTTP-Only Transport Interface**: Our implementation provides a single HTTP interface that automatically handles both standard JSON and SSE responses without requiring different client types.

3. **Passthrough Optimization**: Connection pooling and error handling optimized for the passthrough server use case.

See the docstring in `mcp_client.py` for more details.

### FileProvider Architecture

The FileProvider architecture enables flexible deployment scenarios:

1. **Local Deployment**: Direct filesystem access using `LocalFileProvider`
2. **HTTP-Only Deployment**: Client-delegated operations using `MCPClientFileProvider`
3. **Hybrid Approach**: Local files for GitHub repos, client delegation for user files
4. **Security**: Path validation, file size limits, permission checking, and audit logging

For HTTP-only deployment, MCP clients must implement specific callback tools:
- `read_file`: Read text file contents
- `read_file_binary`: Read binary files as base64-encoded data
- `list_directory`: List directory contents with pattern filtering
- `file_exists`: Check if file or directory exists
- `get_file_stats`: Get file metadata (size, type, modified time)

**Note**: Comprehensive documentation for FileProvider architecture has been consolidated into the main codebase with inline documentation and test examples.

## Testing Approach

- Unit tests focus on individual components (clients, scanner)
- Integration tests verify full workflows and API interactions
- Test data includes vulnerable packages for verification
- Uses pytest with async support via pytest-asyncio
- All tests run with `uv run` to ensure proper virtual environment usage
- Makefile includes targets for different test categories (unit, integration, MCP, security, clients)
- Type checking configured with mypy (strict for production code, relaxed for tests)
- **Test Status**: 369+ unit tests passing, 2 skipped (integration tests requiring API credentials)
- **Recent Refactoring**: Unified MCP passthrough architecture reduces codebase complexity while maintaining full backward compatibility

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

## Deployment and Distribution

### Docker Hub
- **Official Image**: `andrasfe/vulnicheck:latest` on Docker Hub
- **MCP Registry**: Published to https://registry.modelcontextprotocol.io
- **Required Label**: Dockerfile must include `LABEL io.modelcontextprotocol.server.name="io.github.andrasfe/vulnicheck"`
- **Registry Configuration**: `server.json` configures OCI registry (docker.io) with streamable-http transport

### CI/CD Pipeline
- **Single Python Version**: Tests run on Python 3.11 only (matches Docker image)
- **GitHub Actions**: Automated testing, linting, and Docker image building
- **Dependency Management**: Uses `uv sync --extra dev` for consistent environments
- **Coverage**: Generates XML coverage reports for codecov integration
- **Docker Publishing**: Automatically publishes to Docker Hub on main branch commits

## Recent Improvements (2025)

- **Optional Google OAuth 2.0 Authentication (January 2025)**:
  - Added `--auth-mode` command line flag to enable/disable authentication
  - Supports Google OAuth 2.0 using FastMCP's built-in GoogleProvider
  - Authentication is completely optional (default: none/disabled)
  - Environment variables: `FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID`, `FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET`, `FASTMCP_SERVER_BASE_URL`
  - Docker support with persistent token storage in `/home/vulnicheck/.vulnicheck/tokens`
  - Full backward compatibility - existing deployments work unchanged
  - Example: `vulnicheck --auth-mode google` or `docker run ... andrasfe/vulnicheck --auth-mode google`
- **Comprehensive Zip File Support (January 2025)**:
  - All scanning tools now accept base64-encoded zip files via `zip_content` parameter
  - Tools: `scan_dependencies`, `scan_for_secrets`, `scan_dockerfile`, `comprehensive_security_check`
  - Enables scanning of entire project directories in a single operation
  - Automatic extraction and processing of all relevant files within zip archives
  - Supports both file paths and zip content for maximum flexibility
- **Added two new vulnerability databases** for comprehensive coverage:
  - CIRCL Vulnerability-Lookup API (aggregates data from multiple sources)
  - Safety DB (Python-specific vulnerabilities not always in CVE databases)
- **Added GitHub repository scanning (`scan_github_repo` tool)**:
  - Comprehensive security analysis of entire repositories with one command
  - Supports multiple GitHub URL formats (HTTPS, SSH, branches, commits)
  - Analyzes dependencies, secrets, and Dockerfiles in parallel
  - Smart caching based on commit SHA (24-hour TTL)
  - Private repository support with GitHub authentication
  - Provides prioritized remediation recommendations (immediate, medium-term, long-term)
  - Integrates with existing scanners (DependencyScanner, SecretsScanner, DockerScanner)
- Fixed integration tests to properly skip when API credentials are unavailable
- Updated Makefile to include all test files and proper linting coverage
- Resolved all type annotation and mypy issues
- Added comprehensive MCP interaction logging with full payload capture
- Implemented hourly log rotation for MCP logs
- Fixed test order dependencies that were causing intermittent failures
- All tests now pass (351 unit tests, 2 skipped) with clean linting and type checking
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
  - **Now supports GitHub repository URLs**: Pass a GitHub URL to analyze remote repositories
  - Orchestrates all security tools (dependencies, Docker, secrets, MCP) based on user choices
  - Uses LLM to analyze findings, prioritize risks, and generate actionable recommendations
  - Produces executive summary with overall risk scoring
  - Seamlessly integrates GitHub scanner when repository URLs are provided
- **Conversation Storage and Retrieval**:
  - Added automatic conversation logging for all MCP passthrough operations
  - Conversations stored locally in `.vulnicheck/conversations` directory (created on first use)
  - Added `get_mcp_conversations` tool to retrieve and search past interactions
  - Tracks requests, responses, risk assessments, and errors for each conversation
  - Supports filtering by client, server, and search queries
  - Active conversations persist for 1 hour to maintain continuity
  - Includes conversation cleanup functionality for old conversations (30+ days)
- **Setup.py Support (August 2025)**:
  - Added full support for setup.py dependency file scanning
  - AST-based parsing extracts install_requires dependencies
  - Fallback regex parsing for malformed setup.py files
  - Directory scanning now includes setup.py file detection
  - Comprehensive test coverage for setup.py parsing functionality
- **Context Protector Integration (August 2025)**:
  - Integrated Trail of Bits Context Protector-inspired security layer
  - Added trust store management with `manage_trust_store` tool
  - Enhanced MCP passthrough with unified security validation
  - Response sanitization removes ANSI codes and detects prompt injection
  - Trust-on-first-use model prevents unauthorized server configuration changes
- **Docker Deployment (August 2025)**:
  - **Containerized Architecture**: VulniCheck runs exclusively in Docker containers
  - **HTTP Streaming**: Uses HTTP transport with Server-Sent Events for real-time communication
  - **Isolated Environment**: All file operations occur within the secure container
  - **Pre-configured Setup**: All dependencies and tools pre-installed in the image
  - **Security Features**: Container isolation, path validation, size limits
  - **Easy Deployment**: Single `docker run` command to start the service
  - **Production Ready**: Industry-standard containerization for production use
- **Unified MCP Passthrough Architecture (August 2025)**:
  - **Strategy Pattern Refactoring**: Consolidated three separate MCP passthrough implementations into unified architecture
  - **Code Reduction**: Achieved 40% reduction in codebase size (from 2,121 to ~900 lines)
  - **Backward Compatibility**: Maintained 100% API compatibility through wrapper classes
  - **Enhanced Security**: Integrated unified security layer with trust store validation
  - **Performance Optimization**: Improved connection pooling and error handling
  - **Documentation Cleanup**: Removed redundant documentation files, consolidated information into codebase
  - **Production Ready**: Clean, maintainable architecture following Python best practices
- **Recent Bug Fixes (January 2025)**:
  - Fixed comprehensive_security_check parameter validation for npx compatibility  
  - Fixed session_id validation in comprehensive security check
  - Fixed risk level display showing HIGH incorrectly when 0 findings exist
  - Fixed comprehensive security check for MCP server context
  - Added `install_vulnicheck_guide` tool for Claude Code users

## Memories

- **VulniCheck runs exclusively in Docker containers** for production deployment with HTTP-only architecture
- **Published to MCP Registry**: Available at https://registry.modelcontextprotocol.io as `io.github.andrasfe/vulnicheck`
- **Optional Google OAuth Authentication**: Use `--auth-mode google` flag to enable; disabled by default for backward compatibility
- **CI Configuration**: Single Python 3.11 environment matches Docker deployment; no need to test multiple versions
- **Zip File Support**: All major scanning tools accept base64-encoded zip content for directory scanning
- Always do testing and linting before commit (pre-commit hooks enforce this)
- Never add claude as co-author unless explicitly requested
- The uvx config file is stored at ~/.config/uv/uv.toml
- **Recent major refactoring completed**: Unified MCP passthrough architecture with 40% code reduction and full backward compatibility
- **Documentation consolidated**: Removed redundant .md files, information now integrated into codebase with inline documentation
- **Production ready**: Clean, optimized codebase following Python best practices
