# VulniCheck MCP Server

A Python-based MCP (Model Context Protocol) server that provides real-time security advice about Python modules by querying multiple authoritative vulnerability databases including OSV.dev, NVD (National Vulnerability Database), GitHub Advisory Database, CIRCL Vulnerability-Lookup, and Safety DB.

## DISCLAIMER

The information provided by this software and accompanying materials (including but not limited to vulnerability data obtained from the NVD, CWE, OSV, and other public sources) is provided "AS IS" and "AS AVAILABLE" without warranty of any kind, either express or implied. The authors, contributors, and distributors of this software expressly disclaim all warranties, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, and non-infringement.

The authors and distributors do not guarantee the accuracy, completeness, timeliness, or reliability of the information provided. Users are solely responsible for verifying and validating the information before relying on it. Under no circumstances shall the authors, contributors, or distributors be liable for any direct, indirect, incidental, consequential, or special damages, including but not limited to loss of data, loss of profits, or business interruption, arising from the use of this software or the information contained herein, even if advised of the possibility of such damages.

By using this software and its associated data, you acknowledge and agree to assume all risks associated with its use.

This software incorporates or references data from publicly available sources, including the National Vulnerability Database (NVD), Common Weakness Enumeration (CWE), and Open Source Vulnerabilities (OSV), which are provided under their respective public licenses and disclaimers.

## Important Setup Note

⚠️ **IMPORTANT**: Add `.vulnicheck` to your `.gitignore` file! This directory contains:
- Conversation logs from MCP passthrough operations
- Local cache and temporary files
- Security audit trails

```bash
echo ".vulnicheck/" >> .gitignore
```

## Quick Security Check

The easiest way to use VulniCheck is with the **comprehensive_security_check** tool, which provides an interactive, AI-powered security assessment of your entire project or any GitHub repository:

```
# For current directory
"Run a comprehensive security check on my project"

# For a specific local path
"Run a comprehensive security check on /path/to/project"

# For a GitHub repository
"Run a comprehensive security check on https://github.com/owner/repo"
```

This tool will:
- Automatically discover your project structure (dependencies, Dockerfiles, MCP configs)
- Support both local directories and GitHub repositories (public and private with auth)
- Ask you what to scan (you can choose specific areas or scan everything)
- Run all relevant security tools based on your choices
- Provide an AI-analyzed report with prioritized recommendations

**Note:** Requires OPENAI_API_KEY or ANTHROPIC_API_KEY to be configured.

## Features

- **Real-time vulnerability checking** for Python packages using multiple databases:
  - OSV.dev (includes PyPI Advisory Database)
  - NVD (National Vulnerability Database)
  - GitHub Advisory Database
  - CIRCL Vulnerability-Lookup (aggregates multiple sources)
  - Safety DB (Python-specific vulnerabilities)
- **Comprehensive coverage** by querying 5+ authoritative vulnerability databases
- **GitHub repository scanning** - comprehensive security analysis of entire repositories with one command
- **Dependency scanning** for `requirements.txt`, `pyproject.toml`, and lock files
- **Python import scanning** - automatically discovers dependencies from Python source files when no requirements file exists
- **Secrets detection** - scans files and directories for exposed API keys, passwords, and credentials using detect-secrets
- **Docker security scanning** - analyzes Dockerfiles for vulnerable Python dependencies
- **MCP security validation** - self-assessment capability for LLMs to validate their security posture
- **MCP security passthrough** - validates and monitors cross-server MCP operations with built-in security constraints
- **Conversation storage and retrieval** - automatically logs all MCP passthrough interactions for audit and debugging
- **Pre-operation safety assessment** - evaluates risks before performing file operations, commands, or API calls
- **Detailed CVE information** including CVSS scores and severity ratings
- **CWE (Common Weakness Enumeration) mapping** for better understanding of vulnerability types
- **FastMCP integration** for simplified Model Context Protocol implementation
- **Actionable security recommendations** with upgrade suggestions
- **Comprehensive logging** with hourly rotation for MCP interactions
- **Smart caching** - commit-level caching for GitHub repository scans to avoid redundant analysis

## Quick Start

**Requirements:** Python 3.10 or higher

### Option 1: Direct from GitHub with uvx (Recommended)

If you have `uv` installed (`pip install uv`), you can run VulniCheck directly without cloning:

**Claude Desktop:**
```json
{
  "mcpServers": {
    "vulnicheck": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/andrasfe/vulnicheck.git",
        "vulnicheck"
      ],
      "env": {
        "NVD_API_KEY": "your-nvd-api-key",
        "GITHUB_TOKEN": "your-github-token",
        "OPENAI_API_KEY": "your-openai-key",
        "ANTHROPIC_API_KEY": "your-anthropic-key"
      }
    }
  }
}
```

**Claude Code:**
```bash
# Basic setup
claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck

# With environment variables for enhanced features
claude mcp add vulnicheck \
  -e NVD_API_KEY=your-nvd-key \
  -e GITHUB_TOKEN=your-github-token \
  -e OPENAI_API_KEY=your-openai-key \
  -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck
```

**Note:** Environment variables are optional but recommended:
- `NVD_API_KEY`: Increases rate limit from 5 to 50 requests/30s ([get free key](https://nvd.nist.gov/developers/request-an-api-key))
- `GITHUB_TOKEN`: Increases rate limit to 5000 requests/hour ([create token](https://github.com/settings/tokens))
- `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`: Enables AI-powered risk assessment for MCP passthrough

### Option 2: Traditional Installation

1. **Automated Installation and Setup:**
```bash
git clone https://github.com/andrasfe/vulnicheck.git
cd vulnicheck
./run-local.sh
```

This will automatically:
- Create a virtual environment
- Install all dependencies with uv (if available) or pip
- Configure Claude Desktop
- Test the installation

After setup, restart Claude Code to use VulniCheck.

2. **Manual Configuration (if needed):**

**Claude Desktop:**

Add to your Claude MCP settings at `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `~/.config/claude/claude_desktop_config.json` (Linux):
```json
{
  "mcpServers": {
    "vulnicheck": {
      "command": "/path/to/vulnicheck/.venv/bin/python",
      "args": ["-m", "vulnicheck.server"]
    }
  }
}
```

**Claude Code:**

Use the CLI to add the server:
```bash
claude mcp add vulnicheck -e OPENAI_API_KEY="..." -- /path/to/vulnicheck/.venv/bin/python -m vulnicheck.server
```

Or with environment variables:
```bash
claude mcp add vulnicheck -e NVD_API_KEY=your_key -e GITHUB_TOKEN=your_token -- /path/to/vulnicheck/.venv/bin/python -m vulnicheck.server
```

**VS Code / Cursor:**

With uvx:
```json
{
  "mcpServers": {
    "vulnicheck": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/andrasfe/vulnicheck.git",
        "vulnicheck"
      ],
      "env": {
        "NVD_API_KEY": "your-nvd-api-key",
        "GITHUB_TOKEN": "your-github-token"
      }
    }
  }
}
```

Or traditional setup:
```json
{
  "mcpServers": {
    "vulnicheck": {
      "command": "/path/to/vulnicheck/.venv/bin/python",
      "args": ["-m", "vulnicheck.server"]
    }
  }
}
```

## Alternative Installation Options

### Manual Installation with Make
```bash
make install-local
```

### Manual Installation
```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install vulnicheck
pip install -e .

# Run the server
python -m vulnicheck.server
```

### System-wide Installation
```bash
# Install globally (not recommended)
pip install .

# Run from anywhere
vulnicheck
```

## Usage

Once the service is running and your IDE is configured, you can interact with VulniCheck using natural language:

- "Check if numpy has any vulnerabilities"
- "Scan my requirements.txt file for security issues"
- "Get details about CVE-2024-3772"
- "Check all installed packages for vulnerabilities"
- "Scan this directory for exposed secrets"
- "Check if my code contains any API keys or passwords"
- "Validate my MCP security configuration"
- "Scan this Dockerfile for vulnerable Python packages"
- "Scan the GitHub repository https://github.com/numpy/numpy for vulnerabilities"
- "Do a comprehensive security check on https://github.com/owner/repo"

### Managing the Service

```bash
# Update the installation
git pull
./run-local.sh

# Run the server manually
.venv/bin/python -m vulnicheck.server
# (Press Ctrl+C to stop)

# Run with API keys for enhanced rate limits
NVD_API_KEY=your-key GITHUB_TOKEN=your-token .venv/bin/python -m vulnicheck.server
```

## Available Tools

### 1. check_package_vulnerabilities

Check a specific Python package for known vulnerabilities.

**Parameters:**
- `package_name` (required): Name of the Python package
- `version` (optional): Specific version to check
- `include_details` (optional): Include detailed CVE information from NVD

**Example:**
```json
{
  "tool": "check_package_vulnerabilities",
  "package_name": "numpy",
  "version": "1.19.0",
  "include_details": true
}
```

### 2. scan_dependencies

Scan a requirements file or directory for vulnerabilities in all dependencies.

**Parameters:**
- `file_path` (required): Path to requirements.txt, pyproject.toml, or a directory
- `include_details` (optional): Include detailed CVE information

**Behavior:**
- If given a file: Scans the dependency file directly
- If given a directory:
  - First checks for requirements.txt or pyproject.toml
  - If none found, scans all Python files for imports and checks latest versions

**Examples:**
```json
{
  "tool": "scan_dependencies",
  "file_path": "/path/to/requirements.txt",
  "include_details": false
}
```

```json
{
  "tool": "scan_dependencies",
  "file_path": "/path/to/project/directory",
  "include_details": true
}
```

### 3. scan_installed_packages

Scan Python packages for vulnerabilities - either from a provided list or the current environment.

**Parameters:**
- `packages` (optional): List of packages with name and version to scan

**Example:**
```json
{
  "tool": "scan_installed_packages",
  "packages": [
    {"name": "django", "version": "3.2.0"},
    {"name": "flask", "version": "2.0.1"}
  ]
}
```

**Note:** If `packages` is not provided, the tool will scan the MCP server's own environment, which is likely NOT what you want. Always provide the packages list for accurate results.

### 4. get_cve_details

Get detailed information about a specific CVE or GHSA advisory.

**Parameters:**
- `cve_id` (required): CVE identifier (e.g., CVE-2021-12345) or GHSA identifier (e.g., GHSA-1234-5678-9abc)

**Example:**
```json
{
  "tool": "get_cve_details",
  "cve_id": "CVE-2021-41495"
}
```

**Example with GHSA:**
```json
{
  "tool": "get_cve_details",
  "cve_id": "GHSA-fpfv-jqm9-f5jm"
}
```

### 5. scan_for_secrets

Scan files or directories for exposed secrets and credentials using detect-secrets.

**Parameters:**
- `path` (required): File or directory path to scan
- `exclude_patterns` (optional): List of glob patterns to exclude from scanning

**Example:**
```json
{
  "tool": "scan_for_secrets",
  "path": "/path/to/project",
  "exclude_patterns": ["*.log", "build/*"]
}
```

### 6. validate_mcp_security

Validate MCP server security configuration for self-assessment. Allows LLMs to check their own security posture using mcp-scan integration.

**Parameters:**
- `agent_name` (required): The coding agent/IDE being used (e.g., 'claude', 'cursor', 'vscode', 'windsurf', 'continue', or 'custom')
- `config_path` (optional): Custom path to MCP configuration file (only needed if agent_name is 'custom' or config is in non-standard location)
- `mode` (optional): 'scan' for full analysis or 'inspect' for quick check (default: 'scan')
- `local_only` (optional): Use local validation only, no external API calls (default: true)

**Example:**
```json
{
  "tool": "validate_mcp_security",
  "agent_name": "claude",
  "mode": "scan",
  "local_only": true
}
```

**Note:** When running VulniCheck locally, this tool can access your local configuration files (e.g., `~/.claude.json`, `~/.cursor/config.json`). The tool automatically searches standard configuration locations for each agent.

This tool helps LLMs self-validate for:
- Prompt injection in tool descriptions
- Tool poisoning attempts
- Cross-origin escalation risks
- Suspicious behavior patterns

The validation report includes severity levels (CRITICAL, HIGH, MEDIUM, LOW) and provides guidance on whether to proceed with sensitive operations.

**Integration with mcp-scan (Experimental):**

VulniCheck integrates with [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan), an experimental security scanner for Model Context Protocol (MCP) configurations. This feature allows LLMs to perform self-assessment of their security posture by analyzing their own MCP server configurations for potential vulnerabilities.

⚠️ **Note:** The MCP security validation feature is experimental and under active development. It provides an additional layer of security awareness but should not be relied upon as the sole security measure.

Key capabilities:
- Detects potential prompt injection vulnerabilities in tool descriptions
- Identifies suspicious command patterns and tool poisoning attempts
- Validates permission models and cross-origin risks
- Analyzes behavioral patterns that might indicate security issues

This self-validation capability enables LLMs to make informed decisions about whether to proceed with sensitive operations based on their current security configuration.

### 7. mcp_passthrough_tool

Execute MCP tool calls through a security passthrough layer that validates and monitors cross-server operations. This tool enables secure communication between different MCP servers while enforcing security constraints.

**Parameters:**
- `server_name` (required): Name of the target MCP server
- `tool_name` (required): Name of the tool to call on the MCP server
- `parameters` (optional): Parameters to pass to the tool (default: empty dict)
- `security_context` (optional): Additional security constraints for this call
- `use_approval` (optional): Enable risk-based approval mechanism (default: false)

**Example:**
```json
{
  "tool": "mcp_passthrough_tool",
  "server_name": "zen",
  "tool_name": "listmodels",
  "parameters": {}
}
```

**Security Features:**
- **AI-Powered Risk Assessment**: When LLM API keys are configured (OpenAI or Anthropic), uses AI to assess both requests and responses for security risks
- **Risk-based assessment**: Categorizes operations into BLOCKED, HIGH_RISK, REQUIRES_APPROVAL, and LOW_RISK
- **Pattern matching**: Detects dangerous commands, file paths, and parameters
- **Approval workflow**: HIGH_RISK and REQUIRES_APPROVAL operations can be reviewed before execution
- **Response validation**: Checks responses for exposed secrets, sensitive information, or security risks
- **Server blocklist**: Automatically blocks system-level servers (system, admin, root, sudo)
- **Comprehensive logging**: All interactions logged with full request/response payloads

**LLM Risk Assessment (When API Keys Configured):**
- **Pre-execution**: Analyzes requests for attempts to access sensitive files, execute dangerous commands, or perform privilege escalation
- **Post-execution**: Examines responses for exposed credentials, API keys, or sensitive system information
- **Intelligent blocking**: LLM can identify context-specific risks that pattern matching might miss
- **Approval integration**: High-risk responses trigger the approval workflow just like high-risk requests

**Risk Categories:**
- **BLOCKED**: Operations that are always denied (rm -rf /, system file access, etc.)
- **HIGH_RISK**: Dangerous operations requiring explicit approval (sudo commands, database drops)
- **REQUIRES_APPROVAL**: Potentially legitimate but risky operations (recursive deletions, package installs)
- **LOW_RISK**: Safe operations that are auto-approved (file reads, git operations)

**Approval Mechanism:**
When `use_approval` is true and an operation requires approval:
1. The tool returns an approval request with detailed risk assessment
2. Use `approve_mcp_operation` or `deny_mcp_operation` tools to respond
3. Approved operations are executed with the original parameters
4. Denied operations return safely without execution

**Response Format:**
```json
{
  "status": "success|blocked|error|approval_required",
  "result": {},  // Only for successful calls
  "reason": "...",  // For blocked/denied calls
  "error": "...",  // For errors
  "request_id": "...",  // For approval requests
  "display_message": "...",  // For approval requests
  "security_prompt": "..."  // Always included
}
```

**Logging:**
All MCP passthrough interactions are logged to `~/.vulnicheck/logs/mcp_interactions.log` with:
- Full request and response payloads in JSON format
- Hourly log rotation with timestamp-based filenames
- Pattern: `mcp_interactions.log.YYYYMMDD_HHMMSS.log`

### 8. approve_mcp_operation

Approve a pending MCP operation that requires security approval.

**Parameters:**
- `request_id` (required): The request ID from the approval request
- `reason` (required): Justification for approving this operation

**Example:**
```json
{
  "tool": "approve_mcp_operation",
  "request_id": "abc123",
  "reason": "Operation aligns with user intent to analyze project structure"
}
```

### 9. deny_mcp_operation

Deny a pending MCP operation that requires security approval.

**Parameters:**
- `request_id` (required): The request ID from the approval request
- `reason` (required): Explanation for denying this operation
- `alternative` (optional): Suggested safer alternative approach

**Example:**
```json
{
  "tool": "deny_mcp_operation",
  "request_id": "abc123",
  "reason": "Operation too risky for current context",
  "alternative": "Use read-only operations instead"
}
```

### 10. list_mcp_servers

List available MCP servers and their tools.

**Parameters:**
- `agent_name` (optional): The coding assistant/IDE (claude, cursor, vscode, etc.)

**Example:**
```json
{
  "tool": "list_mcp_servers"
}
```

### 11. assess_operation_safety

Pre-operation risk assessment tool for evaluating the safety of file operations, command execution, and API calls before performing them.

**Parameters:**
- `operation_type` (required): Type of operation (e.g., 'file_write', 'file_delete', 'command_execution', 'api_call')
- `operation_details` (required): Details about the operation as a dictionary
  - For file operations: include 'path' and optionally 'content'
  - For commands: include 'command' and 'args'
  - For API calls: include 'endpoint' and 'method'
- `context` (optional): Additional context about why this operation is being performed

**Example:**
```json
{
  "tool": "assess_operation_safety",
  "operation_type": "file_read",
  "operation_details": {"path": "/etc/passwd"},
  "context": "User wants to check system users"
}
```

**Response includes:**
- Risk assessment (using LLM when API keys are available, structured patterns otherwise)
- Identified risks with specific concerns
- Recommendations for safer alternatives
- Whether human approval is required
- When no LLM is available, provides guidance for manual risk evaluation

**Risk Assessment Features:**
- **LLM-based assessment** when OPENAI_API_KEY or ANTHROPIC_API_KEY is configured
- **Structured risk patterns** as fallback when no LLM is available
- **Context-aware evaluation** considering the operation's purpose
- **Specific risk identification** for different operation types
- **Actionable recommendations** for risk mitigation

This tool helps LLMs and developers make informed decisions about potentially dangerous operations before executing them, promoting a security-first approach to system interactions.

### 12. scan_dockerfile

Analyze Dockerfiles for Python dependencies and check for vulnerabilities.

**Parameters:**
- `dockerfile_path` (optional): Absolute path to the Dockerfile to scan
- `dockerfile_content` (optional): Content of the Dockerfile as a string

**Note:** Either `dockerfile_path` or `dockerfile_content` must be provided.

**Example:**
```json
{
  "tool": "scan_dockerfile",
  "dockerfile_path": "/path/to/Dockerfile"
}
```

**Capabilities:**
- Extracts Python packages from various installation methods:
  - `pip install` commands (with version specifiers)
  - `poetry add` commands
  - `pipenv install` commands
  - `conda install` commands
- Identifies referenced dependency files:
  - requirements.txt
  - pyproject.toml
  - Pipfile/Pipfile.lock
  - poetry.lock
  - environment.yml
- Checks each extracted package for known vulnerabilities
- Provides severity breakdown and detailed vulnerability information
- Groups vulnerabilities by package for easy review

**Example with dockerfile_content:**
```json
{
  "tool": "scan_dockerfile",
  "dockerfile_content": "FROM python:3.9\nRUN pip install requests==2.28.0 flask>=2.0.0\nCOPY requirements.txt .\nRUN pip install -r requirements.txt"
}
```

**Response includes:**
- Total packages found and vulnerable packages count
- Severity breakdown (CRITICAL, HIGH, MODERATE, LOW)
- List of all dependencies with vulnerability status
- Referenced dependency files found in the Dockerfile
- Detailed vulnerability information for each affected package

### 13. get_mcp_conversations

Retrieve stored conversations between clients (e.g., Claude) and MCP servers that VulniCheck has intermediated.

**Parameters:**
- `client` (optional): Filter by client name (e.g., 'claude', 'cursor')
- `server` (optional): Filter by MCP server name (e.g., 'github', 'zen')
- `query` (optional): Search query to find conversations containing specific tools or parameters
- `limit` (optional): Maximum number of conversations to return (default: 20, max: 1000)

**Example:**
```json
{
  "tool": "get_mcp_conversations",
  "server": "github",
  "limit": 10
}
```

**Features:**
- **Automatic conversation tracking** - All MCP passthrough operations are automatically logged
- **Conversation storage** - Stored locally in `.vulnicheck/conversations` directory
- **Search capability** - Search across tool names, parameters, and results
- **Risk assessment tracking** - Security risk assessments are preserved with conversations
- **Active conversation reuse** - Conversations remain active for 1 hour for continuity

**Response includes:**
- Conversation metadata (client, server, timestamps)
- Recent messages with request/response pairs
- Tool names and parameters used
- Security status and risk assessments
- Error messages if operations failed

**Use cases:**
- Review past MCP interactions
- Audit security decisions made during passthrough
- Debug failed operations
- Track usage patterns across different MCP servers
- Analyze security risks encountered

### 14. scan_github_repo

Scan a GitHub repository for security vulnerabilities by analyzing dependencies, secrets, and Dockerfiles.

**Parameters:**
- `repo_url` (required): GitHub repository URL (e.g., https://github.com/owner/repo)
- `scan_types` (optional): Types of scans to perform. Options: 'dependencies', 'secrets', 'dockerfile'. Defaults to all.
- `depth` (optional): Scan depth: 'quick' (fast, minimal checks), 'standard' (balanced), 'deep' (comprehensive). Default: 'standard'
- `auth_token` (optional): GitHub authentication token for private repos. Uses GITHUB_TOKEN env var if not provided.

**Example:**
```json
{
  "tool": "scan_github_repo",
  "repo_url": "https://github.com/numpy/numpy",
  "scan_types": ["dependencies", "secrets"],
  "depth": "standard"
}
```

**Supported URL formats:**
- https://github.com/owner/repo
- https://github.com/owner/repo.git
- https://github.com/owner/repo/tree/branch
- https://github.com/owner/repo/commit/hash
- git@github.com:owner/repo.git

**Features:**
- **Comprehensive scanning** - Analyzes dependencies, secrets, and Dockerfiles in one operation
- **Smart caching** - Caches results by commit SHA for 24 hours to avoid redundant scans
- **Private repository support** - Works with private repos using GitHub tokens
- **Parallel scanning** - Runs all scan types concurrently for better performance
- **Branch/commit support** - Can scan specific branches or commits
- **Remediation recommendations** - Provides immediate, medium-term, and long-term action items

**Response includes:**
- Repository information (owner, name, branch, commit)
- Scan configuration and date
- Findings organized by scan type:
  - **Dependencies**: Vulnerable packages with CVE details and severity
  - **Secrets**: Exposed credentials categorized by severity
  - **Dockerfiles**: Vulnerable packages in Docker images
- Summary statistics (total issues, severity breakdown)
- Prioritized remediation recommendations

**Example response summary:**
```json
{
  "status": "success",
  "repository": "https://github.com/owner/repo",
  "summary": {
    "total_issues": 15,
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 0,
    "scan_types_completed": ["dependencies", "secrets", "dockerfile"]
  },
  "remediation": {
    "immediate": [
      "Update vulnerable dependencies to patched versions",
      "Rotate all exposed secrets and credentials immediately"
    ],
    "medium_term": [
      "Implement automated dependency scanning in CI/CD pipeline"
    ],
    "long_term": [
      "Set up automated dependency updates with security patches"
    ]
  }
}
```

**Use cases:**
- Pre-acquisition security audit of repositories
- Regular security assessments of your own projects
- Evaluating third-party dependencies before adoption
- Compliance and security reporting
- CI/CD integration for automated security checks

## Example Output

### Package Vulnerability Check

```
# Python Package Security Report: numpy
Version: 1.19.0
Found 3 vulnerabilities

## Summary
- CRITICAL: 0
- HIGH: 2
- MEDIUM: 1

## Vulnerabilities

### GHSA-fpfv-jqm9-f5jm
**Summary**: NULL Pointer Dereference in NumPy
**Severity**: HIGH
**CVE IDs**: CVE-2021-41495
**CWE**: CWE-476

#### CVE-2021-41495 Details:
- CVSS Score: 7.5
- Description: NumPy before 1.22.0 contains a null pointer dereference...
- CWE: CWE-476 (NULL Pointer Dereference)

**References**:
- https://github.com/numpy/numpy/security/advisories/GHSA-fpfv-jqm9-f5jm

**Recommendation**: Update to a patched version
```

## Configuration

Create a `.env` file in the project root for optional configuration:

```env
# NVD API Key (recommended for better rate limits)
NVD_API_KEY=your-api-key-here

# GitHub token for better rate limits (optional)
GITHUB_TOKEN=your-github-token

# LLM API Keys for AI-powered security assessment (optional)
# If provided, MCP passthrough will use AI to assess security risks
# Supports either OpenAI or Anthropic (provide one or the other)
OPENAI_API_KEY=your-openai-api-key-here
ANTHROPIC_API_KEY=your-anthropic-api-key-here

# Cache TTL in seconds (default: 900)
CACHE_TTL=1800

# Logging configuration
VULNICHECK_LOG_LEVEL=INFO
VULNICHECK_LOG_CONSOLE=false
```

### API Rate Limits

**OSV.dev**
- No authentication required
- Free and open API
- Includes PyPI Advisory Database

**NVD (National Vulnerability Database)**
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds (10x more!)
- Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

**GitHub Advisory Database**
- Without token: 60 requests per hour
- With token: 5,000 requests per hour
- Get a free GitHub token at: https://github.com/settings/tokens

**CIRCL Vulnerability-Lookup**
- No authentication required
- Free public API
- Aggregates data from multiple sources

**Safety DB**
- No authentication required
- Open source database on GitHub
- Updated monthly

**Note**: The server automatically handles rate limiting to prevent hitting API limits.

## Development

### Local Development Setup

```bash
# Quick setup with all dependencies
make install-local

# Or manual setup for development
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Available Make Commands

```bash
make help           # Show all available commands
make install        # Install package in development mode
make install-dev    # Install with development dependencies
make install-local  # Set up local environment with Claude integration
make test          # Run all tests
make test-unit     # Run unit tests only
make test-integration # Run integration tests (requires API credentials)
make test-coverage # Run tests with coverage report
make lint          # Run linting checks (ruff + mypy)
make format        # Format code with ruff
make clean         # Clean build artifacts
```

### Running Tests

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests (requires GITHUB_TOKEN)
make test-integration

# Run with coverage
make test-coverage

# Run specific test categories
make test-mcp      # MCP-related tests
make test-security # Security-related tests
make test-clients  # Client tests
```

**Note:** Integration tests require API credentials (GITHUB_TOKEN) to avoid rate limiting. Tests will be skipped if credentials are not available.

### Code Quality

```bash
# Run all checks (lint + type checking)
make lint

# Auto-fix issues
make lint-fix

# Format code
make format
```

### Pre-commit Hooks

The project uses pre-commit hooks to ensure code quality:

```bash
# Install pre-commit hooks (one-time setup)
uv run pre-commit install

# Run pre-commit manually on all files
uv run pre-commit run --all-files
```

**Pre-commit checks include:**
- Trailing whitespace removal
- End-of-file fixing
- YAML/JSON/TOML validation
- `make lint` - Runs ruff and mypy checks
- `make test-unit` - Runs unit tests
- Private key detection

## Security Considerations

- The server performs read-only operations and doesn't modify any files
- Built with FastMCP for secure and efficient MCP protocol handling
- No sensitive data is stored or transmitted
- All external API calls use HTTPS
- MCP passthrough tool validates all cross-server operations:
  - Risk-based security assessment for all operations
  - Blocks dangerous patterns and commands
  - Approval workflow for high-risk operations
  - Comprehensive logging of all interactions
- All MCP interactions are logged with full payloads for audit purposes

## Troubleshooting

### API Rate Limiting

If you encounter rate limiting errors:
- Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key
- Get a GitHub token: https://github.com/settings/tokens
- Add them to your environment or `.env` file:
  ```bash
  export NVD_API_KEY=your-key-here
  export GITHUB_TOKEN=your-token-here
  ```

### Common Issues

**MCP server not found**
- Ensure you've run the server with: `python -m vulnicheck.server`
- Check that you've added it to Claude Code: `claude mcp add vulnicheck -- /path/to/vulnicheck/.venv/bin/python -m vulnicheck.server`

**Permission errors**
- The MCP validator tool needs read access to configuration directories
- On macOS, you may need to grant terminal/IDE access to folders like `~/.claude/`

**Integration test failures**
- Integration tests require GITHUB_TOKEN to avoid rate limiting
- Set the environment variable or tests will be skipped

## Recent Improvements (2025)

- **Added two new vulnerability databases** for comprehensive coverage:
  - CIRCL Vulnerability-Lookup API (aggregates data from multiple sources)
  - Safety DB (Python-specific vulnerabilities not always in CVE databases)
- **Added GitHub repository scanning** (`scan_github_repo` tool):
  - Comprehensive security analysis of entire repositories with one command
  - Supports public and private repositories with authentication
  - Analyzes dependencies, secrets, and Dockerfiles in parallel
  - Smart caching based on commit SHA for efficient re-scans
  - Provides prioritized remediation recommendations
- **Enhanced comprehensive_security_check with GitHub URL support**:
  - Now accepts GitHub repository URLs in addition to local paths
  - Seamlessly integrates GitHub repository scanning into the interactive workflow
  - Automatically uses the GitHub scanner when a repository URL is provided
  - Maintains the same interactive Q&A experience for both local and remote repos
- Fixed integration tests to properly skip when API credentials are unavailable
- Updated Makefile to include all test files and proper linting coverage
- Resolved all type annotation and mypy issues
- Added comprehensive MCP interaction logging with full payload capture
- Implemented hourly log rotation for MCP logs
- Fixed test order dependencies that were causing intermittent failures
- All tests now pass (294 unit tests, 1 skipped) with clean linting and type checking
- Added pre-commit hooks that run `make lint` and `make test-unit` before commits
- Added Docker vulnerability scanner tool for analyzing Dockerfiles
- Enhanced MCP passthrough with risk-based approval workflows
- Added AI-powered risk assessment using LLM (OpenAI/Anthropic) for MCP passthrough:
  - Pre-execution request validation to block dangerous operations
  - Post-execution response analysis to detect exposed secrets
  - Intelligent context-aware security assessment beyond pattern matching
  - Integration with existing approval workflow for high-risk operations

## License

MIT License - see [LICENSE](LICENSE) file for details

## Author

Created and maintained by [andrasfe](https://github.com/andrasfe)
