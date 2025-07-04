# VulniCheck MCP Server

A Python-based MCP (Model Context Protocol) server that provides real-time security advice about Python modules by querying multiple authoritative vulnerability databases including OSV.dev, NVD (National Vulnerability Database), and GitHub Advisory Database. 

## DISCLAIMER

The information provided by this software and accompanying materials (including but not limited to vulnerability data obtained from the NVD, CWE, OSV, and other public sources) is provided "AS IS" and "AS AVAILABLE" without warranty of any kind, either express or implied. The authors, contributors, and distributors of this software expressly disclaim all warranties, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, and non-infringement.

The authors and distributors do not guarantee the accuracy, completeness, timeliness, or reliability of the information provided. Users are solely responsible for verifying and validating the information before relying on it. Under no circumstances shall the authors, contributors, or distributors be liable for any direct, indirect, incidental, consequential, or special damages, including but not limited to loss of data, loss of profits, or business interruption, arising from the use of this software or the information contained herein, even if advised of the possibility of such damages.

By using this software and its associated data, you acknowledge and agree to assume all risks associated with its use.

This software incorporates or references data from publicly available sources, including the National Vulnerability Database (NVD), Common Weakness Enumeration (CWE), and Open Source Vulnerabilities (OSV), which are provided under their respective public licenses and disclaimers.

## Features

- **Real-time vulnerability checking** for Python packages using OSV.dev, NVD, and GitHub Advisory Database APIs
- **Comprehensive coverage** by querying multiple authoritative vulnerability databases
- **Dependency scanning** for `requirements.txt` and `pyproject.toml` files
- **Python import scanning** - automatically discovers dependencies from Python source files when no requirements file exists
- **Secrets detection** - scans files and directories for exposed API keys, passwords, and credentials using detect-secrets
- **Detailed CVE information** including CVSS scores and severity ratings
- **CWE (Common Weakness Enumeration) mapping** for better understanding of vulnerability types
- **FastMCP integration** for simplified Model Context Protocol implementation
- **Actionable security recommendations** with upgrade suggestions

## Quick Start

**Requirements:** Python 3.10 or higher

1. **Install:**
```bash
git clone https://github.com/andrasfe/vulnicheck.git
cd vulnicheck
./run-local.sh
```

This script will:
- Create a virtual environment
- Install all dependencies
- Show you how to configure Claude

2. **Configure your IDE:**

**Claude Desktop:**

Add to your Claude MCP settings at `~/.claude.json` (or through the UI):
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
claude mcp add vulnicheck -- /path/to/vulnicheck/.venv/bin/python -m vulnicheck.server
```

Or with environment variables:
```bash
claude mcp add vulnicheck -e NVD_API_KEY=your_key -e GITHUB_TOKEN=your_token -- /path/to/vulnicheck/.venv/bin/python -m vulnicheck.server
```

**VS Code / Cursor:**
Add to your MCP settings:
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

## Installation Options

### Option 1: Quick Start with Script (Recommended)
Use the `./run-local.sh` script as shown above. It handles everything automatically.

### Option 2: Manual Installation
```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install vulnicheck
pip install -e .

# Run the server
python -m vulnicheck.server
```

### Option 3: System-wide Installation
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

### Managing the Service

```bash
# Update the installation
git pull
./run-local.sh

# Test the server manually
python -m vulnicheck.server
# (Press Ctrl+C to stop)

# Run with API keys for enhanced rate limits
NVD_API_KEY=your-key GITHUB_TOKEN=your-token python -m vulnicheck.server
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

### 3. get_cve_details

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

### 4. scan_for_secrets

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

### 5. validate_mcp_security

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

# Cache TTL in seconds (default: 900)
CACHE_TTL=1800
```

### API Rate Limits

**OSV.dev**
- No authentication required
- Free and open API

**NVD (National Vulnerability Database)**
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds (10x more!)
- Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

**GitHub Advisory Database**
- Without token: 60 requests per hour
- With token: 5,000 requests per hour
- Get a free GitHub token at: https://github.com/settings/tokens

**Note**: The server automatically handles rate limiting to prevent hitting API limits.

## Development

### Local Development Setup

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run unit tests
make test-unit

# Run all tests
make test

# Run with coverage
make test-coverage
```

### Code Quality

```bash
# Run all checks (lint + type checking)
make lint

# Auto-fix issues
make lint-fix

# Format code
make format
```

## Security Considerations

- The server performs read-only operations and doesn't modify any files
- Built with FastMCP for secure and efficient MCP protocol handling
- No sensitive data is stored or transmitted
- All external API calls use HTTPS

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

## License

MIT License - see [LICENSE](LICENSE) file for details

## Author

Created and maintained by [andrasfe](https://github.com/andrasfe)