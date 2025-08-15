# VulniCheck - AI-Powered Security Scanner

VulniCheck provides comprehensive security analysis for Python projects and GitHub repositories using AI-powered vulnerability detection. It runs as an HTTP-only MCP server with support for both local file access and client-delegated file operations via the FileProvider architecture.

## Quick Start

### Installation for Claude Code

[!CAUTION]
**MCP servers can execute code on your system. Only install MCP servers from trusted sources after reviewing their code and understanding the permissions they require.**

The simplest way to get started is to ask claude:
Hey Claude, follow instructions at https://raw.githubusercontent.com/andrasfe/vulnicheck/refs/heads/main/CLAUDE_INSTALL.md to install this MCP server.


## Usage

Once installed, simply ask Claude Code:

```
"Run a comprehensive security check on my project"

"Run a comprehensive security check on https://github.com/owner/repo"

"Check this directory for security vulnerabilities"
```

VulniCheck will:
- ✅ Scan dependencies for known vulnerabilities (requirements.txt, pyproject.toml, setup.py)
- ✅ Detect exposed secrets and credentials
- ✅ Analyze Dockerfiles for security issues
- ✅ Validate MCP configurations
- ✅ Generate AI-powered risk assessments
- ✅ Provide actionable remediation recommendations

## Key Features

- **HTTP-Only Architecture**: Modern HTTP server deployment with flexible file operations
- **FileProvider System**: Supports both local file access and client-delegated operations
- **Comprehensive Coverage**: Queries 5+ vulnerability databases (OSV.dev, NVD, GitHub Advisory, CIRCL, Safety DB)
- **GitHub Integration**: Scan any public/private GitHub repository directly
- **AI-Powered Analysis**: Uses OpenAI/Anthropic APIs for intelligent security assessment
- **Secrets Detection**: Finds exposed API keys, passwords, and credentials
- **Docker Security**: Analyzes Dockerfiles for vulnerable dependencies
- **Smart Caching**: Avoids redundant scans with commit-level caching
- **Flexible Deployment**: Local development and HTTP-only production scenarios
- **Zero Config**: Works out of the box, enhanced with optional API keys

## Requirements

- Python 3.10+
- Claude Code or compatible MCP client with HTTP transport support
- For HTTP-only mode: MCP client must implement file operation callback tools

## Supported File Types

- **Dependencies**: `requirements.txt`, `pyproject.toml`, `setup.py`, lock files (`uv.lock`, `requirements.lock`, etc.)
- **Containers**: `Dockerfile`, `docker-compose.yml`
- **Secrets**: All text-based files (excludes binary files, git history)
- **GitHub**: Any public or private repository URL

## Deployment Modes

### Local Mode (Development)
```bash
# Direct filesystem access for all operations
export VULNICHECK_HTTP_ONLY=false
vulnicheck  # Starts HTTP server on port 3000
```

### HTTP-Only Mode (Production)
```bash
# Client-delegated file operations via MCP
export VULNICHECK_HTTP_ONLY=true
export VULNICHECK_MCP_SERVER=files
vulnicheck  # Requires MCP client with file callback tools
```

## MCP Client Requirements

For HTTP-only deployment, your MCP client must implement these callback tools:
- `read_file` - Read text file contents
- `read_file_binary` - Read binary files as base64
- `list_directory` - List directory contents
- `file_exists` - Check file/directory existence
- `get_file_stats` - Get file metadata

See `docs/mcp_client_callback_tools_specification.md` for complete details.

## Support

- **Architecture Guide**: See `docs/file_provider_architecture.md` for FileProvider details
- **Client Integration**: See `docs/mcp_client_callback_tools_specification.md`
- **Complete Documentation**: See [DETAILS.md](DETAILS.md) for full documentation
- **Issues**: Report problems at https://github.com/andrasfe/vulnicheck/issues
- **Development**: Contributions welcome! See DETAILS.md for development setup

---

**DISCLAIMER**: Vulnerability data provided "AS IS" without warranty. Users responsible for verification. See DETAILS.md for full disclaimer.
