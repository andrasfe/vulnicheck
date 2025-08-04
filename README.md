# VulniCheck - AI-Powered Security Scanner

VulniCheck provides comprehensive security analysis for Python projects and GitHub repositories using AI-powered vulnerability detection.

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

- **Comprehensive Coverage**: Queries 5+ vulnerability databases (OSV.dev, NVD, GitHub Advisory, CIRCL, Safety DB)
- **GitHub Integration**: Scan any public/private GitHub repository directly
- **AI-Powered Analysis**: Uses OpenAI/Anthropic APIs for intelligent security assessment
- **Secrets Detection**: Finds exposed API keys, passwords, and credentials
- **Docker Security**: Analyzes Dockerfiles for vulnerable dependencies
- **Smart Caching**: Avoids redundant scans with commit-level caching
- **Zero Config**: Works out of the box, enhanced with optional API keys

## Requirements

- Python 3.10+
- Claude Code or compatible MCP client

## Supported File Types

- **Dependencies**: `requirements.txt`, `pyproject.toml`, `setup.py`, lock files (`uv.lock`, `requirements.lock`, etc.)
- **Containers**: `Dockerfile`, `docker-compose.yml`
- **Secrets**: All text-based files (excludes binary files, git history)
- **GitHub**: Any public or private repository URL

## Support

- **Documentation**: See [DETAILS.md](DETAILS.md) for complete documentation
- **Issues**: Report problems at https://github.com/andrasfe/vulnicheck/issues
- **Development**: Contributions welcome! See DETAILS.md for development setup

---

**DISCLAIMER**: Vulnerability data provided "AS IS" without warranty. Users responsible for verification. See DETAILS.md for full disclaimer.
