# VulniCheck - AI-Powered Security Scanner

VulniCheck provides comprehensive security analysis for Python projects and GitHub repositories using AI-powered vulnerability detection. It runs as a Docker-based HTTP MCP server, providing secure containerized deployment with comprehensive vulnerability scanning capabilities.

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

- **Docker Deployment**: Secure containerized deployment with HTTP streaming
- **Production Ready**: Scalable HTTP server architecture
- **Comprehensive Coverage**: Queries 5+ vulnerability databases (OSV.dev, NVD, GitHub Advisory, CIRCL, Safety DB)
- **GitHub Integration**: Scan any public/private GitHub repository directly
- **AI-Powered Analysis**: Uses OpenAI/Anthropic APIs for intelligent security assessment
- **Secrets Detection**: Finds exposed API keys, passwords, and credentials
- **Docker Security**: Analyzes Dockerfiles for vulnerable dependencies
- **Smart Caching**: Avoids redundant scans with commit-level caching
- **Flexible Deployment**: Local development and HTTP-only production scenarios
- **Zero Config**: Works out of the box, enhanced with optional API keys

## Requirements

- Docker
- Claude Code or compatible MCP client with HTTP transport support

## Supported File Types

- **Dependencies**: `requirements.txt`, `pyproject.toml`, `setup.py`, lock files (`uv.lock`, `requirements.lock`, etc.)
- **Containers**: `Dockerfile`, `docker-compose.yml`
- **Secrets**: All text-based files (excludes binary files, git history)
- **GitHub**: Any public or private repository URL

## Deployment

### Docker Setup (Recommended)
```bash
# Clone and build
git clone -b docker-deployment https://github.com/andrasfe/vulnicheck.git
cd vulnicheck
docker build -t vulnicheck .

# Run with optional API keys
docker run -d --name vulnicheck -p 3000:3000 \
  -e OPENAI_API_KEY=your-key \
  -e ANTHROPIC_API_KEY=your-key \
  vulnicheck
```

The server will be available at http://localhost:3000/mcp

## Support

- **Installation Guide**: See [CLAUDE_INSTALL.md](CLAUDE_INSTALL.md) for setup instructions
- **Project Documentation**: See [CLAUDE.md](CLAUDE.md) for development details
- **Issues**: Report problems at https://github.com/andrasfe/vulnicheck/issues
- **Development**: Contributions welcome! See CLAUDE.md for development setup

---

**DISCLAIMER**: Vulnerability data provided "AS IS" without warranty. Users responsible for verification.
