# VulniCheck - AI-Powered Security Scanner

VulniCheck provides comprehensive security analysis for Python projects and GitHub repositories using AI-powered vulnerability detection. It runs as a Docker-based HTTP MCP server with standard HTTP streaming (no SSE required), providing secure containerized deployment with comprehensive vulnerability scanning capabilities.

## Quick Start

### 1. Pull and Run the Docker Container

```bash
# Pull the latest image from Docker Hub
docker pull andrasfe/vulnicheck:latest

# Run with OpenAI API key (for enhanced AI-powered risk assessment)
docker run -d --name vulnicheck-mcp -p 3000:3000 \
  --restart=unless-stopped \
  -e OPENAI_API_KEY=your-openai-api-key \
  andrasfe/vulnicheck:latest

# Or run without API key (basic vulnerability scanning)
docker run -d --name vulnicheck-mcp -p 3000:3000 \
  --restart=unless-stopped \
  andrasfe/vulnicheck:latest
```

### 2. Add to Claude Code

```bash
claude mcp add --transport http vulnicheck http://localhost:3000/mcp
```

That's it! VulniCheck is now available in Claude Code.

## Usage

Once installed, simply ask Claude:

```
"Run a comprehensive security check on my project"

"Scan https://github.com/owner/repo for vulnerabilities"

"Check my dependencies for security issues"

"Scan my Dockerfile for vulnerable packages"
```

VulniCheck will:
- ✅ Scan dependencies for known vulnerabilities (requirements.txt, pyproject.toml, setup.py)
- ✅ Detect exposed secrets and credentials
- ✅ Analyze Dockerfiles for security issues
- ✅ Validate MCP configurations
- ✅ Generate AI-powered risk assessments
- ✅ Provide actionable remediation recommendations

## Key Features

- **Docker Deployment**: Secure containerized deployment with HTTP streaming (no SSE/Server-Sent Events required)
- **Production Ready**: Scalable HTTP server architecture
- **Comprehensive Coverage**: Queries 5+ vulnerability databases (OSV.dev, NVD, GitHub Advisory, CIRCL, Safety DB)
- **GitHub Integration**: Scan any public/private GitHub repository directly (up to 1GB)
- **AI-Powered Analysis**: Uses OpenAI/Anthropic APIs for intelligent security assessment
- **Secrets Detection**: Finds exposed API keys, passwords, and credentials
- **Docker Security**: Analyzes Dockerfiles for vulnerable dependencies
- **Smart Caching**: Avoids redundant scans with commit-level caching
- **Space Management**: Automatic cleanup prevents disk exhaustion (2GB total limit)
- **Zero Config**: Works out of the box, enhanced with optional API keys

## Available Tools

| Tool | Description |
|------|-------------|
| `check_package_vulnerabilities` | Check a specific Python package for vulnerabilities |
| `scan_dependencies` | Scan dependency files (requirements.txt, pyproject.toml, etc.) |
| `scan_installed_packages` | Scan currently installed Python packages |
| `get_cve_details` | Get detailed information about a specific CVE |
| `scan_for_secrets` | Detect exposed secrets and credentials in code |
| `scan_dockerfile` | Analyze Dockerfiles for vulnerable Python dependencies |
| `scan_github_repo` | Comprehensive security scan of GitHub repositories |
| `assess_operation_safety` | AI-powered risk assessment for operations |
| `validate_mcp_security` | Validate MCP server security configurations |
| `comprehensive_security_check` | Interactive AI-powered security assessment |

## Optional API Keys

Enhance VulniCheck with API keys for better rate limits and AI features:

```bash
docker run -d --name vulnicheck-mcp -p 3000:3000 \
  --restart=unless-stopped \
  -e OPENAI_API_KEY=your-key \           # AI-powered risk assessment
  -e ANTHROPIC_API_KEY=your-key \        # Alternative AI provider
  -e GITHUB_TOKEN=your-token \           # Higher GitHub API rate limits
  -e NVD_API_KEY=your-key \              # Higher NVD rate limits
  andrasfe/vulnicheck:latest
```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/andrasfe/vulnicheck.git
cd vulnicheck

# Build Docker image
docker build -t vulnicheck .

# Run locally built image
docker run -d --name vulnicheck-mcp -p 3000:3000 --restart=unless-stopped vulnicheck
```

## Docker Hub

The official Docker image is available at:
- **Docker Hub**: [andrasfe/vulnicheck](https://hub.docker.com/r/andrasfe/vulnicheck)
- **Latest Tag**: `andrasfe/vulnicheck:latest`

## Requirements

- Docker
- Claude Code or any MCP client with HTTP transport support (standard HTTP, no SSE required)
- Optional: API keys for enhanced features

## Supported File Types

- **Dependencies**: `requirements.txt`, `pyproject.toml`, `setup.py`, lock files
- **Containers**: `Dockerfile`, `docker-compose.yml`
- **Secrets**: All text-based source files
- **GitHub**: Any public or private repository URL

## Support

- **Issues**: Report problems at https://github.com/andrasfe/vulnicheck/issues
- **Development**: See [CLAUDE.md](CLAUDE.md) for development details
- **Security**: Report security issues privately via GitHub Security Advisories

---

**DISCLAIMER**: Vulnerability data provided "AS IS" without warranty. Users are responsible for verification and remediation.
