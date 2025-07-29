# VulniCheck - AI-Powered Security Scanner

VulniCheck provides comprehensive security analysis for Python projects and GitHub repositories using AI-powered vulnerability detection.

## Quick Start

### Installation for Claude Code

The simplest way to get started is to let Claude Code install by pointing it to this URL:

```
Hey Claude, follow these instructions:
```

Claude will:
1. Ask for your API keys (optional but recommended). Eithe OPENAI_API_KEY or ANTHROPIC_API_KEY.
2. Run: `claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck` --env <insert here>
3. Ask user to exit/restart claude code


## Usage

Once installed, simply ask Claude Code:

```
"Run a comprehensive security check on my project"

"Run a comprehensive security check on https://github.com/owner/repo" 

"Check this directory for security vulnerabilities"
```

VulniCheck will:
- ✅ Scan dependencies for known vulnerabilities
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

## Support

- **Documentation**: See [DETAILS.md](DETAILS.md) for complete documentation
- **Issues**: Report problems at https://github.com/andrasfe/vulnicheck/issues
- **Development**: Contributions welcome! See DETAILS.md for development setup

---

**DISCLAIMER**: Vulnerability data provided "AS IS" without warranty. Users responsible for verification. See DETAILS.md for full disclaimer.