# VulniCheck - AI-Powered Security Scanner

VulniCheck provides comprehensive security analysis for Python projects and GitHub repositories using AI-powered vulnerability detection.

## Quick Start

### Installation for Claude Code

The simplest way to get started is to let Claude Code handle the installation:

```
Ask Claude Code: "Install VulniCheck MCP server for comprehensive security scanning"
```

Claude will:
1. Ask for your API keys (optional but recommended)
2. Run: `claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck`
3. Configure environment variables
4. Test the installation

### Manual Installation

If you prefer manual setup:

```bash
# Install with uvx (recommended)
claude mcp add vulnicheck -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck

# Or clone and install locally
git clone https://github.com/andrasfe/vulnicheck.git
cd vulnicheck
./run-local.sh
```

### Optional API Keys (Recommended)

Set these environment variables for enhanced features:

```bash
# For better rate limits
export NVD_API_KEY=your-nvd-key        # Get free key: https://nvd.nist.gov/developers/request-an-api-key
export GITHUB_TOKEN=your-github-token  # Get token: https://github.com/settings/tokens

# For AI-powered security analysis
export OPENAI_API_KEY=your-openai-key      # Or use Anthropic instead
# export ANTHROPIC_API_KEY=your-anthropic-key
```

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