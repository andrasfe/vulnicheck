#!/bin/bash

# VulniCheck Setup Script
# Installs dependencies and configures Claude/Cursor for HTTP transport

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions for colored output
success() {
    echo -e "${GREEN}✓ $1${NC}"
}

info() {
    echo -e "${YELLOW}→ $1${NC}"
}

error() {
    echo -e "${RED}✗ $1${NC}"
}

header() {
    echo -e "${BLUE}$1${NC}"
}

# Check Python version
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        error "Python not found. Please install Python 3.8 or higher."
        exit 1
    fi

    PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.major)')
    PYTHON_MINOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.minor)')

    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
        error "Python 3.8 or higher is required. Found: Python $PYTHON_VERSION"
        exit 1
    fi

    success "Found Python $PYTHON_VERSION"
}

# Main setup function
main() {
    echo "VulniCheck Setup"
    echo "================"
    echo ""

    # Check we're in the right directory
    if [ ! -f "pyproject.toml" ] || ! grep -q "vulnicheck" pyproject.toml; then
        error "Please run this script from the vulnicheck project directory"
        exit 1
    fi

    # Step 1: Check Python
    check_python

    # Step 2: Create virtual environment
    header "Setting up virtual environment..."
    if [ ! -d ".venv" ]; then
        info "Creating virtual environment..."
        $PYTHON_CMD -m venv .venv
        success "Created virtual environment"
    else
        info "Virtual environment already exists"
    fi

    # Step 3: Install dependencies
    header "Installing dependencies..."
    source .venv/bin/activate

    info "Upgrading pip..."
    pip install --upgrade pip --quiet

    if command -v uv &> /dev/null; then
        info "Installing with uv (fast)..."
        uv pip install -e ".[dev]"
    else
        info "Installing with pip..."
        pip install -e ".[dev]"
    fi

    success "Dependencies installed"

    # Step 4: Configure Claude
    header "Configuring Claude..."

    PYTHON_PATH="$(pwd)/.venv/bin/python"
    CLAUDE_CONFIG="$HOME/.claude.json"

    if [ ! -f "$CLAUDE_CONFIG" ]; then
        error "Claude configuration not found at $CLAUDE_CONFIG"
        error "Make sure Claude Code is installed and has been run at least once"
        exit 1
    fi

    # Check if jq is available
    if ! command -v jq &> /dev/null; then
        error "jq is required for configuration updates"
        info "Install jq:"
        echo "  Ubuntu/Debian: sudo apt-get install jq"
        echo "  macOS: brew install jq"
        echo "  RHEL/CentOS: sudo yum install jq"
        exit 1
    fi

    # Backup config
    cp "$CLAUDE_CONFIG" "$CLAUDE_CONFIG.backup.$(date +%s)"
    info "Backed up configuration"

    # Add vulnicheck to config (HTTP transport)
    info "Adding VulniCheck to Claude configuration (HTTP transport)..."
    jq '.mcpServers.vulnicheck = {
        "type": "http",
        "url": "http://localhost:3000",
        "description": "VulniCheck HTTP server - start with: '"$PYTHON_PATH"' -m vulnicheck.server"
    }' "$CLAUDE_CONFIG" > "$CLAUDE_CONFIG.tmp" && mv "$CLAUDE_CONFIG.tmp" "$CLAUDE_CONFIG"

    success "VulniCheck added to Claude configuration"

    # Step 4.5: Configure Cursor (if config exists)
    header "Checking for Cursor..."

    CURSOR_CONFIG="$HOME/.cursor/mcp.json"

    if [ -f "$CURSOR_CONFIG" ]; then
        info "Found Cursor configuration"

        # Check if vulnicheck is already configured
        if grep -q '"vulnicheck"' "$CURSOR_CONFIG" 2>/dev/null; then
            info "VulniCheck already configured in Cursor"
        else
            # Backup config
            cp "$CURSOR_CONFIG" "$CURSOR_CONFIG.backup.$(date +%s)"
            info "Backed up Cursor configuration"

            # Add vulnicheck to config (HTTP transport)
            info "Adding VulniCheck to Cursor configuration (HTTP transport)..."
            jq '.mcpServers.vulnicheck = {
                "url": "http://localhost:3000",
                "description": "VulniCheck HTTP server - start with: '"$PYTHON_PATH"' -m vulnicheck.server"
            }' "$CURSOR_CONFIG" > "$CURSOR_CONFIG.tmp" && mv "$CURSOR_CONFIG.tmp" "$CURSOR_CONFIG"

            success "VulniCheck added to Cursor configuration"
        fi
    else
        info "Cursor configuration not found (skipping)"
    fi

    # Step 5: Test installation
    header "Testing installation..."

    if .venv/bin/python -c "import vulnicheck.server" 2>/dev/null; then
        success "VulniCheck imports correctly"
    else
        error "Failed to import VulniCheck"
        exit 1
    fi

    info "Available tools:"
    echo "  - check_package_vulnerabilities     # Check specific Python package vulnerabilities"
    echo "  - scan_dependencies                 # Scan dependency files (requirements.txt, pyproject.toml, setup.py)"
    echo "  - scan_installed_packages           # Scan currently installed Python packages"
    echo "  - get_cve_details                   # Get detailed CVE information"
    echo "  - scan_for_secrets                  # Scan files for exposed credentials"
    echo "  - validate_mcp_security             # Validate MCP server security configuration"
    echo "  - mcp_passthrough_tool              # Secure MCP tool proxying with risk assessment"
    echo "  - approve_mcp_operation             # Approve pending MCP operations (interactive mode)"
    echo "  - deny_mcp_operation                # Deny pending MCP operations (interactive mode)"
    echo "  - list_mcp_servers                  # List available MCP servers"
    echo "  - scan_dockerfile                   # Analyze Dockerfiles for Python vulnerabilities"
    echo "  - assess_operation_safety           # Pre-operation risk assessment for LLMs"
    echo "  - comprehensive_security_check      # Interactive AI-powered security assessment"
    echo "  - get_mcp_conversations             # Retrieve and search past MCP interactions"
    echo "  - scan_github_repo                  # Comprehensive GitHub repository security analysis"
    echo "  - manage_trust_store                # Manage MCP server trust store"
    echo "  - install_vulnicheck_guide          # Installation guide for Claude Code users"

    # Show current MCP servers
    echo ""
    info "Current Claude MCP servers:"
    jq -r '.mcpServers | keys[]' "$CLAUDE_CONFIG" | sed 's/^/  - /'

    if [ -f "$CURSOR_CONFIG" ]; then
        echo ""
        info "Current Cursor MCP servers:"
        jq -r '.mcpServers | keys[]' "$CURSOR_CONFIG" | sed 's/^/  - /'
    fi

    # Final message
    echo ""
    header "Setup complete!"
    success "VulniCheck is installed and configured"
    echo ""

    # Show startup instructions
    echo "IMPORTANT: Start the VulniCheck HTTP server first:"
    echo "  .venv/bin/python -m vulnicheck.server"
    echo ""
    # Show restart instructions based on what was configured
    if [ -f "$CURSOR_CONFIG" ] && grep -q '"vulnicheck"' "$CURSOR_CONFIG" 2>/dev/null; then
        echo "Then restart Claude Code and Cursor to use VulniCheck"
    else
        echo "Then restart Claude Code to use VulniCheck"
    fi
    echo ""
    echo "Optional environment variables:"
    echo "  export NVD_API_KEY=your-key          # For higher NVD rate limits (5→50 req/30s)"
    echo "  export GITHUB_TOKEN=your-token       # For GitHub Advisory access (5000 req/hour)"
    echo "  export OPENAI_API_KEY=your-key       # For LLM-based risk assessment"
    echo "  export ANTHROPIC_API_KEY=your-key    # Alternative to OpenAI for risk assessment"
    echo "  export MCP_PORT=3000                 # Change HTTP server port (default: 3000)"
    echo "  export VULNICHECK_DEBUG=true         # Enable debug logging"
    echo ""
    echo "To run the HTTP server manually:"
    echo "  .venv/bin/python -m vulnicheck.server"
    echo "  Server will be available at http://localhost:3000"
}

# Run main
main
