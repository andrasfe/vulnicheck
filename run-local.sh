#!/bin/bash

# VulniCheck Setup Script
# Installs dependencies and configures Claude

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

    # Add vulnicheck to config
    info "Adding VulniCheck to Claude configuration..."
    jq '.mcpServers.vulnicheck = {
        "type": "stdio",
        "command": "'"$PYTHON_PATH"'",
        "args": ["-m", "vulnicheck.server"],
        "env": {
            "PYTHONPATH": "'"$(pwd)"'"
        }
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

            # Add vulnicheck to config
            info "Adding VulniCheck to Cursor configuration..."
            # Check if Cursor is using URL-based config
            if jq -e '.mcpServers.vulnicheck.url' "$CURSOR_CONFIG" >/dev/null 2>&1; then
                info "Cursor is using URL-based MCP config, updating to command-based..."
            fi
            jq '.mcpServers.vulnicheck = {
                "command": "'"$PYTHON_PATH"'",
                "args": ["-m", "vulnicheck.server"],
                "env": {
                    "PYTHONPATH": "'"$(pwd)"'"
                }
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
    echo "  - check_package_vulnerabilities"
    echo "  - scan_dependencies"
    echo "  - scan_installed_packages"
    echo "  - get_cve_details"
    echo "  - scan_for_secrets"
    echo "  - validate_mcp_security"
    echo "  - mcp_passthrough_tool"
    echo "  - approve_mcp_operation"
    echo "  - deny_mcp_operation"
    echo "  - list_mcp_servers"

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

    # Show restart instructions based on what was configured
    if [ -f "$CURSOR_CONFIG" ] && grep -q '"vulnicheck"' "$CURSOR_CONFIG" 2>/dev/null; then
        echo "Please restart Claude Code and Cursor to use VulniCheck"
    else
        echo "Please restart Claude Code to use VulniCheck"
    fi
    echo ""
    echo "Optional environment variables:"
    echo "  export NVD_API_KEY=your-key     # For higher NVD rate limits"
    echo "  export GITHUB_TOKEN=your-token  # For GitHub Advisory access"
    echo ""
    echo "To run the server manually:"
    echo "  .venv/bin/python -m vulnicheck.server"
}

# Run main
main
