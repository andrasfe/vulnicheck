#!/bin/bash
# VulniCheck Local Setup Script

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}VulniCheck Local Setup${NC}"
echo "========================"

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Error: Python $REQUIRED_VERSION or higher is required (found $PYTHON_VERSION)${NC}"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv .venv
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source .venv/bin/activate

# Upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip --quiet

# Install dependencies
echo -e "${YELLOW}Installing vulnicheck...${NC}"
pip install -e . --quiet

# Show available environment variables
echo ""
echo -e "${GREEN}Environment Configuration:${NC}"
if [ -n "$NVD_API_KEY" ]; then
    echo "- NVD_API_KEY: [SET]"
else
    echo "- NVD_API_KEY: [NOT SET] (rate limits apply)"
fi
if [ -n "$GITHUB_TOKEN" ]; then
    echo "- GITHUB_TOKEN: [SET]"
else
    echo "- GITHUB_TOKEN: [NOT SET] (rate limits apply)"
fi
echo "- CACHE_TTL: ${CACHE_TTL:-900} seconds"
echo ""

# Show how to configure in Claude
echo -e "${GREEN}Setup Complete!${NC}"
echo ""
echo "To add VulniCheck to Claude, run this command:"
echo ""
echo -e "${YELLOW}claude mcp add vulnicheck -- $(pwd)/.venv/bin/python -m vulnicheck.server${NC}"
echo ""
echo -e "${RED}Important: After adding the server, you must exit Claude and restart it for the changes to take effect!${NC}"
echo ""
echo "Or manually add to your MCP settings:"
echo ""
echo -e "${YELLOW}{
  \"mcpServers\": {
    \"vulnicheck\": {
      \"command\": \"$(pwd)/.venv/bin/python\",
      \"args\": [\"-m\", \"vulnicheck.server\"]
    }
  }
}${NC}"
echo ""
echo "Or run manually for testing:"
echo -e "${YELLOW}$(pwd)/.venv/bin/python -m vulnicheck.server${NC}"