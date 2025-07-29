#!/bin/bash
# Auto-installation script for VulniCheck MCP server
# This script can be run by Claude Code to install VulniCheck automatically

set -e

echo "🛡️  Installing VulniCheck MCP Server..."

# Check if claude command exists
if ! command -v claude &> /dev/null; then
    echo "❌ Claude Code CLI not found. Please install it first."
    exit 1
fi

# Check if we're in interactive mode
if [ -t 0 ]; then
    echo "Interactive installation. Asking for API keys..."
    
    # Ask for API keys
    echo "🔑 Optional API Keys (press Enter to skip):"
    
    read -p "NVD API Key: " NVD_API_KEY
    read -p "GitHub Token: " GITHUB_TOKEN  
    read -p "OpenAI API Key: " OPENAI_API_KEY
    read -p "Anthropic API Key: " ANTHROPIC_API_KEY
    
    # Build environment variables
    ENV_VARS=""
    [ ! -z "$NVD_API_KEY" ] && ENV_VARS="$ENV_VARS -e NVD_API_KEY=$NVD_API_KEY"
    [ ! -z "$GITHUB_TOKEN" ] && ENV_VARS="$ENV_VARS -e GITHUB_TOKEN=$GITHUB_TOKEN"
    [ ! -z "$OPENAI_API_KEY" ] && ENV_VARS="$ENV_VARS -e OPENAI_API_KEY=$OPENAI_API_KEY"
    [ ! -z "$ANTHROPIC_API_KEY" ] && ENV_VARS="$ENV_VARS -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"
    
else
    echo "Non-interactive installation. Using environment variables if available."
    ENV_VARS=""
    [ ! -z "$NVD_API_KEY" ] && ENV_VARS="$ENV_VARS -e NVD_API_KEY=$NVD_API_KEY"
    [ ! -z "$GITHUB_TOKEN" ] && ENV_VARS="$ENV_VARS -e GITHUB_TOKEN=$GITHUB_TOKEN"
    [ ! -z "$OPENAI_API_KEY" ] && ENV_VARS="$ENV_VARS -e OPENAI_API_KEY=$OPENAI_API_KEY"
    [ ! -z "$ANTHROPIC_API_KEY" ] && ENV_VARS="$ENV_VARS -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"
fi

# Install VulniCheck
echo "🚀 Installing VulniCheck..."
eval "claude mcp add vulnicheck $ENV_VARS -- uvx --from git+https://github.com/andrasfe/vulnicheck.git vulnicheck"

echo "✅ VulniCheck installed successfully!"
echo ""
echo "Next steps:"
echo "1. Restart Claude Code"
echo "2. Ask: 'Run a comprehensive security check on my project'"
echo "3. Add '.vulnicheck/' to your .gitignore"
echo ""
echo "💡 Get API keys for enhanced features:"
echo "- NVD: https://nvd.nist.gov/developers/request-an-api-key"
echo "- GitHub: https://github.com/settings/tokens"