#!/bin/bash
# Script to run the MCP test client

echo "🧪 Running VulniCheck MCP Test Client"
echo "===================================="

# Check if virtual environment exists
if [ -d "../../.venv" ]; then
    echo "✅ Found virtual environment"
    source ../../.venv/bin/activate
elif [ -d ".venv" ]; then
    echo "✅ Found virtual environment"
    source .venv/bin/activate
else
    echo "❌ No virtual environment found"
    echo "   Please run from project root or create venv first"
    exit 1
fi

# Set environment variables for testing
export VULNICHECK_DEBUG=true

# Optional: Set NVD API key if available
# export NVD_API_KEY="your-key-here"

# Run the test client
python test_mcp_client.py
