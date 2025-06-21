#!/bin/bash
# Quick setup script for VulniCheck

echo "VulniCheck Setup"
echo "================"
echo ""

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "ERROR: uv is not installed. Please install it first:"
    echo "   curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
uv venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
uv pip install -e ".[dev]"

# Check for .env file
if [ ! -f .env ]; then
    echo ""
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "✅ Created .env file"
    echo ""
    echo "OPTIONAL but RECOMMENDED:"
    echo "   Get a free NVD API key for 10x higher rate limits:"
    echo "   https://nvd.nist.gov/developers/request-an-api-key"
    echo ""
    echo "   Then add it to your .env file:"
    echo "   NVD_API_KEY=your-key-here"
else
    echo "✅ .env file already exists"
fi

echo ""
echo "Setup complete! 🎉"
echo ""
echo "To run the MCP server:"
echo "  source .venv/bin/activate"
echo "  vulnicheck"
echo ""
echo "To run tests:"
echo "  pytest -m 'not integration'  # Unit tests only"
echo "  ./run_integration_tests.sh   # Integration tests"