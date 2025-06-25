#!/bin/bash
# Setup script for VulniCheck MCP Service

echo "Setting up VulniCheck MCP..."
echo ""

# Check for .env file
if [ -f .env ]; then
    echo "Loading environment from .env file..."
    export $(cat .env | grep -v '^#' | xargs)
fi

# Build the Docker image (force rebuild to pick up code changes)
echo "Building Docker image..."
docker-compose build --no-cache || exit 1

# Stop any existing service
echo "Stopping any existing service..."
docker-compose down 2>/dev/null

# Start the service
echo "Starting VulniCheck service..."
docker-compose up -d || exit 1

# Wait for service to be ready
echo "Waiting for service to start..."
sleep 3

# Check if service is running
if docker-compose ps | grep -q "vulnicheck-mcp.*Up"; then
    echo ""
    echo "✅ VulniCheck MCP is running!"
    echo ""
    echo "Service URL: http://localhost:${MCP_PORT:-3000}"
    echo ""
    echo "Configure your IDE to connect to: http://localhost:${MCP_PORT:-3000}"
    echo ""
    echo "Examples:"
    echo "  Claude:  claude mcp add vulnicheck --transport sse http://localhost:${MCP_PORT:-3000}/sse"
    echo "  VS Code: Add http://localhost:${MCP_PORT:-3000} to MCP servers"
    echo "  Cursor:  Add http://localhost:${MCP_PORT:-3000} to MCP settings"
    echo ""
    echo "Useful commands:"
    echo "  View logs:    docker-compose logs -f"
    echo "  Stop service: docker-compose down"
    echo "  Restart:      docker-compose restart"
    echo ""
else
    echo "❌ Failed to start service. Check logs with: docker-compose logs"
    exit 1
fi