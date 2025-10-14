#!/bin/bash
# Restart VulniCheck with current ngrok URL and OAuth enabled

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  VulniCheck OAuth + ngrok Restart Script                  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Load configuration from .env file first
if [ -f .env ]; then
    source .env
    CLIENT_ID="$GOOGLE_CLIENT_ID"
    CLIENT_SECRET="$GOOGLE_CLIENT_SECRET"
else
    echo -e "${RED}ERROR: .env file not found!${NC}"
    echo "Create a .env file with GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET"
    exit 1
fi

# Verify credentials are loaded
if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
    echo -e "${RED}ERROR: OAuth credentials not found in .env file!${NC}"
    echo "Make sure .env contains GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET"
    exit 1
fi

# Get ngrok URL - use .env value if set, otherwise auto-detect
if [ -n "$NGROK_URL" ]; then
    echo -e "${GREEN}✓${NC} Using ngrok URL from .env: ${YELLOW}$NGROK_URL${NC}"
else
    echo -e "${YELLOW}Auto-detecting ngrok URL...${NC}"

    # Check if ngrok is running
    if ! curl -s http://localhost:4040/api/tunnels > /dev/null 2>&1; then
        echo -e "${RED}ERROR: ngrok doesn't appear to be running!${NC}"
        echo "Start ngrok first with: ngrok http 3000"
        echo "Or set NGROK_URL in .env file"
        exit 1
    fi

    # Get ngrok URL from the API
    NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | grep -o '"public_url":"https://[^"]*' | grep -o 'https://[^"]*' | head -1)

    if [ -z "$NGROK_URL" ]; then
        echo -e "${RED}ERROR: Could not detect ngrok URL${NC}"
        echo "Make sure ngrok is running: ngrok http 3000"
        echo "Or set NGROK_URL in .env file"
        exit 1
    fi

    echo -e "${GREEN}✓${NC} Detected ngrok URL: ${YELLOW}$NGROK_URL${NC}"
fi
echo ""

# Stop and remove old container
echo -e "${YELLOW}Stopping existing container...${NC}"
docker stop vulnicheck-mcp 2>/dev/null || true
docker rm vulnicheck-mcp 2>/dev/null || true
echo -e "${GREEN}✓${NC} Old container removed"
echo ""

# Build docker command with optional environment variables
DOCKER_CMD="docker run -d --name vulnicheck-mcp -p 3000:3000 --restart=unless-stopped"

# Add OAuth credentials
DOCKER_CMD="$DOCKER_CMD -e FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID=$CLIENT_ID"
DOCKER_CMD="$DOCKER_CMD -e FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET=$CLIENT_SECRET"
DOCKER_CMD="$DOCKER_CMD -e FASTMCP_SERVER_BASE_URL=$NGROK_URL"

# Add optional API keys if set in .env
[ -n "$OPENAI_API_KEY" ] && DOCKER_CMD="$DOCKER_CMD -e OPENAI_API_KEY=$OPENAI_API_KEY"
[ -n "$ANTHROPIC_API_KEY" ] && DOCKER_CMD="$DOCKER_CMD -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"
[ -n "$GITHUB_TOKEN" ] && DOCKER_CMD="$DOCKER_CMD -e GITHUB_TOKEN=$GITHUB_TOKEN"
[ -n "$NVD_API_KEY" ] && DOCKER_CMD="$DOCKER_CMD -e NVD_API_KEY=$NVD_API_KEY"

# Add volume and image
DOCKER_CMD="$DOCKER_CMD -v vulnicheck_tokens:/home/vulnicheck/.vulnicheck/tokens"
DOCKER_CMD="$DOCKER_CMD vulnicheck:latest python -m vulnicheck.server --auth-mode google"

# Start new container
echo -e "${YELLOW}Starting VulniCheck with OAuth...${NC}"
echo -e "${YELLOW}⚠️  Note: OAuth does not work with HTTP transport in FastMCP 2.12.4${NC}"
eval $DOCKER_CMD > /dev/null

# Wait for container to start
echo -n "Waiting for container to start"
for i in {1..5}; do
    sleep 1
    echo -n "."
done
echo ""

# Check if container is running
if docker ps | grep -q vulnicheck-mcp; then
    echo -e "${GREEN}✓${NC} VulniCheck started successfully!"
else
    echo -e "${RED}✗${NC} Failed to start container. Check logs with: docker logs vulnicheck-mcp"
    exit 1
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Configuration Summary                                     ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}MCP Endpoint:${NC}      $NGROK_URL/mcp"
echo -e "  ${GREEN}OAuth Authorize:${NC}   $NGROK_URL/oauth/authorize"
echo -e "  ${GREEN}OAuth Callback:${NC}    $NGROK_URL/oauth/callback"
echo ""
echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  ACTION REQUIRED: Update Google Cloud Console             ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "1. Go to: https://console.cloud.google.com/apis/credentials"
echo "2. Click on your OAuth 2.0 Client ID"
echo "3. Add this to Authorized redirect URIs:"
echo ""
echo -e "   ${GREEN}$NGROK_URL/oauth/callback${NC}"
echo ""
echo "4. Click SAVE"
echo ""
echo -e "${GREEN}View logs:${NC}      docker logs -f vulnicheck-mcp"
echo -e "${GREEN}Stop server:${NC}    docker stop vulnicheck-mcp"
echo ""
