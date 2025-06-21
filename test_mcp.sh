#!/bin/bash

# Test MCP server in Docker

# Initialize
echo "Initializing..."
echo '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "0.1.0", "capabilities": {}, "clientInfo": {"name": "test", "version": "0.1.0"}}, "id": 1}' | docker exec -i vulnicheck-mcp vulnicheck

# List tools
echo -e "\nListing tools..."
echo '{"jsonrpc": "2.0", "method": "tools/list", "id": 2}' | docker exec -i vulnicheck-mcp vulnicheck

# Test GHSA lookup
echo -e "\nTesting GHSA to CVE mapping..."
echo '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "get_cve_details", "arguments": {"cve_id": "GHSA-mr82-8j83-vxmv"}}, "id": 3}' | docker exec -i vulnicheck-mcp vulnicheck