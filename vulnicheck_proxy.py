#!/usr/bin/env python3
"""
FastMCP proxy for VulniCheck HTTP server.
This creates a STDIO MCP server that proxies to the HTTP VulniCheck server.
"""

import sys
import logging
from fastmcp import FastMCP

# Enable debug logging
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger(__name__)

try:
    logger.info("Creating FastMCP proxy for http://localhost:3000/mcp")
    # Create a FastMCP proxy that forwards to the VulniCheck HTTP server
    proxy = FastMCP.as_proxy(
        "http://localhost:3000/mcp", 
        name="VulniCheck Security Scanner"
    )
    logger.info("Proxy created successfully, starting server...")
    
    if __name__ == "__main__":
        proxy.run()
except Exception as e:
    logger.error(f"Error creating or running proxy: {e}")
    sys.exit(1)