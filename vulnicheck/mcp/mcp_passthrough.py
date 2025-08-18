"""
Compatibility wrapper for MCPPassthrough.

This module maintains backward compatibility by re-exporting the unified implementation.
All functionality has been consolidated into unified_passthrough.py.
"""

import json
from typing import Any

from .unified_passthrough import (
    MCPConnectionPool,
)

# Import unified implementation
from .unified_passthrough import (
    MCPPassthrough as UnifiedMCPPassthrough,
)

# Re-export the unified class with the original name
MCPPassthrough = UnifiedMCPPassthrough
MCPCall = UnifiedMCPPassthrough  # For any legacy references

# Re-export other classes for compatibility
__all__ = [
    "MCPPassthrough",
    "MCPConnectionPool",
    "mcp_passthrough_tool",
    "get_passthrough",
]

# Global instance for reuse
_global_passthrough: MCPPassthrough | None = None


async def get_passthrough(agent_name: str | None = None) -> MCPPassthrough:
    """Get or create the global passthrough instance."""
    global _global_passthrough

    if _global_passthrough is None:
        _global_passthrough = MCPPassthrough(agent_name)

    return _global_passthrough


async def mcp_passthrough_tool(
    server_name: str,
    tool_name: str,
    parameters: dict[str, Any] | None = None,
    security_context: str | None = None,
    agent_name: str | None = None,
) -> str:
    """
    Execute an MCP tool call through the security passthrough.

    This tool acts as a security layer between the LLM and MCP servers,
    intercepting calls and adding security constraints.
    """
    if parameters is None:
        parameters = {}

    passthrough = await get_passthrough(agent_name)

    if not passthrough.validate_server_access(server_name):
        return json.dumps(
            {
                "status": "blocked",
                "reason": f"Access to server '{server_name}' is not allowed",
            },
            indent=2,
        )

    result = await passthrough.execute_with_security(
        server_name=server_name,
        tool_name=tool_name,
        parameters=parameters,
        security_context=security_context,
    )

    return json.dumps(result, indent=2)
