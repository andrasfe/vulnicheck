"""
Compatibility wrapper for MCPPassthroughInteractive.

This module maintains backward compatibility by re-exporting the unified implementation.
All functionality has been consolidated into unified_passthrough.py.
"""

import json
from typing import Any

from .unified_passthrough import (
    ApprovalStatus,
    Operation,
)

# Import unified implementation
from .unified_passthrough import (
    MCPPassthroughInteractive as UnifiedMCPPassthroughInteractive,
)


# Create a wrapper class to add compatibility methods
class MCPPassthroughInteractive(UnifiedMCPPassthroughInteractive):
    """Interactive MCP passthrough with backward compatibility methods."""

    def get_pending_operations(self) -> list[dict[str, Any]]:
        """Get list of pending operations for backward compatibility."""
        strategy = self.approval_strategy
        if hasattr(strategy, 'pending_operations'):
            return [
                {
                    "request_id": op.request_id,
                    "server_name": op.server_name,
                    "tool_name": op.tool_name,
                    "parameters": op.parameters,
                    "created_at": op.created_at.isoformat(),
                    "expires_at": op.expires_at.isoformat(),
                    "status": op.status.name,
                }
                for op in strategy.pending_operations.values()
            ]
        return []

    async def close(self) -> None:
        """Close the passthrough and any underlying connections."""
        if hasattr(self, 'base_passthrough') and self.base_passthrough and hasattr(self.base_passthrough, 'close'):
            await self.base_passthrough.close()

# Legacy compatibility - map old names
PendingOperation = Operation

# Re-export other classes for compatibility
__all__ = [
    "MCPPassthroughInteractive",
    "PendingOperation",
    "ApprovalStatus",
    "get_interactive_passthrough",
    "mcp_passthrough_interactive",
]

# Global instance (singleton pattern)
_interactive_passthrough: MCPPassthroughInteractive | None = None


def get_interactive_passthrough() -> MCPPassthroughInteractive:
    """
    Get or create the global interactive passthrough instance.

    Returns the singleton instance for consistent state management.
    """
    global _interactive_passthrough
    if _interactive_passthrough is None:
        _interactive_passthrough = MCPPassthroughInteractive()
    return _interactive_passthrough


async def mcp_passthrough_interactive(
    server_name: str,
    tool_name: str,
    parameters: dict[str, Any] | None = None,
    security_context: str | None = None,
) -> str:
    """
    Execute MCP tool call with interactive approval.

    This function returns immediately with either:
    - The tool result (for safe operations)
    - An approval request (for risky operations)
    - A blocked response (for dangerous operations)

    Returns:
        JSON string when called from MCP tools, dict when called directly
    """
    if parameters is None:
        parameters = {}

    passthrough = get_interactive_passthrough()
    result = await passthrough.execute_with_approval(
        server_name=server_name,
        tool_name=tool_name,
        parameters=parameters,
        security_context=security_context,
    )

    # Always return JSON string for MCP tools
    return json.dumps(result, indent=2)
