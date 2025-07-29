"""Model Context Protocol (MCP) related functionality."""

from ..core.mcp_paths import get_mcp_paths_for_agent
from .conversation_storage import ConversationStorage
from .mcp_approval_integration import MCPApprovalIntegration
from .mcp_client import MCPClient
from .mcp_config_cache import MCPConfigCache
from .mcp_passthrough import mcp_passthrough_tool
from .mcp_passthrough_interactive import (
    get_interactive_passthrough,
    mcp_passthrough_interactive,
)
from .mcp_passthrough_with_approval import mcp_passthrough_tool_with_approval
from .mcp_validator import MCPValidator

# Create aliases for server.py compatibility
unified_mcp_passthrough = mcp_passthrough_tool_with_approval

__all__ = [
    "MCPClient",
    "MCPValidator",
    "mcp_passthrough_tool",
    "mcp_passthrough_tool_with_approval",
    "unified_mcp_passthrough",
    "get_interactive_passthrough",
    "mcp_passthrough_interactive",
    "MCPApprovalIntegration",
    "ConversationStorage",
    "MCPConfigCache",
    "get_mcp_paths_for_agent",
]
