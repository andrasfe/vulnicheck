"""
MCP Passthrough Tool - Security layer for MCP server interactions.

This module provides a passthrough mechanism that intercepts MCP server calls
and injects security prompts to prevent harmful operations.
"""

import json
import logging
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class MCPCall(BaseModel):
    """Model for MCP server call parameters."""

    server_name: str = Field(description="Name of the target MCP server")
    tool_name: str = Field(description="Name of the tool to call on the MCP server")
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="Parameters to pass to the tool"
    )
    security_context: str | None = Field(
        default=None,
        description="Additional security context or constraints for this call",
    )


class MCPPassthrough:
    """
    Passthrough handler for MCP server calls with security enforcement.

    This class intercepts MCP server tool calls and adds security prompts
    to prevent potentially harmful operations.
    """

    def __init__(self, mcp_client: Any = None) -> None:
        """
        Initialize the passthrough handler.

        Args:
            mcp_client: Optional MCP client instance for making actual calls
        """
        self.mcp_client = mcp_client
        self.security_prompt_template = """
SECURITY NOTICE: You are about to execute an MCP tool call with the following details:
- Server: {server_name}
- Tool: {tool_name}
- Parameters: {parameters}

IMPORTANT SECURITY CONSTRAINTS:
1. DO NOT execute commands that could harm the system or access sensitive data
2. DO NOT read or expose files containing secrets, passwords, or API keys
3. DO NOT execute shell commands that could modify system files or settings
4. DO NOT access user's personal files without explicit permission
5. VERIFY that the requested operation aligns with the user's actual intent

Additional context: {security_context}

Please review this operation carefully before proceeding.
"""

    async def execute_with_security(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        security_context: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute an MCP tool call with security checks.

        Args:
            server_name: Target MCP server name
            tool_name: Tool to call on the server
            parameters: Parameters for the tool
            security_context: Additional security constraints

        Returns:
            Result from the MCP tool call or security rejection
        """
        # Log the attempted call
        logger.info(
            f"MCP Passthrough: {server_name}.{tool_name} with params: {parameters}"
        )

        # Build security prompt
        security_prompt = self.security_prompt_template.format(
            server_name=server_name,
            tool_name=tool_name,
            parameters=json.dumps(parameters, indent=2),
            security_context=security_context or "None provided",
        )

        # Check for obviously dangerous operations
        dangerous_patterns = [
            # File system operations on sensitive paths
            ("/etc/", "file_path"),
            ("/root/", "file_path"),
            ("~/.ssh/", "file_path"),
            (".env", "file_path"),
            ("password", "file_path"),
            ("secret", "file_path"),
            ("key", "file_path"),
            # Dangerous commands
            ("rm -rf", "command"),
            ("sudo", "command"),
            ("chmod 777", "command"),
            ("curl | bash", "command"),
            ("wget | sh", "command"),
        ]

        # Check parameters for dangerous patterns
        param_str = json.dumps(parameters).lower()
        for pattern, _ in dangerous_patterns:
            if pattern.lower() in param_str:
                logger.warning(f"Blocked potentially dangerous operation: {pattern}")
                return {
                    "status": "blocked",
                    "reason": f"Operation blocked due to potentially dangerous pattern: {pattern}",
                    "security_prompt": security_prompt,
                }

        # If we have an MCP client, make the actual call
        if self.mcp_client:
            try:
                # This is a placeholder - actual implementation would depend on
                # the MCP client library being used
                result = await self._forward_to_mcp(server_name, tool_name, parameters)
                return {
                    "status": "success",
                    "result": result,
                    "security_prompt": security_prompt,
                }
            except Exception as e:
                logger.error(f"MCP call failed: {e}")
                return {
                    "status": "error",
                    "error": str(e),
                    "security_prompt": security_prompt,
                }
        else:
            # Return mock response if no client configured
            return {
                "status": "mock",
                "message": "No MCP client configured - returning mock response",
                "requested_call": {
                    "server": server_name,
                    "tool": tool_name,
                    "parameters": parameters,
                },
                "security_prompt": security_prompt,
            }

    async def _forward_to_mcp(
        self, server_name: str, tool_name: str, parameters: dict[str, Any]
    ) -> Any:
        """
        Forward the call to the actual MCP server.

        This is a placeholder that would be implemented based on the
        actual MCP client library being used.
        """
        # Placeholder implementation
        raise NotImplementedError(
            "MCP client forwarding not implemented. "
            "This would depend on the specific MCP client library."
        )

    def validate_server_access(self, server_name: str) -> bool:
        """
        Validate if access to a specific MCP server is allowed.

        Args:
            server_name: Name of the MCP server

        Returns:
            True if access is allowed, False otherwise
        """
        # Define blocklist of servers that should never be accessed
        blocked_servers = [
            "system",
            "admin",
            "root",
            "sudo",
        ]

        if server_name.lower() in blocked_servers:
            logger.warning(f"Access to server '{server_name}' is blocked")
            return False

        return True


# FastMCP tool function for the passthrough
async def mcp_passthrough(
    server_name: str,
    tool_name: str,
    parameters: dict[str, Any] | None = None,
    security_context: str | None = None,
) -> str:
    """
    Execute an MCP tool call through the security passthrough.

    This tool acts as a security layer between the LLM and MCP servers,
    intercepting calls and adding security constraints.

    Args:
        server_name: Name of the target MCP server
        tool_name: Name of the tool to call on the MCP server
        parameters: Parameters to pass to the tool (default: empty dict)
        security_context: Additional security constraints for this call

    Returns:
        JSON string with the result or security rejection
    """
    if parameters is None:
        parameters = {}

    passthrough = MCPPassthrough()

    # Validate server access
    if not passthrough.validate_server_access(server_name):
        return json.dumps(
            {
                "status": "blocked",
                "reason": f"Access to server '{server_name}' is not allowed",
            },
            indent=2,
        )

    # Execute with security checks
    result = await passthrough.execute_with_security(
        server_name=server_name,
        tool_name=tool_name,
        parameters=parameters,
        security_context=security_context,
    )

    return json.dumps(result, indent=2)
