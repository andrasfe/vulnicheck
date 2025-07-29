"""
Unified MCP Passthrough Tool with real MCP client integration.

This module provides a single passthrough mechanism that intercepts MCP server calls,
adds security prompts, and can optionally connect to real MCP servers.
"""

import asyncio
import json
import logging
import os
from typing import Any

from pydantic import BaseModel, Field

from ..core.agent_detector import detect_agent
from ..core.logging_config import configure_mcp_logging
from ..security.dangerous_commands_config import get_dangerous_commands_config
from .conversation_storage import ConversationStorage
from .mcp_client import MCPClient, MCPConnection
from .mcp_config_cache import MCPConfigCache

logger = logging.getLogger(__name__)

# Create a separate logger for MCP interactions
interaction_logger = logging.getLogger("vulnicheck.mcp_interactions")


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


class MCPConnectionPool:
    """Manages a pool of MCP server connections."""

    def __init__(self, config_cache: MCPConfigCache, mcp_client: MCPClient):
        self.config_cache = config_cache
        self.mcp_client = mcp_client
        self._connections: dict[tuple[str, str], MCPConnection] = {}
        self._lock = asyncio.Lock()

    async def get_connection(self, agent_name: str, server_name: str) -> MCPConnection:
        """Get or create a connection to an MCP server."""
        key = (agent_name, server_name)

        async with self._lock:
            # Check if we have an active connection
            if key in self._connections:
                connection = self._connections[key]
                # TODO: Add health check here
                return connection

            # Get server configuration
            config = await self.config_cache.get_server_config(agent_name, server_name)
            if not config:
                raise ValueError(
                    f"Server '{server_name}' not found in {agent_name} configuration"
                )

            # Create new connection
            try:
                connection = await self.mcp_client.connect(server_name, config)
                self._connections[key] = connection
                return connection
            except Exception as e:
                logger.error(f"Failed to connect to {server_name}: {e}")
                raise

    async def close_connection(self, agent_name: str, server_name: str) -> None:
        """Close a specific connection."""
        key = (agent_name, server_name)
        async with self._lock:
            if key in self._connections:
                await self._connections[key].close()
                del self._connections[key]

    async def close_all(self) -> None:
        """Close all connections."""
        async with self._lock:
            for connection in self._connections.values():
                try:
                    await connection.close()
                except Exception as e:
                    logger.error(f"Error closing connection: {e}")
            self._connections.clear()


class MCPPassthrough:
    """
    Unified passthrough handler for MCP server calls with security enforcement.

    This class intercepts MCP server tool calls, adds security prompts,
    and can optionally forward calls to real MCP servers.
    """

    def __init__(
        self, agent_name: str | None = None, enable_real_connections: bool | None = None
    ):
        """
        Initialize the passthrough handler.

        Args:
            agent_name: Name of the agent (claude, cursor, etc.). If not provided,
                       will attempt to auto-detect using shared detector.
            enable_real_connections: Whether to enable real MCP connections.
                                   If None, will check MCP_PASSTHROUGH_ENHANCED env var.
        """
        # Detect agent using shared detector
        self.agent_name = detect_agent(agent_name)
        logger.info(f"Initialized MCP passthrough for agent: {self.agent_name}")

        # Configure MCP interaction logging
        log_dir = os.path.expanduser("~/.vulnicheck/logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "mcp_interactions.log")

        # Configure logging with both file and console output
        configure_mcp_logging(
            log_file=log_file,
            log_level=os.environ.get("VULNICHECK_LOG_LEVEL", "INFO"),
            enable_console=os.environ.get("VULNICHECK_LOG_CONSOLE", "false").lower() == "true"
        )

        interaction_logger.info(f"MCP passthrough initialized for {self.agent_name}", extra={
            "event": "passthrough_init",
            "agent": self.agent_name,
            "log_file": log_file
        })

        # Determine if we should enable real connections
        if enable_real_connections is None:
            enable_real_connections = (
                os.environ.get("MCP_PASSTHROUGH_ENHANCED", "true").lower() == "true"
            )

        self.enable_real_connections = enable_real_connections

        # Declare attributes with proper types
        self.config_cache: MCPConfigCache | None = None
        self.mcp_client: MCPClient | None = None
        self.connection_pool: MCPConnectionPool | None = None

        # Initialize MCP components if real connections are enabled
        if self.enable_real_connections:
            try:
                self.config_cache = MCPConfigCache()
                self.mcp_client = MCPClient()
                self.connection_pool = MCPConnectionPool(
                    self.config_cache, self.mcp_client
                )
                logger.info("Real MCP connections enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize MCP components: {e}")
                logger.warning("Falling back to mock mode")
                self.enable_real_connections = False
                self.config_cache = None
                self.mcp_client = None
                self.connection_pool = None
        else:
            logger.info("Running in mock mode (no real MCP connections)")

        # Conversation storage will be initialized on first use
        self._conversation_storage: ConversationStorage | None = None
        self._active_conversations: dict[str, str] = {}  # server -> conversation_id

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

    def _get_conversation_storage(self) -> ConversationStorage:
        """Get or create conversation storage on demand."""
        if self._conversation_storage is None:
            self._conversation_storage = ConversationStorage()
        return self._conversation_storage

    def _get_or_create_conversation(self, server_name: str) -> str:
        """Get or create a conversation for a server."""
        if server_name in self._active_conversations:
            return self._active_conversations[server_name]

        storage = self._get_conversation_storage()

        # Try to get an active conversation
        conv = storage.get_active_conversation(self.agent_name, server_name)
        if conv:
            self._active_conversations[server_name] = conv.id
            return conv.id

        # Create a new conversation
        conv = storage.start_conversation(
            client=self.agent_name,
            server=server_name,
            metadata={"passthrough_mode": "basic"}
        )
        self._active_conversations[server_name] = conv.id
        return conv.id

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
        # Get or create conversation
        conversation_id = self._get_or_create_conversation(server_name)
        storage = self._get_conversation_storage()

        # Log request to conversation
        storage.add_request(
            conversation_id=conversation_id,
            client=self.agent_name,
            server=server_name,
            tool=tool_name,
            parameters=parameters
        )

        # Log the incoming request
        interaction_logger.info(
            "MCP_REQUEST",
            extra={
                "event": "mcp_request",
                "agent": self.agent_name,
                "server": server_name,
                "tool": tool_name,
                "parameters": parameters,
                "security_context": security_context,
                "has_real_connections": self.enable_real_connections,
            }
        )

        # Build security prompt
        security_prompt = self.security_prompt_template.format(
            server_name=server_name,
            tool_name=tool_name,
            parameters=json.dumps(parameters, indent=2),
            security_context=security_context or "None provided",
        )

        # Get the dangerous commands configuration
        config = get_dangerous_commands_config()

        # Check parameters for dangerous patterns
        param_str = json.dumps(parameters)

        # Check the command/tool name itself
        check_str = f"{server_name} {tool_name} {param_str}"

        # Check for dangerous patterns
        dangerous_match = config.check_dangerous_pattern(check_str)

        if dangerous_match:
            category, pattern_name, matched_text = dangerous_match

            # Log security decision - BLOCKED
            interaction_logger.warning(
                "MCP_SECURITY_BLOCKED",
                extra={
                    "event": "mcp_security_decision",
                    "decision": "blocked",
                    "agent": self.agent_name,
                    "server": server_name,
                    "tool": tool_name,
                    "category": category,
                    "pattern": pattern_name,
                    "matched_text": matched_text,
                    "risk_level": "BLOCKED",
                }
            )

            response = {
                "status": "blocked",
                "reason": f"Operation blocked due to dangerous pattern in category '{category}': {matched_text}",
                "pattern": pattern_name,
                "category": category,
                "security_prompt": security_prompt,
            }

            # Log the response with full details
            interaction_logger.info(
                "MCP_RESPONSE",
                extra={
                    "event": "mcp_response",
                    "agent": self.agent_name,
                    "server": server_name,
                    "tool": tool_name,
                    "status": "blocked",
                    "result": response,
                }
            )

            # Log response to conversation
            storage.add_response(
                conversation_id=conversation_id,
                client=self.agent_name,
                server=server_name,
                tool=tool_name,
                result=response
            )

            return response

        # Log security decision - ALLOWED (no dangerous patterns)
        interaction_logger.info(
            "MCP_SECURITY_ALLOWED",
            extra={
                "event": "mcp_security_decision",
                "decision": "allowed",
                "agent": self.agent_name,
                "server": server_name,
                "tool": tool_name,
                "risk_level": "SAFE",
            }
        )

        # If we have real connections enabled, make the actual call
        if self.enable_real_connections and self.connection_pool:
            try:
                result = await self._forward_to_mcp(server_name, tool_name, parameters)
                response = {
                    "status": "success",
                    "result": result,
                    "security_prompt": security_prompt,
                }

                # Log successful response with full result
                interaction_logger.info(
                    "MCP_RESPONSE",
                    extra={
                        "event": "mcp_response",
                        "agent": self.agent_name,
                        "server": server_name,
                        "tool": tool_name,
                        "status": "success",
                        "result": result,
                        "has_result": result is not None,
                    }
                )

                # Log response to conversation
                storage.add_response(
                    conversation_id=conversation_id,
                    client=self.agent_name,
                    server=server_name,
                    tool=tool_name,
                    result=response
                )

                return response
            except Exception as e:
                logger.error(f"MCP call failed: {e}")

                response = {
                    "status": "error",
                    "error": str(e),
                    "security_prompt": security_prompt,
                }

                # Log error response
                interaction_logger.error(
                    "MCP_RESPONSE_ERROR",
                    extra={
                        "event": "mcp_response",
                        "agent": self.agent_name,
                        "server": server_name,
                        "tool": tool_name,
                        "status": "error",
                        "error": str(e),
                    }
                )

                # Log response to conversation
                storage.add_response(
                    conversation_id=conversation_id,
                    client=self.agent_name,
                    server=server_name,
                    tool=tool_name,
                    result=response,
                    error=str(e)
                )

                return response
        else:
            # Return mock response if no real connections
            mock_response: dict[str, Any] = {
                "status": "mock",
                "message": "Running in mock mode - no real MCP connections",
                "requested_call": {
                    "server": server_name,
                    "tool": tool_name,
                    "parameters": parameters,
                },
                "security_prompt": security_prompt,
            }
            response = mock_response

            # Log mock response with full details
            interaction_logger.info(
                "MCP_RESPONSE",
                extra={
                    "event": "mcp_response",
                    "agent": self.agent_name,
                    "server": server_name,
                    "tool": tool_name,
                    "status": "mock",
                    "result": response,
                }
            )

            # Log response to conversation
            storage.add_response(
                conversation_id=conversation_id,
                client=self.agent_name,
                server=server_name,
                tool=tool_name,
                result=response
            )

            return response

    async def _forward_to_mcp(
        self, server_name: str, tool_name: str, parameters: dict[str, Any]
    ) -> Any:
        """
        Forward the call to the actual MCP server.

        This implementation actually connects to and calls the MCP server.
        """
        if not self.connection_pool:
            raise RuntimeError("Connection pool not initialized")

        try:
            # Get or create connection
            connection = await self.connection_pool.get_connection(
                self.agent_name, server_name
            )

            # Make the actual tool call
            result = await connection.call_tool(tool_name, parameters)

            logger.info(f"Successfully called {server_name}.{tool_name}")
            return result

        except Exception as e:
            logger.error(f"Failed to forward MCP call: {e}")
            raise

    def validate_server_access(self, server_name: str) -> bool:
        """
        Validate if access to a specific MCP server is allowed.

        Args:
            server_name: Name of the MCP server

        Returns:
            True if access is allowed, False otherwise
        """
        # Get the dangerous commands configuration
        config = get_dangerous_commands_config()

        # Check if the server name matches any blocked server patterns
        dangerous_match = config.check_dangerous_pattern(
            server_name, categories=["server"]
        )

        if dangerous_match:
            category, pattern_name, matched_text = dangerous_match
            logger.warning(
                f"Access to server '{server_name}' is blocked - "
                f"matches pattern '{pattern_name}'"
            )
            return False

        return True

    async def get_available_servers(self) -> dict[str, list[str]]:
        """Get list of available servers and their tools."""
        if not self.enable_real_connections or not self.config_cache:
            return {}

        configs = await self.config_cache.get_server_configs(self.agent_name)

        available: dict[str, list[str]] = {}
        for server_name in configs:
            try:
                # Try to get connection and discover tools
                if self.connection_pool is None:
                    available[server_name] = ["<connection pool not initialized>"]
                    continue
                connection = await self.connection_pool.get_connection(
                    self.agent_name, server_name
                )
                tools = await connection.discover_tools()
                available[server_name] = list(tools.keys())
            except Exception as e:
                logger.warning(f"Could not connect to {server_name}: {e}")
                available[server_name] = ["<connection failed>"]

        return available

    async def close(self) -> None:
        """Clean up resources."""
        if self.connection_pool:
            await self.connection_pool.close_all()
        if self.mcp_client:
            await self.mcp_client.close_all()


# Global instance for reuse
_global_passthrough: MCPPassthrough | None = None


async def get_passthrough(agent_name: str | None = None) -> MCPPassthrough:
    """Get or create the global passthrough instance."""
    global _global_passthrough

    if _global_passthrough is None:
        _global_passthrough = MCPPassthrough(agent_name)

    return _global_passthrough


# FastMCP tool function for the passthrough
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
    intercepting calls and adding security constraints. It can optionally
    forward calls to real MCP servers when MCP_PASSTHROUGH_ENHANCED=true.

    Args:
        server_name: Name of the target MCP server
        tool_name: Name of the tool to call on the MCP server
        parameters: Parameters to pass to the tool (default: empty dict)
        security_context: Additional security constraints for this call
        agent_name: Override the detected agent name

    Returns:
        JSON string with the result or security rejection
    """
    if parameters is None:
        parameters = {}

    # Get or create passthrough
    passthrough = await get_passthrough(agent_name)

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
