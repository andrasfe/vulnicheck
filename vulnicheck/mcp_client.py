"""
MCP Client Implementation.

This module provides a generic MCP client that can connect to any MCP server
using various transport mechanisms (stdio, HTTP).

Why Custom Implementation Instead of Official MCP SDK?
----------------------------------------------------
While the official Anthropic MCP SDK provides excellent functionality including
persistent connections and high-level abstractions, we need a custom implementation
for the following reasons:

1. **HTTP Transport Compatibility**: Some MCP servers (like context7) respond to
   regular HTTP POST requests with SSE-formatted responses (event/data format).
   The SDK has separate SSE and StreamableHTTP clients, but neither handles this
   correctly:
   - SSE client expects a continuous event stream (hangs on single responses)
   - StreamableHTTP client expects plain JSON responses (can't parse SSE format)

2. **Unified Transport Interface**: Vulnicheck needs to dynamically connect to
   servers with different transport types based on configuration. Our implementation
   provides a single interface that automatically handles stdio, HTTP, and HTTP+SSE.

3. **Connection Pool Management**: As a passthrough server, vulnicheck maintains
   connections to multiple MCP servers simultaneously. While the SDK supports
   persistent connections, our custom pool management is optimized for the
   passthrough use case.

4. **Error Recovery**: Our implementation includes specific error handling for
   the quirks of various MCP servers we need to support.

This custom implementation provides:
- Unified MCPClient for managing persistent connections
- Support for both stdio and HTTP transports (with automatic SSE parsing)
- Single interface regardless of transport type
- Connection pooling optimized for passthrough operations
- Proper handling of servers that return SSE for regular HTTP requests
"""

import asyncio
import contextlib
import json
import logging
import os
from asyncio import StreamReader, StreamWriter
from asyncio.subprocess import Process
from typing import Any
from uuid import uuid4

import httpx
from pydantic import BaseModel

from .mcp_config_cache import MCPServerConfig

logger = logging.getLogger(__name__)


class MCPTool(BaseModel):
    """MCP tool definition."""

    name: str
    description: str
    inputSchema: dict[str, Any]


class MCPMessage(BaseModel):
    """MCP protocol message."""

    jsonrpc: str = "2.0"
    id: str | None = None
    method: str | None = None
    params: dict[str, Any] | None = None
    result: Any | None = None
    error: dict[str, Any] | None = None


class MCPConnection:
    """Represents a connection to an MCP server."""

    def __init__(self, server_name: str, transport: "MCPTransport"):
        self.server_name = server_name
        self.transport = transport
        self.tools: dict[str, MCPTool] = {}
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the connection and discover capabilities."""
        if self._initialized:
            return

        # Send initialize request
        response = await self.transport.request(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                "clientInfo": {
                    "name": "vulnicheck-mcp-passthrough",
                    "version": "1.0.0",
                },
            },
        )

        if "error" in response:
            raise Exception(f"Initialization failed: {response['error']}")

        # Send initialized notification (required by MCP protocol)
        await self.transport.notify("notifications/initialized", None)

        self._initialized = True
        logger.info(f"Initialized connection to {self.server_name}")

    async def discover_tools(self) -> dict[str, MCPTool]:
        """Discover available tools from the server."""
        if not self._initialized:
            await self.initialize()

        # Use the correct MCP method name: "tools/list"
        # MCP expects None or PaginatedRequestParams for tools/list
        response = await self.transport.request("tools/list", None)

        if "error" in response:
            raise Exception(f"Tool discovery failed: {response['error']}")

        # Parse tools
        self.tools = {}
        for tool_data in response.get("result", {}).get("tools", []):
            tool = MCPTool(**tool_data)
            self.tools[tool.name] = tool

        logger.info(f"Discovered {len(self.tools)} tools from {self.server_name}")
        return self.tools

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """Call a tool on the MCP server."""
        if not self._initialized:
            await self.initialize()

        if tool_name not in self.tools:
            # Try to discover tools if not cached
            await self.discover_tools()
            if tool_name not in self.tools:
                raise ValueError(
                    f"Tool '{tool_name}' not found on server '{self.server_name}'"
                )

        # Use the correct MCP method name: "tools/call"
        response = await self.transport.request(
            "tools/call", {"name": tool_name, "arguments": arguments}
        )

        if "error" in response:
            raise Exception(f"Tool call failed: {response['error']}")

        return response.get("result")

    async def close(self) -> None:
        """Close the connection."""
        await self.transport.close()


class MCPTransport:
    """Base class for MCP transport mechanisms."""

    async def request(
        self, method: str, params: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Send a request and wait for response."""
        raise NotImplementedError

    async def notify(self, method: str, params: dict[str, Any] | None) -> None:
        """Send a notification (no response expected)."""
        raise NotImplementedError

    async def close(self) -> None:
        """Close the transport."""
        raise NotImplementedError


class StdioTransport(MCPTransport):
    """MCP transport over stdio (stdin/stdout)."""

    def __init__(self) -> None:
        self.process: Process | None = None
        self.reader: StreamReader | None = None
        self.writer: StreamWriter | None = None
        self._read_task: asyncio.Task | None = None
        self._pending_requests: dict[str, asyncio.Future] = {}
        self._closed = False

    async def connect(
        self,
        command: str,
        args: list[str],
        env: dict[str, str],
        cwd: str | None = None,
    ) -> None:
        """Connect to an MCP server via stdio."""
        try:
            # Prepare environment
            full_env = os.environ.copy()
            full_env.update(env)

            # Start the process with increased buffer limit for large responses
            # Zen server can send very large tool lists
            self.process = await asyncio.create_subprocess_exec(
                command,
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=full_env,
                cwd=cwd,
                limit=1024 * 1024,  # 1MB limit for stdout buffer
            )

            if self.process.stdin is None or self.process.stdout is None:
                raise RuntimeError("Failed to create process pipes")

            logger.info(f"Started MCP server process: {command} {' '.join(args)}")

            # Start reading from stdout
            self._read_task = asyncio.create_task(self._read_loop())

        except Exception as e:
            logger.error(f"Failed to connect to MCP server: {e}")
            raise

    async def _read_loop(self) -> None:
        """Read messages from stdout."""
        if not self.process or not self.process.stdout:
            return

        try:
            while not self._closed:
                # Read line by line
                # Buffer limit is set on subprocess creation to handle large responses
                line = await self.process.stdout.readuntil(b"\n")
                if not line:
                    break

                try:
                    # Parse JSON-RPC message
                    message = json.loads(line.decode("utf-8").strip())
                    await self._handle_message(message)
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON received: {e}")
                except Exception as e:
                    logger.error(f"Error handling message: {e}")

        except Exception as e:
            if not isinstance(e, asyncio.CancelledError):
                logger.error(f"Read loop error: {e}")

    async def _handle_message(self, message: dict[str, Any]) -> None:
        """Handle an incoming message."""
        msg_id = message.get("id")
        logger.debug(f"Received message: {message}")

        if msg_id and msg_id in self._pending_requests:
            # This is a response to our request
            future = self._pending_requests.pop(msg_id)
            if not future.cancelled():
                future.set_result(message)
        else:
            # This is a notification or request from server
            logger.debug(f"Received notification/request: {message}")

    async def request(
        self, method: str, params: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Send a request and wait for response."""
        if self._closed or not self.process or not self.process.stdin:
            raise RuntimeError("Transport is closed")

        # Create request message
        msg_id = str(uuid4())

        # Build message dict - always include params
        message_dict = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": method,
            "params": params if params is not None else {},
        }

        # Create future for response
        future: asyncio.Future[dict[str, Any]] = asyncio.Future()
        self._pending_requests[msg_id] = future

        try:
            # Send request
            message_str = json.dumps(message_dict) + "\n"
            logger.debug(f"Sending request: {message_str.strip()}")
            # Type assertion: stdin is not None after successful connection
            stdin = self.process.stdin
            stdin.write(message_str.encode("utf-8"))
            await stdin.drain()

            # Wait for response with timeout
            response = await asyncio.wait_for(future, timeout=30.0)
            return response

        except asyncio.TimeoutError:
            self._pending_requests.pop(msg_id, None)
            raise TimeoutError(f"Request '{method}' timed out") from None
        except Exception:
            self._pending_requests.pop(msg_id, None)
            raise

    async def notify(self, method: str, params: dict[str, Any] | None) -> None:
        """Send a notification (no response expected)."""
        if self._closed or not self.process or not self.process.stdin:
            raise RuntimeError("Transport is closed")

        # Build notification message - always include params like in request
        message_dict = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params if params is not None else {},
        }

        message_str = json.dumps(message_dict) + "\n"
        logger.debug(f"Sending notification: {message_str.strip()}")
        # Type assertion: stdin is not None after successful connection
        stdin = self.process.stdin
        stdin.write(message_str.encode("utf-8"))
        await stdin.drain()

    async def close(self) -> None:
        """Close the transport."""
        if self._closed:
            return

        self._closed = True

        # Cancel read task
        if self._read_task:
            self._read_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._read_task

        # Cancel pending requests
        for future in self._pending_requests.values():
            if not future.done():
                future.cancel()
        self._pending_requests.clear()

        # Terminate process
        if self.process:
            try:
                self.process.terminate()
                # process.wait() is already a coroutine for asyncio.subprocess.Process
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.process.kill()
                # process.wait() is already a coroutine
                await self.process.wait()

            logger.info("Closed MCP server process")


class HTTPTransport(MCPTransport):
    """MCP transport over HTTP.

    This transport handles HTTP-based MCP servers that may return responses in
    different formats:
    - Standard JSON responses
    - SSE-formatted responses (Server-Sent Events format) for regular POST requests

    The implementation handles:
    - Proper Accept headers for content negotiation
    - Parsing SSE-formatted responses (event/data format) from regular HTTP responses
    - URL handling without trailing slashes (httpx quirk)
    - Persistent connection via httpx.AsyncClient

    Note: This is NOT an SSE streaming connection. Servers like context7 return
    single HTTP responses that use SSE formatting (event: message, data: {...}).
    The SDK's SSE client expects continuous event streams, while the StreamableHTTP
    client expects plain JSON, so neither handles this hybrid format correctly.
    """

    def __init__(self, url: str) -> None:
        # Remove trailing slash to avoid httpx adding another one
        self.url = url.rstrip("/")
        self.client: httpx.AsyncClient | None = None
        self._closed = False

    async def connect(self) -> None:
        """Connect to an HTTP MCP server."""
        if self.client is None:
            # Don't use base_url to avoid trailing slash issues
            self.client = httpx.AsyncClient(
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
                timeout=httpx.Timeout(30.0),
            )
            logger.info(f"Connected to HTTP MCP server at {self.url}")

    def _parse_sse_response(self, text: str) -> dict[str, Any]:
        """Parse Server-Sent Events formatted response to extract JSON data.

        Some MCP servers (like context7) return responses in SSE format even for
        regular HTTP POST requests. This is NOT a streaming SSE connection - it's
        a single HTTP response that happens to use SSE formatting.

        SSE format example:
            event: message
            data: {"jsonrpc": "2.0", "id": "123", "result": {...}}

        We extract the JSON from the 'data:' line.
        """
        lines = text.strip().split('\n')
        for line in lines:
            if line.startswith('data:'):
                # Extract JSON from data field
                data_content = line[5:].strip()
                if data_content:
                    return dict(json.loads(data_content))
        # If no data found, raise error
        raise ValueError(f"No data found in SSE response: {text}")

    async def request(
        self, method: str, params: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Send a request and wait for response."""
        if self._closed or not self.client:
            raise RuntimeError("Transport is closed")

        # Build request message
        request_id = str(uuid4())
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params if params is not None else {},
        }

        logger.debug(f"Sending HTTP request: {json.dumps(message)}")
        logger.debug(f"URL: {self.url}")

        try:
            # Send POST request to the full URL
            response = await self.client.post(
                self.url,
                json=message,
            )
            response.raise_for_status()

            # Parse response - handle both JSON and SSE formats
            content_type = response.headers.get("content-type", "")

            if "text/event-stream" in content_type or response.text.startswith("event:"):
                # Parse SSE response
                result = self._parse_sse_response(response.text)
            else:
                # Parse regular JSON response
                result = response.json()

            logger.debug(f"Received HTTP response: {json.dumps(result)}")

            if result.get("id") != request_id:
                raise ValueError(f"Response ID mismatch: {result.get('id')} != {request_id}")

            return dict(result)

        except httpx.HTTPError as e:
            logger.error(f"HTTP request failed: {e}")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": f"HTTP request failed: {str(e)}",
                },
            }

    async def notify(self, method: str, params: dict[str, Any] | None) -> None:
        """Send a notification (no response expected)."""
        if self._closed or not self.client:
            raise RuntimeError("Transport is closed")

        # Build notification message (no id for notifications)
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params if params is not None else {},
        }

        logger.debug(f"Sending HTTP notification: {json.dumps(message)}")

        try:
            # Send POST request (fire and forget)
            response = await self.client.post(
                self.url,
                json=message,
            )
            response.raise_for_status()
        except httpx.HTTPError as e:
            logger.error(f"HTTP notification failed: {e}")

    async def close(self) -> None:
        """Close the transport."""
        if self._closed:
            return

        self._closed = True

        if self.client:
            await self.client.aclose()
            self.client = None
            logger.info("Closed HTTP MCP client")


class MCPClient:
    """High-level MCP client.

    This client manages persistent connections to multiple MCP servers and provides
    a unified interface for tool discovery and execution.

    Architecture:
    - Maintains a pool of persistent connections (self._connections)
    - Dynamically selects transport based on server configuration
    - Handles connection lifecycle (connect, initialize, close)
    - Provides high-level methods for common operations

    This design is necessary because:
    1. Vulnicheck acts as a passthrough server that proxies requests to other MCP servers
    2. Each incoming request may target a different MCP server
    3. Creating a new connection for each request would be inefficient
    4. The official SDK's context manager approach doesn't support connection pooling

    Example usage:
        client = MCPClient()
        connection = await client.connect("server_name", config)
        result = await connection.call_tool("tool_name", {"arg": "value"})
    """

    def __init__(self) -> None:
        self._connections: dict[str, MCPConnection] = {}

    async def connect(self, server_name: str, config: MCPServerConfig) -> MCPConnection:
        """Connect to an MCP server."""
        if server_name in self._connections:
            return self._connections[server_name]

        # Create transport based on type
        transport: MCPTransport
        if config.transport == "stdio":
            if not config.command:
                raise ValueError("Stdio transport requires 'command' configuration")
            transport = StdioTransport()
            await transport.connect(
                command=config.command, args=config.args, env=config.env, cwd=config.cwd
            )
        elif config.transport == "http":
            if not config.url:
                raise ValueError("HTTP transport requires 'url' configuration")
            http_transport = HTTPTransport(config.url)
            await http_transport.connect()
            transport = http_transport
        else:
            raise NotImplementedError(
                f"Transport '{config.transport}' not yet implemented"
            )

        # Create connection
        connection = MCPConnection(server_name, transport)
        await connection.initialize()
        await connection.discover_tools()

        self._connections[server_name] = connection
        return connection

    async def get_connection(self, server_name: str) -> MCPConnection | None:
        """Get an existing connection."""
        return self._connections.get(server_name)

    async def close_connection(self, server_name: str) -> None:
        """Close a specific connection."""
        if server_name in self._connections:
            await self._connections[server_name].close()
            del self._connections[server_name]

    async def close_all(self) -> None:
        """Close all connections."""
        for connection in list(self._connections.values()):
            await connection.close()
        self._connections.clear()
