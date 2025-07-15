"""Tests for HTTP transport functionality."""

import json

import httpx
import pytest

from vulnicheck.mcp_client import HTTPTransport, MCPClient, MCPConnection
from vulnicheck.mcp_config_cache import MCPServerConfig


class TestHTTPTransport:
    """Test HTTP transport implementation."""

    @pytest.mark.asyncio
    async def test_connect(self) -> None:
        """Test connecting to HTTP server."""
        transport = HTTPTransport("https://example.com/mcp")
        await transport.connect()

        assert transport.client is not None
        assert transport.url == "https://example.com/mcp"

        await transport.close()

    @pytest.mark.asyncio
    async def test_request_success(self, httpx_mock) -> None:
        """Test successful request."""
        transport = HTTPTransport("https://example.com/mcp")
        await transport.connect()

        # Mock successful response
        response_data = {
            "jsonrpc": "2.0",
            "id": "test-id",
            "result": {"tools": [{"name": "test_tool"}]}
        }
        httpx_mock.add_response(json=response_data)

        # Patch uuid to return predictable ID
        from unittest.mock import patch
        with patch("vulnicheck.mcp_client.uuid4", return_value="test-id"):
            result = await transport.request("tools/list", None)
            assert result == response_data

        await transport.close()

    @pytest.mark.asyncio
    async def test_request_http_error(self, httpx_mock) -> None:
        """Test request with HTTP error."""
        transport = HTTPTransport("https://example.com/mcp")
        await transport.connect()

        # Mock error response
        httpx_mock.add_response(status_code=500)

        result = await transport.request("tools/list", None)
        assert "error" in result
        assert result["error"]["code"] == -32603

        await transport.close()

    @pytest.mark.asyncio
    async def test_notify(self, httpx_mock) -> None:
        """Test notification."""
        transport = HTTPTransport("https://example.com/mcp")
        await transport.connect()

        # Mock successful response
        httpx_mock.add_response()

        # Should not raise
        await transport.notify("initialized", {})

        await transport.close()

    @pytest.mark.asyncio
    async def test_close(self) -> None:
        """Test closing transport."""
        transport = HTTPTransport("https://example.com/mcp")
        await transport.connect()

        assert transport.client is not None
        await transport.close()
        assert transport.client is None
        assert transport._closed


class TestMCPClientHTTPIntegration:
    """Test MCPClient with HTTP transport."""

    @pytest.mark.asyncio
    async def test_connect_http_server(self, httpx_mock) -> None:
        """Test connecting to HTTP MCP server."""
        # Mock server responses - using a matcher function instead of ANY
        def match_any_uuid(request):
            """Match any request and return appropriate response based on method."""
            json_body = json.loads(request.content)
            if json_body.get("method") == "initialize":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": json_body["id"],
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {"tools": {}}
                        }
                    }
                )
            elif json_body.get("method") == "tools/list":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": json_body["id"],
                        "result": {
                            "tools": [
                                {
                                    "name": "test_tool",
                                    "description": "Test tool",
                                    "inputSchema": {"type": "object"}
                                }
                            ]
                        }
                    }
                )
            else:
                # For notifications
                return httpx.Response(200)

        # Use non_mocked_hosts to allow all requests, then handle them with callback
        httpx_mock.non_mocked_hosts = []  # Mock all hosts

        # Add callback that will be reused for all requests
        httpx_mock.add_callback(match_any_uuid, is_reusable=True)

        # Create config
        config = MCPServerConfig(
            transport="http",
            url="https://example.com/mcp"
        )

        # Connect
        client = MCPClient()
        connection = await client.connect("test_server", config)

        assert isinstance(connection, MCPConnection)
        assert connection.server_name == "test_server"
        assert "test_tool" in connection.tools

        await client.close_all()

    @pytest.mark.asyncio
    async def test_connect_http_no_url(self) -> None:
        """Test connecting to HTTP server without URL."""
        config = MCPServerConfig(
            transport="http"
        )

        client = MCPClient()
        with pytest.raises(ValueError, match="HTTP transport requires 'url' configuration"):
            await client.connect("test_server", config)
