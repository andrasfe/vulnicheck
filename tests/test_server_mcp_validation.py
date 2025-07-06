"""Simple tests for the new MCP validation API."""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# Import the actual function
import vulnicheck.server

validate_mcp_security_func = vulnicheck.server.validate_mcp_security.fn


@pytest.mark.asyncio
async def test_validate_mcp_security_unknown_agent():
    """Test validation with unknown agent name."""
    mock_validator = AsyncMock()
    with (
        patch("vulnicheck.server.mcp_validator", mock_validator),
        patch("vulnicheck.server._ensure_clients_initialized"),
    ):
        result = await validate_mcp_security_func(
            agent_name="unknown_agent", mode="scan", local_only=True
        )

    assert "Unknown agent 'unknown_agent'" in result
    assert "Valid agents:" in result


@pytest.mark.asyncio
async def test_validate_mcp_security_custom_config_no_issues():
    """Test validation with custom config path - no issues."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.return_value = {
        "server_count": 1,
        "issue_count": 0,
        "issues": [],
    }

    # Create a real temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        config = {"mcpServers": {"test": {"command": "test"}}}
        f.write(json.dumps(config))
        f.flush()
        temp_path = f.name

    try:
        with (
            patch("vulnicheck.server.mcp_validator", mock_validator),
            patch("vulnicheck.server._ensure_clients_initialized"),
        ):
            result = await validate_mcp_security_func(
                agent_name="custom", config_path=temp_path, mode="scan", local_only=True
            )

        assert "No security issues detected" in result
        assert "Your MCP configuration appears to be secure" in result
        assert temp_path in result  # Should show the scanned file
        mock_validator.validate_config.assert_called_once()
    finally:
        Path(temp_path).unlink()


@pytest.mark.asyncio
async def test_validate_mcp_security_custom_config_with_issues():
    """Test validation with custom config path - has issues."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.return_value = {
        "server_count": 1,
        "issue_count": 1,
        "issues": [
            {
                "severity": "HIGH",
                "title": "Dangerous command",
                "server": "risky-server",
                "description": "Uses bash command",
                "recommendation": "Review this server",
            }
        ],
    }

    # Create a real temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        config = {
            "mcpServers": {"risky": {"command": "bash", "args": ["-c", "echo test"]}}
        }
        f.write(json.dumps(config))
        f.flush()
        temp_path = f.name

    try:
        with (
            patch("vulnicheck.server.mcp_validator", mock_validator),
            patch("vulnicheck.server._ensure_clients_initialized"),
        ):
            result = await validate_mcp_security_func(
                agent_name="custom", config_path=temp_path, mode="scan"
            )

        assert "HIGH Severity Issues (1)" in result
        assert "Dangerous command" in result
        assert "HIGH RISK DETECTED" in result
        assert temp_path in result  # Should show which file has the issue
    finally:
        Path(temp_path).unlink()


@pytest.mark.asyncio
async def test_validate_mcp_security_output_includes_agent():
    """Test that output includes the agent name."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.return_value = {
        "server_count": 1,
        "issue_count": 0,
        "issues": [],
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        config = {"mcpServers": {"test": {"command": "test"}}}
        f.write(json.dumps(config))
        f.flush()
        temp_path = f.name

    try:
        with (
            patch("vulnicheck.server.mcp_validator", mock_validator),
            patch("vulnicheck.server._ensure_clients_initialized"),
        ):
            result = await validate_mcp_security_func(
                agent_name="cursor", config_path=temp_path, mode="scan"
            )

        assert "Agent: cursor" in result
        assert "## Configuration Files Scanned" in result
        assert temp_path in result
    finally:
        Path(temp_path).unlink()


@pytest.mark.asyncio
async def test_validate_mcp_security_no_config_found():
    """Test when no config files are found for an agent."""
    mock_validator = AsyncMock()

    with (
        patch("vulnicheck.server.mcp_validator", mock_validator),
        patch("vulnicheck.server._ensure_clients_initialized"),
        tempfile.TemporaryDirectory() as temp_dir,
        patch("vulnicheck.server.Path.home", return_value=Path(temp_dir)),
        patch("vulnicheck.server.Path.cwd", return_value=Path(temp_dir)),
    ):
        result = await validate_mcp_security_func(agent_name="claude", mode="scan")

    assert "No MCP configuration found for claude" in result
    assert "Searched locations:" in result
