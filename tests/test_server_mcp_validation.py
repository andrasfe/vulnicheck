"""Tests for MCP validation tool in server.py."""

from unittest.mock import AsyncMock, patch

import pytest

# Import the actual function, not the decorated one
import vulnicheck.server

# Get the actual function from the decorated tool
validate_mcp_security_func = vulnicheck.server.validate_mcp_security.fn


@pytest.mark.asyncio
async def test_validate_mcp_security_no_issues():
    """Test validation with no security issues found."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.return_value = {
        "server_count": 2,
        "issue_count": 0,
        "issues": []
    }

    with patch("vulnicheck.server.mcp_validator", mock_validator), patch("vulnicheck.server._ensure_clients_initialized"):
            result = await validate_mcp_security_func(mode="scan", local_only=True)

    assert "No security issues detected" in result
    assert "Your MCP configuration appears to be secure" in result
    assert "LOW RISK" in result
    mock_validator.validate_config.assert_called_once_with(
        config_json=None,
        mode="scan"
    )


@pytest.mark.asyncio
async def test_validate_mcp_security_critical_issues():
    """Test validation with critical security issues."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.return_value = {
        "server_count": 1,
        "issue_count": 2,
        "issues": [
            {
                "severity": "CRITICAL",
                "title": "Malicious server detected",
                "server": "evil-server",
                "description": "This server is known to be malicious",
                "recommendation": "Remove immediately"
            },
            {
                "severity": "HIGH",
                "title": "Prompt injection risk",
                "server": "vulnerable-server",
                "description": "Tool descriptions contain injection attempts",
                "recommendation": "Review and sanitize"
            }
        ]
    }

    with patch("vulnicheck.server.mcp_validator", mock_validator), patch("vulnicheck.server._ensure_clients_initialized"):
            result = await validate_mcp_security_func(mode="scan", local_only=True)

    assert "CRITICAL Severity Issues (1)" in result
    assert "HIGH Severity Issues (1)" in result
    assert "Malicious server detected" in result
    assert "HIGH RISK DETECTED" in result
    assert "Do NOT perform sensitive operations" in result


@pytest.mark.asyncio
async def test_validate_mcp_security_medium_issues():
    """Test validation with medium severity issues."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.return_value = {
        "server_count": 3,
        "issue_count": 1,
        "issues": [
            {
                "severity": "MEDIUM",
                "title": "Suspicious tool behavior",
                "server": "questionable-server",
                "description": "Tool has unusual permissions",
                "recommendation": "Review tool permissions"
            }
        ]
    }

    with patch("vulnicheck.server.mcp_validator", mock_validator), patch("vulnicheck.server._ensure_clients_initialized"):
            result = await validate_mcp_security_func(mode="inspect", local_only=False)

    assert "MEDIUM Severity Issues (1)" in result
    assert "MODERATE RISK DETECTED" in result
    assert "Exercise caution with file operations" in result
    mock_validator.local_only = False  # Check that setting was updated


@pytest.mark.asyncio
async def test_validate_mcp_security_with_error():
    """Test validation when an error occurs."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.return_value = {
        "error": "Failed to connect to MCP server",
        "server_count": 0,
        "issue_count": 0,
        "issues": []
    }

    with patch("vulnicheck.server.mcp_validator", mock_validator), patch("vulnicheck.server._ensure_clients_initialized"):
            result = await validate_mcp_security_func(mode="scan")

    assert "Validation Error" in result
    assert "Failed to connect to MCP server" in result


@pytest.mark.asyncio
async def test_validate_mcp_security_with_config_json():
    """Test validation with JSON configuration."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.return_value = {
        "server_count": 1,
        "issue_count": 0,
        "issues": []
    }

    config_json = '{"mcpServers": {"test": {"command": "test"}}}'

    with patch("vulnicheck.server.mcp_validator", mock_validator), patch("vulnicheck.server._ensure_clients_initialized"):
            await validate_mcp_security_func(
                mode="scan",
                config_json=config_json,
                local_only=True
            )

    mock_validator.validate_config.assert_called_once_with(
        config_json=config_json,
        mode="scan"
    )


@pytest.mark.asyncio
async def test_validate_mcp_security_exception_handling():
    """Test validation when an exception is raised."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.side_effect = Exception("Unexpected error")

    with patch("vulnicheck.server.mcp_validator", mock_validator), patch("vulnicheck.server._ensure_clients_initialized"):
            result = await validate_mcp_security_func(mode="scan")

    assert "Error during MCP security validation" in result
    assert "Unexpected error" in result
    assert "mcp-scan is not properly installed" in result


@pytest.mark.asyncio
async def test_validate_mcp_security_mixed_severities():
    """Test validation with mixed severity issues."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.return_value = {
        "server_count": 4,
        "issue_count": 5,
        "issues": [
            {"severity": "LOW", "title": "Info leak", "server": "s1", "description": "Minor info"},
            {"severity": "MEDIUM", "title": "Suspicious", "server": "s2", "description": "Hmm"},
            {"severity": "HIGH", "title": "Dangerous", "server": "s3", "description": "Bad"},
            {"severity": "MEDIUM", "title": "Suspicious2", "server": "s4", "description": "Hmm2"},
            {"severity": "UNKNOWN", "title": "Unknown", "server": "s5", "description": "???"},
        ]
    }

    with patch("vulnicheck.server.mcp_validator", mock_validator), patch("vulnicheck.server._ensure_clients_initialized"):
            result = await validate_mcp_security_func(mode="scan")

    # Should prioritize HIGH severity
    assert "HIGH RISK DETECTED" in result
    assert "HIGH Severity Issues (1)" in result
    assert "MEDIUM Severity Issues (2)" in result
    assert "LOW Severity Issues (1)" in result
    # UNKNOWN severity should not appear in the grouped output


@pytest.mark.asyncio
async def test_validate_mcp_security_output_format():
    """Test the output format of the validation report."""
    mock_validator = AsyncMock()
    mock_validator.validate_config.return_value = {
        "server_count": 1,
        "issue_count": 0,
        "issues": []
    }

    with patch("vulnicheck.server.mcp_validator", mock_validator), patch("vulnicheck.server._ensure_clients_initialized"):
            result = await validate_mcp_security_func(mode="scan", local_only=True)

    # Check for expected sections
    assert "# MCP Security Self-Validation Report" in result
    assert "## Summary" in result
    assert "## Self-Assessment Guidelines" in result
    assert "## When to Use This Validation" in result
    assert "## About MCP-Scan" in result

    # Check metadata
    assert "Mode: scan" in result
    assert "Local Only: True" in result
    assert "Date:" in result
