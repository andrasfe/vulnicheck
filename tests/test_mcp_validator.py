"""Tests for MCP security validation functionality."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnicheck.mcp_validator import MCPValidator


@pytest.fixture
def mock_mcp_scanner():
    """Mock MCPScanner for testing."""
    with patch("vulnicheck.mcp_validator.MCPScanner") as mock:
        # Create async context manager mock
        scanner_instance = AsyncMock()
        scanner_instance.scan = AsyncMock()
        scanner_instance.inspect = AsyncMock()
        scanner_instance.__aenter__ = AsyncMock(return_value=scanner_instance)
        scanner_instance.__aexit__ = AsyncMock(return_value=None)

        # Make the class return the async context manager instance
        mock.return_value = scanner_instance

        yield mock, scanner_instance


@pytest.mark.asyncio
async def test_validate_config_scan_mode(mock_mcp_scanner):
    """Test validation in scan mode."""
    mock_class, mock_instance = mock_mcp_scanner

    # Mock scan results
    mock_instance.scan.return_value = {
        "test-server": {
            "malicious": False,
            "prompt_injection_risk": True,
            "suspicious_tools": [
                {"name": "dangerous_tool", "reason": "Suspicious behavior detected"}
            ]
        }
    }

    validator = MCPValidator(local_only=True)
    results = await validator.validate_config(
        config_paths=["/path/to/config.json"],
        mode="scan"
    )

    assert results["server_count"] == 1
    assert results["issue_count"] == 2
    assert len(results["issues"]) == 2

    # Check that high severity issue was created for prompt injection
    prompt_injection_issues = [
        i for i in results["issues"] if i["severity"] == "HIGH"
    ]
    assert len(prompt_injection_issues) == 1
    assert "prompt injection" in prompt_injection_issues[0]["title"].lower()


@pytest.mark.asyncio
async def test_validate_config_inspect_mode(mock_mcp_scanner):
    """Test validation in inspect mode."""
    mock_class, mock_instance = mock_mcp_scanner

    # Mock inspect results
    mock_instance.inspect.return_value = {
        "servers": ["server1", "server2"]
    }

    validator = MCPValidator(local_only=False)
    results = await validator.validate_config(
        config_paths=["/path/to/config.json"],
        mode="inspect"
    )

    assert results["server_count"] == 2
    assert results["issue_count"] == 0
    assert mock_instance.inspect.called


@pytest.mark.asyncio
async def test_validate_config_malicious_server(mock_mcp_scanner):
    """Test detection of malicious server."""
    mock_class, mock_instance = mock_mcp_scanner

    # Mock scan results with malicious server
    mock_instance.scan.return_value = {
        "evil-server": {
            "malicious": True
        }
    }

    validator = MCPValidator()
    results = await validator.validate_config(
        config_paths=["/path/to/config.json"],
        mode="scan"
    )

    assert results["issue_count"] == 1
    assert results["issues"][0]["severity"] == "CRITICAL"
    assert "malicious" in results["issues"][0]["title"].lower()


@pytest.mark.asyncio
async def test_validate_config_no_config_files():
    """Test behavior when no config files are found."""
    validator = MCPValidator()

    # Mock _detect_config_paths to return empty list
    with patch.object(validator, "_detect_config_paths", return_value=[]):
        results = await validator.validate_config(mode="scan")

    assert results["error"] == "No MCP configuration files found"
    assert results["server_count"] == 0
    assert results["issue_count"] == 0


@pytest.mark.asyncio
async def test_validate_config_error_handling(mock_mcp_scanner):
    """Test error handling during validation."""
    mock_class, mock_instance = mock_mcp_scanner

    # Make scan raise an exception
    mock_instance.scan.side_effect = Exception("Scan failed")

    validator = MCPValidator()
    results = await validator.validate_config(
        config_paths=["/path/to/config.json"],
        mode="scan"
    )

    assert "error" in results
    assert "Scan failed" in results["error"]
    assert results["issue_count"] == 0


def test_detect_config_paths():
    """Test automatic config path detection."""
    validator = MCPValidator()

    # Mock Path.exists to return True for claude config
    with patch("vulnicheck.mcp_validator.Path") as mock_path_class:
        # Create a mock path instance
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.__str__.return_value = "/home/user/.config/claude/claude_desktop_config.json"

        # Make Path() return our mock
        mock_path_class.home.return_value.__truediv__.return_value = mock_path
        mock_path_class.return_value = mock_path

        paths = validator._detect_config_paths()

        # Should find at least one config
        assert len(paths) > 0


def test_format_results_json_string():
    """Test formatting of JSON string results."""
    validator = MCPValidator()

    json_results = json.dumps({
        "servers": ["server1", "server2"]
    })

    formatted = validator._format_results(json_results)

    assert formatted["server_count"] == 2  # Count from servers list
    assert formatted["issue_count"] == 0
    assert formatted["issues"] == []


def test_format_results_error_string():
    """Test formatting of error string results."""
    validator = MCPValidator()

    error_result = "Connection failed"
    formatted = validator._format_results(error_result)

    assert formatted["error"] == "Connection failed"
    assert formatted["server_count"] == 0
    assert formatted["issue_count"] == 0


def test_format_results_suspicious_tools():
    """Test formatting of results with multiple suspicious tools."""
    validator = MCPValidator()

    results = {
        "test-server": {
            "suspicious_tools": [
                {"name": "tool1", "reason": "Reason 1"},
                {"name": "tool2", "reason": "Reason 2"},
            ]
        }
    }

    formatted = validator._format_results(results)

    assert formatted["server_count"] == 1
    assert formatted["issue_count"] == 2
    assert all(issue["severity"] == "MEDIUM" for issue in formatted["issues"])
    assert all("Suspicious tool" in issue["title"] for issue in formatted["issues"])


@pytest.mark.asyncio
async def test_validate_config_invalid_mode(mock_mcp_scanner):
    """Test validation with invalid mode."""
    mock_class, mock_instance = mock_mcp_scanner

    validator = MCPValidator()
    results = await validator.validate_config(
        config_paths=["/path/to/config.json"],
        mode="invalid"
    )

    # Should return an error when invalid mode is used
    assert "error" in results
    assert "Invalid mode: invalid" in results["error"]


def test_detect_config_paths_with_env_var():
    """Test config path detection with environment variable."""
    validator = MCPValidator()

    with patch("pathlib.Path.exists") as mock_exists, patch.dict("os.environ", {"MCP_CONFIG_PATH": "/custom/config.json"}):
        mock_exists.return_value = True

        paths = validator._detect_config_paths()

        assert "/custom/config.json" in paths


def test_format_results_complex_scan():
    """Test formatting of complex scan results."""
    validator = MCPValidator()

    results = {
        "server1": {
            "malicious": True,
            "prompt_injection_risk": True,
            "suspicious_tools": [
                {"name": "tool1", "reason": "Reason 1"}
            ]
        },
        "server2": {
            "malicious": False,
            "prompt_injection_risk": False,
            "suspicious_tools": []
        }
    }

    formatted = validator._format_results(results)

    assert formatted["server_count"] == 2
    assert formatted["issue_count"] == 3  # 1 malicious + 1 prompt injection + 1 suspicious tool

    # Check severity distribution
    severities = [issue["severity"] for issue in formatted["issues"]]
    assert severities.count("CRITICAL") == 1
    assert severities.count("HIGH") == 1
    assert severities.count("MEDIUM") == 1


@pytest.mark.asyncio
async def test_validate_config_with_mcp_scanner_init_error(mock_mcp_scanner):
    """Test when MCPScanner initialization fails."""
    mock_class, _ = mock_mcp_scanner

    # Make the constructor raise an exception
    mock_class.side_effect = ImportError("mcp-scan not installed")

    validator = MCPValidator()
    results = await validator.validate_config(
        config_paths=["/path/to/config.json"],
        mode="scan"
    )

    assert "error" in results
    assert "mcp-scan not installed" in results["error"]


def test_init_with_custom_base_url():
    """Test initialization with custom base URL."""
    validator = MCPValidator(local_only=False)
    assert validator.base_url == "https://mcp.invariantlabs.ai/"
    assert validator.local_only is False


def test_format_results_with_empty_dict():
    """Test formatting of empty results dictionary."""
    validator = MCPValidator()

    formatted = validator._format_results({})

    assert formatted["server_count"] == 0
    assert formatted["issue_count"] == 0
    assert formatted["issues"] == []


def test_format_results_with_nested_server_count():
    """Test formatting when results contain a servers key."""
    validator = MCPValidator()

    results = {
        "servers": ["s1", "s2", "s3"],
        "server1": {"malicious": False}
    }

    formatted = validator._format_results(results)

    # Should count both the servers list and individual server data
    assert formatted["server_count"] == 4  # 3 from list + 1 individual
