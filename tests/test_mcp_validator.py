"""Tests for MCP security validation functionality."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from vulnicheck.mcp.mcp_validator import MCPValidator


def test_mcp_scan_policy_loading():
    """Test that mcp_scan policy loading works with our temporary directory approach."""
    import os
    import shutil

    # Clean up any existing module imports
    import sys
    import tempfile
    from pathlib import Path

    from vulnicheck.mcp.mcp_validator import EMBEDDED_POLICY_GR

    if "mcp_scan" in sys.modules:
        del sys.modules["mcp_scan"]
    if "mcp_scan.verify_api" in sys.modules:
        del sys.modules["mcp_scan.verify_api"]

    original_cwd = os.getcwd()
    temp_dir = tempfile.mkdtemp()

    try:
        # Create the expected directory structure
        policy_dir = Path(temp_dir) / "src" / "mcp_scan"
        policy_dir.mkdir(parents=True)
        (policy_dir / "policy.gr").write_text(EMBEDDED_POLICY_GR)

        # Change to temp directory
        os.chdir(temp_dir)

        # Import mcp_scan
        import mcp_scan.verify_api

        # Test that get_policy works
        policy_content = mcp_scan.verify_api.get_policy()
        assert isinstance(policy_content, str)
        assert "prompt injection" in policy_content
        assert len(policy_content) > 0

    except ImportError:
        pytest.skip("mcp_scan not installed")
    finally:
        # Restore working directory
        os.chdir(original_cwd)
        # Clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_mcp_scanner():
    """Mock MCPScanner for testing."""
    # Since MCPScanner is imported lazily, we need to patch mcp_scan.MCPScanner
    with patch("mcp_scan.MCPScanner") as mock:
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
async def test_validate_config_json_input():
    """Test validation with JSON string input."""
    validator = MCPValidator(local_only=True)

    # Test with invalid JSON
    result = await validator.validate_config("invalid json", mode="scan")
    assert "error" in result
    assert "Invalid JSON" in result["error"]
    assert result["issue_count"] == 0

    # Test with valid JSON
    config = {"mcpServers": {"test": {"command": "echo", "args": ["test"], "env": {}}}}

    with patch("mcp_scan.MCPScanner") as mock_scanner:
        mock_instance = AsyncMock()
        mock_instance.scan = AsyncMock(return_value={})
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=None)
        mock_scanner.return_value = mock_instance

        result = await validator.validate_config(json.dumps(config), mode="scan")

        # Check that a temporary file was created with the config
        assert mock_scanner.called
        call_args = mock_scanner.call_args
        assert "files" in call_args.kwargs
        assert len(call_args.kwargs["files"]) == 1
        assert call_args.kwargs["files"][0].endswith(".json")


@pytest.mark.asyncio
async def test_validate_config_policy_file_error():
    """Test handling of policy.gr file not found error."""
    validator = MCPValidator(local_only=True)

    config = {"mcpServers": {"test": {"command": "test", "args": [], "env": {}}}}

    with patch("mcp_scan.MCPScanner") as mock_scanner:
        mock_instance = AsyncMock()
        # Simulate FileNotFoundError for policy.gr
        mock_instance.__aenter__.side_effect = FileNotFoundError(
            "[Errno 2] No such file or directory: 'src/mcp_scan/policy.gr'"
        )
        mock_scanner.return_value = mock_instance

        result = await validator.validate_config(json.dumps(config), mode="scan")

        # Should fall back to basic validation
        assert "error" not in result
        assert "note" in result
        assert "Basic validation performed" in result["note"]
        assert result["server_count"] == 1  # Basic validation still counts servers


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
            ],
        }
    }

    validator = MCPValidator(local_only=True)
    config = {"mcpServers": {"test-server": {"command": "test", "args": []}}}
    results = await validator.validate_config(
        config_json=json.dumps(config), mode="scan"
    )

    assert results["server_count"] == 1
    assert results["issue_count"] == 2
    assert len(results["issues"]) == 2

    # Check that high severity issue was created for prompt injection
    prompt_injection_issues = [i for i in results["issues"] if i["severity"] == "HIGH"]
    assert len(prompt_injection_issues) == 1
    assert "prompt injection" in prompt_injection_issues[0]["title"].lower()


@pytest.mark.asyncio
async def test_validate_config_inspect_mode(mock_mcp_scanner):
    """Test validation in inspect mode."""
    mock_class, mock_instance = mock_mcp_scanner

    # Mock inspect results
    mock_instance.inspect.return_value = {"servers": ["server1", "server2"]}

    validator = MCPValidator(local_only=False)
    config = {
        "mcpServers": {"server1": {"command": "cmd1"}, "server2": {"command": "cmd2"}}
    }
    results = await validator.validate_config(
        config_json=json.dumps(config), mode="inspect"
    )

    assert results["server_count"] == 2
    assert results["issue_count"] == 0
    assert mock_instance.inspect.called


@pytest.mark.asyncio
async def test_validate_config_malicious_server(mock_mcp_scanner):
    """Test detection of malicious server."""
    mock_class, mock_instance = mock_mcp_scanner

    # Mock scan results with malicious server
    mock_instance.scan.return_value = {"evil-server": {"malicious": True}}

    validator = MCPValidator()
    config = {"mcpServers": {"evil-server": {"command": "evil", "args": []}}}
    results = await validator.validate_config(
        config_json=json.dumps(config), mode="scan"
    )

    assert results["issue_count"] == 1
    assert results["issues"][0]["severity"] == "CRITICAL"
    assert "malicious" in results["issues"][0]["title"].lower()


@pytest.mark.asyncio
async def test_validate_config_empty_json():
    """Test behavior when empty JSON is provided."""
    validator = MCPValidator()

    # Test with empty object
    results = await validator.validate_config("{}", mode="scan")

    # Should process but find no servers
    assert results["server_count"] == 0
    assert results["issue_count"] == 0


@pytest.mark.asyncio
async def test_validate_config_error_handling(mock_mcp_scanner):
    """Test error handling during validation."""
    mock_class, mock_instance = mock_mcp_scanner

    # Make scan raise an exception
    mock_instance.scan.side_effect = Exception("Scan failed")

    validator = MCPValidator()
    config = {"mcpServers": {"evil-server": {"command": "evil", "args": []}}}
    results = await validator.validate_config(
        config_json=json.dumps(config), mode="scan"
    )

    assert "error" in results
    assert "Scan failed" in results["error"]
    assert results["issue_count"] == 0


# Removed test_detect_config_paths as _detect_config_paths is no longer used in the new API


def test_format_results_json_string():
    """Test formatting of JSON string results."""
    validator = MCPValidator()

    json_results = json.dumps({"servers": ["server1", "server2"]})

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
    config = {"mcpServers": {"test": {"command": "test"}}}
    results = await validator.validate_config(
        config_json=json.dumps(config), mode="invalid"
    )

    # Should return an error when invalid mode is used
    assert "error" in results
    assert "Invalid mode: invalid" in results["error"]


# Removed test_detect_config_paths_with_env_var as _detect_config_paths is no longer used in the new API


def test_format_results_complex_scan():
    """Test formatting of complex scan results."""
    validator = MCPValidator()

    results = {
        "server1": {
            "malicious": True,
            "prompt_injection_risk": True,
            "suspicious_tools": [{"name": "tool1", "reason": "Reason 1"}],
        },
        "server2": {
            "malicious": False,
            "prompt_injection_risk": False,
            "suspicious_tools": [],
        },
    }

    formatted = validator._format_results(results)

    assert formatted["server_count"] == 2
    assert (
        formatted["issue_count"] == 3
    )  # 1 malicious + 1 prompt injection + 1 suspicious tool

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
    config = {"mcpServers": {"evil-server": {"command": "evil", "args": []}}}
    results = await validator.validate_config(
        config_json=json.dumps(config), mode="scan"
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

    results = {"servers": ["s1", "s2", "s3"], "server1": {"malicious": False}}

    formatted = validator._format_results(results)

    # Should count both the servers list and individual server data
    assert formatted["server_count"] == 4  # 3 from list + 1 individual
