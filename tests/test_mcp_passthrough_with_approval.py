"""
Tests for the enhanced MCP passthrough with approval mechanism.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import vulnicheck.mcp_passthrough_with_approval as approval_module
from vulnicheck.dangerous_commands_risk_config import RiskLevel
from vulnicheck.mcp_passthrough_with_approval import (
    ApprovalRequest,
    ApprovalResponse,
    MCPPassthroughWithApproval,
    mcp_passthrough_tool_with_approval,
)


@pytest.fixture
def mock_config():
    """Mock dangerous commands configuration."""
    config = MagicMock()
    config.check_dangerous_pattern = MagicMock(return_value=None)
    config.get_risk_description = MagicMock(
        return_value="This is a test risk description"
    )
    return config


@pytest.fixture
def mock_approval_callback():
    """Mock approval callback that always approves."""

    async def callback(request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            request_id=request.request_id, approved=True, reason="Test approval"
        )

    return callback


@pytest.fixture
def mock_denial_callback():
    """Mock approval callback that always denies."""

    async def callback(request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            request_id=request.request_id,
            approved=False,
            reason="Test denial",
            suggested_alternative="Use a safer command",
        )

    return callback


class TestMCPPassthroughWithApproval:
    """Test the enhanced MCP passthrough functionality."""

    @pytest.mark.asyncio
    async def test_init_with_defaults(self):
        """Test initialization with default values."""
        passthrough = MCPPassthroughWithApproval()
        assert passthrough.agent_name in ["claude", "cursor", "vscode", "unknown"]
        assert passthrough.auto_approve_low_risk is True
        assert passthrough.approval_callback is None

    @pytest.mark.asyncio
    async def test_init_with_approval_callback(self, mock_approval_callback):
        """Test initialization with approval callback."""
        passthrough = MCPPassthroughWithApproval(
            agent_name="claude",
            approval_callback=mock_approval_callback,
            auto_approve_low_risk=False,
        )
        assert passthrough.agent_name == "claude"
        assert passthrough.approval_callback == mock_approval_callback
        assert passthrough.auto_approve_low_risk is False

    @pytest.mark.asyncio
    async def test_execute_safe_operation(self, mock_config):
        """Test executing a safe operation (no dangerous patterns)."""
        with patch(
            "vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config",
            return_value=mock_config,
        ):
            passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

            result = await passthrough.execute_with_security(
                server_name="test_server",
                tool_name="safe_tool",
                parameters={"action": "read"},
            )

            assert result["status"] == "mock"
            assert result["risk_assessment"] is None  # No dangerous pattern found
            mock_config.check_dangerous_pattern.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_blocked_operation(self, mock_config):
        """Test executing a blocked operation."""
        # Mock a blocked pattern
        mock_pattern = MagicMock()
        mock_pattern.risk_level = RiskLevel.BLOCKED
        mock_pattern.category = "filesystem"
        mock_pattern.name = "rm_rf_root"
        mock_pattern.description = "Destroy entire filesystem"

        mock_config.check_dangerous_pattern.return_value = (mock_pattern, "rm -rf /")

        with patch(
            "vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config",
            return_value=mock_config,
        ):
            passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

            result = await passthrough.execute_with_security(
                server_name="system",
                tool_name="execute",
                parameters={"command": "rm -rf /"},
            )

            assert result["status"] == "blocked"
            assert "Operation blocked" in result["reason"]
            assert result["risk_assessment"]["risk_level"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_execute_high_risk_with_approval(
        self, mock_config, mock_approval_callback
    ):
        """Test executing a high-risk operation with approval."""
        # Mock a high-risk pattern
        mock_pattern = MagicMock()
        mock_pattern.risk_level = RiskLevel.HIGH_RISK
        mock_pattern.category = "privilege"
        mock_pattern.name = "sudo"
        mock_pattern.description = "Run command as root"

        mock_config.check_dangerous_pattern.return_value = (mock_pattern, "sudo")

        with patch(
            "vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config",
            return_value=mock_config,
        ):
            passthrough = MCPPassthroughWithApproval(
                enable_real_connections=False, approval_callback=mock_approval_callback
            )

            result = await passthrough.execute_with_security(
                server_name="system",
                tool_name="execute",
                parameters={"command": "sudo apt update"},
            )

            assert result["status"] == "mock"  # Because real connections are disabled
            assert result["risk_assessment"]["risk_level"] == "HIGH_RISK"

    @pytest.mark.asyncio
    async def test_execute_high_risk_with_denial(
        self, mock_config, mock_denial_callback
    ):
        """Test executing a high-risk operation that gets denied."""
        # Mock a high-risk pattern
        mock_pattern = MagicMock()
        mock_pattern.risk_level = RiskLevel.HIGH_RISK
        mock_pattern.category = "privilege"
        mock_pattern.name = "sudo"
        mock_pattern.description = "Run command as root"

        mock_config.check_dangerous_pattern.return_value = (mock_pattern, "sudo")

        with patch(
            "vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config",
            return_value=mock_config,
        ):
            passthrough = MCPPassthroughWithApproval(
                enable_real_connections=False, approval_callback=mock_denial_callback
            )

            result = await passthrough.execute_with_security(
                server_name="system",
                tool_name="execute",
                parameters={"command": "sudo rm -rf /"},
            )

            assert result["status"] == "denied"
            assert result["reason"] == "Test denial"
            assert result["suggested_alternative"] == "Use a safer command"

    @pytest.mark.asyncio
    async def test_execute_low_risk_auto_approved(self, mock_config):
        """Test executing a low-risk operation with auto-approval."""
        # Mock a low-risk pattern
        mock_pattern = MagicMock()
        mock_pattern.risk_level = RiskLevel.LOW_RISK
        mock_pattern.category = "network"
        mock_pattern.name = "curl_download"
        mock_pattern.description = "Download file"

        mock_config.check_dangerous_pattern.return_value = (mock_pattern, "curl -o")

        with patch(
            "vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config",
            return_value=mock_config,
        ):
            passthrough = MCPPassthroughWithApproval(
                enable_real_connections=False, auto_approve_low_risk=True
            )

            result = await passthrough.execute_with_security(
                server_name="system",
                tool_name="execute",
                parameters={"command": "curl -o file.txt https://example.com"},
            )

            assert result["status"] == "mock"  # Auto-approved and executed
            assert result["risk_assessment"]["risk_level"] == "LOW_RISK"

    @pytest.mark.asyncio
    async def test_execute_requires_approval_no_callback(self, mock_config):
        """Test executing an operation that requires approval but no callback is set."""
        # Mock a pattern that requires approval
        mock_pattern = MagicMock()
        mock_pattern.risk_level = RiskLevel.REQUIRES_APPROVAL
        mock_pattern.category = "filesystem"
        mock_pattern.name = "rm_recursive"
        mock_pattern.description = "Delete directory recursively"

        mock_config.check_dangerous_pattern.return_value = (mock_pattern, "rm -r")

        with patch(
            "vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config",
            return_value=mock_config,
        ):
            passthrough = MCPPassthroughWithApproval(
                enable_real_connections=False,
                approval_callback=None,  # No callback
            )

            result = await passthrough.execute_with_security(
                server_name="system",
                tool_name="execute",
                parameters={"command": "rm -r /tmp/test"},
            )

            assert result["status"] == "blocked"
            assert "no approval mechanism configured" in result["reason"]

    @pytest.mark.asyncio
    async def test_approval_timeout(self, mock_config):
        """Test approval request timeout."""
        # Skip this test for now - it's complex to test timeout behavior properly
        pytest.skip("Timeout test is complex to implement properly")

    @pytest.mark.asyncio
    async def test_claude_approval_callback_high_risk(self):
        """Test the example Claude approval callback with high-risk operation."""
        # Save the current callback to restore it after the test
        original_callback = approval_module.claude_approval_callback
        try:
            # Import the original default callback
            from vulnicheck.mcp_passthrough_with_approval import (
                default_approval_callback,
            )
            approval_module.claude_approval_callback = default_approval_callback

            request = ApprovalRequest(
                server_name="system",
                tool_name="execute",
                parameters={"command": "sudo rm -rf /"},
                risk_assessment={
                    "risk_level": RiskLevel.HIGH_RISK.value,
                    "category": "privilege",
                    "description": "Run command as root",
                },
            )

            response = await default_approval_callback(request)

            assert response.approved is False
            assert "manual review" in response.reason
            assert response.suggested_alternative is not None
        finally:
            # Restore the original callback
            approval_module.claude_approval_callback = original_callback

    @pytest.mark.asyncio
    async def test_claude_approval_callback_requires_approval(self):
        """Test the example Claude approval callback with requires-approval operation."""
        # Save the current callback to restore it after the test
        original_callback = approval_module.claude_approval_callback
        try:
            # Import the original default callback
            from vulnicheck.mcp_passthrough_with_approval import (
                default_approval_callback,
            )
            approval_module.claude_approval_callback = default_approval_callback

            request = ApprovalRequest(
                server_name="system",
                tool_name="execute",
                parameters={"command": "rm -r /tmp/test"},
                risk_assessment={
                    "risk_level": RiskLevel.REQUIRES_APPROVAL.value,
                    "category": "filesystem",
                    "description": "Delete directory recursively",
                },
            )

            response = await default_approval_callback(request)

            assert response.approved is True
            assert "approved after risk assessment" in response.reason
        finally:
            # Restore the original callback
            approval_module.claude_approval_callback = original_callback

    @pytest.mark.asyncio
    async def test_mcp_passthrough_tool_with_approval(self, mock_config):
        """Test the FastMCP tool function."""
        mock_config.check_dangerous_pattern.return_value = None

        # Mock the passthrough instance to avoid connection issues
        mock_passthrough = AsyncMock()
        mock_passthrough.execute_with_security.return_value = {
            "status": "mock",
            "message": "Running in mock mode - no real MCP connections",
            "requested_call": {
                "server": "test_server",
                "tool": "test_tool",
                "parameters": {"test": "value"},
            },
            "risk_assessment": None,
        }

        with (
            patch(
                "vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config",
                return_value=mock_config,
            ),
            patch(
                "vulnicheck.mcp_passthrough_with_approval.MCPPassthroughWithApproval",
                return_value=mock_passthrough,
            ),
        ):
            result_json = await mcp_passthrough_tool_with_approval(
                server_name="test_server",
                tool_name="test_tool",
                parameters={"test": "value"},
                security_context="Test context",
            )

            result = json.loads(result_json)
            assert result["status"] == "mock"
            assert result["requested_call"]["server"] == "test_server"
            assert result["requested_call"]["tool"] == "test_tool"

    @pytest.mark.asyncio
    async def test_format_security_prompt(self):
        """Test security prompt formatting."""
        passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

        risk_assessment = {
            "server_name": "test_server",
            "tool_name": "dangerous_tool",
            "risk_level": "HIGH_RISK",
            "category": "privilege",
            "pattern_name": "sudo",
            "description": "Run command as root",
            "risk_explanation": "This operation is high risk",
        }

        prompt = passthrough._format_security_prompt(risk_assessment)

        assert "test_server" in prompt
        assert "dangerous_tool" in prompt
        assert "HIGH_RISK" in prompt
        assert "privilege" in prompt
        assert "sudo" in prompt
        assert "Run command as root" in prompt

    @pytest.mark.asyncio
    async def test_pending_approvals_cleanup(self, mock_config, mock_approval_callback):
        """Test that pending approvals are cleaned up properly."""
        # Mock a pattern that requires approval
        mock_pattern = MagicMock()
        mock_pattern.risk_level = RiskLevel.REQUIRES_APPROVAL
        mock_pattern.category = "filesystem"
        mock_pattern.name = "rm_recursive"
        mock_pattern.description = "Delete directory recursively"

        mock_config.check_dangerous_pattern.return_value = (mock_pattern, "rm -r")

        with patch(
            "vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config",
            return_value=mock_config,
        ):
            passthrough = MCPPassthroughWithApproval(
                enable_real_connections=False, approval_callback=mock_approval_callback
            )

            # Execute operation
            await passthrough.execute_with_security(
                server_name="system",
                tool_name="execute",
                parameters={"command": "rm -r /tmp/test"},
            )

            # Check that pending approvals are cleaned up
            assert len(passthrough.pending_approvals) == 0

    @pytest.mark.asyncio
    async def test_close_resources(self):
        """Test resource cleanup."""
        passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

        # Should not raise even with no resources
        await passthrough.close()

        # Test with mocked resources
        passthrough.connection_pool = AsyncMock()
        passthrough.mcp_client = AsyncMock()

        await passthrough.close()

        passthrough.connection_pool.close_all.assert_called_once()
        passthrough.mcp_client.close_all.assert_called_once()
