"""
Tests for the enhanced MCP passthrough with approval mechanism.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

import vulnicheck.mcp.mcp_passthrough_with_approval as approval_module
from vulnicheck.mcp.mcp_passthrough_with_approval import (
    ApprovalRequest,
    ApprovalResponse,
    MCPPassthroughWithApproval,
    mcp_passthrough_tool_with_approval,
)
from vulnicheck.security.unified_security import RiskLevel


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
        passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

        result = await passthrough.execute_with_security(
            server_name="test_server",
            tool_name="safe_tool",
            parameters={"action": "read"},
        )

        assert result["status"] == "mock"
        # With unified security, safe operations won't have risk_assessment in the result
        assert "risk_assessment" not in result or result.get("risk_assessment") is None

    @pytest.mark.asyncio
    async def test_execute_blocked_operation(self, mock_config):
        """Test executing a blocked operation."""
        passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

        result = await passthrough.execute_with_security(
            server_name="system",
            tool_name="execute",
            parameters={"command": "rm -rf /"},
        )

        assert result["status"] == "blocked"
        assert "blocked" in result["reason"].lower()
        assert result["risk_assessment"]["risk_level"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_execute_high_risk_with_approval(
        self, mock_config, mock_approval_callback
    ):
        """Test executing a high-risk operation with approval."""
        passthrough = MCPPassthroughWithApproval(
            enable_real_connections=False, approval_callback=mock_approval_callback
        )

        result = await passthrough.execute_with_security(
            server_name="system",
            tool_name="execute",
            parameters={"command": "sudo apt update"},
        )

        # With unified security, "sudo" command will be blocked (privilege category)
        assert result["status"] == "blocked"
        assert result["risk_assessment"]["risk_level"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_execute_high_risk_with_denial(
        self, mock_config, mock_denial_callback
    ):
        """Test executing a high-risk operation that gets denied."""
        passthrough = MCPPassthroughWithApproval(
            enable_real_connections=False, approval_callback=mock_denial_callback
        )

        # Use a command that is HIGH_RISK but not BLOCKED
        result = await passthrough.execute_with_security(
            server_name="shell-server",
            tool_name="execute",
            parameters={"command": "chmod 777 /etc"},  # This is HIGH_RISK
        )

        # With approval callback that denies, HIGH_RISK operations should be denied
        assert result["status"] == "denied"
        assert result["reason"] == "Test denial"
        assert result["suggested_alternative"] == "Use a safer command"

    @pytest.mark.asyncio
    async def test_execute_low_risk_auto_approved(self, mock_config):
        """Test executing a low-risk operation with auto-approval."""
        passthrough = MCPPassthroughWithApproval(
            enable_real_connections=False, auto_approve_low_risk=True
        )

        # Use a command that should be safe (no dangerous patterns)
        result = await passthrough.execute_with_security(
            server_name="data-server",
            tool_name="query",
            parameters={"query": "SELECT * FROM users LIMIT 10"},
        )

        # Safe operations should be auto-approved and executed
        assert result["status"] == "mock"
        # Safe operations won't have risk_assessment in the result
        assert "risk_assessment" not in result or result.get("risk_assessment") is None

    @pytest.mark.asyncio
    async def test_execute_requires_approval_no_callback(self, mock_config):
        """Test executing an operation that requires approval but no callback is set."""
        passthrough = MCPPassthroughWithApproval(
            enable_real_connections=False,
            approval_callback=None,  # No callback
        )

        # Use a command that REQUIRES_APPROVAL (rm -r pattern)
        result = await passthrough.execute_with_security(
            server_name="shell-server",
            tool_name="execute",
            parameters={"command": "rm -r /tmp/test"},  # REQUIRES_APPROVAL pattern
        )

        # Operations requiring approval with no callback should be blocked
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
            from vulnicheck.mcp.mcp_passthrough_with_approval import (
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
            from vulnicheck.mcp.mcp_passthrough_with_approval import (
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
        # Test with a blocked server name
        result_json = await mcp_passthrough_tool_with_approval(
            server_name="root",  # This is a blocked server name
            tool_name="test_tool",
            parameters={"test": "value"},
            security_context="Test context",
        )

        result = json.loads(result_json)
        assert result["status"] == "blocked"
        assert "root" in result["reason"].lower()

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
        passthrough = MCPPassthroughWithApproval(
            enable_real_connections=False, approval_callback=mock_approval_callback
        )

        # Execute a HIGH_RISK operation that will trigger approval
        await passthrough.execute_with_security(
            server_name="shell-server",
            tool_name="execute",
            parameters={"command": "chmod 777 /etc"},  # HIGH_RISK command
        )

        # Check that pending approvals are cleaned up after approval
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
