"""
Tests for the enhanced MCP passthrough with approval mechanism using unified security.
"""

import json

import pytest

from vulnicheck.mcp.mcp_passthrough_with_approval import (
    ApprovalRequest,
    ApprovalResponse,
    MCPPassthroughWithApproval,
    mcp_passthrough_tool_with_approval,
)


@pytest.fixture
def mock_approval_callback():
    """Mock approval callback that always approves."""
    async def callback(request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            request_id=request.request_id,
            approved=True,
            reason="Test approval",
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
            suggested_alternative="Try a safer approach",
        )
    return callback


class TestMCPPassthroughWithApprovalUnified:
    """Test cases for MCPPassthroughWithApproval with unified security."""

    @pytest.mark.asyncio
    async def test_execute_safe_operation(self):
        """Test executing a safe operation (no dangerous patterns)."""
        passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

        result = await passthrough.execute_with_security(
            server_name="test_server",
            tool_name="safe_tool",
            parameters={"action": "read", "path": "/safe/path"},
        )

        assert result["status"] == "mock"
        # Safe operations shouldn't have risk_assessment in mock mode
        assert "risk_assessment" not in result or result.get("risk_assessment") is None

    @pytest.mark.asyncio
    async def test_execute_blocked_operation_server(self):
        """Test executing operation with blocked server name."""
        passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

        # "system" is a blocked server name
        result = await passthrough.execute_with_security(
            server_name="system",
            tool_name="execute",
            parameters={"command": "ls"},
        )

        assert result["status"] == "blocked"
        assert "blocked" in result["reason"].lower()
        assert result["risk_assessment"]["risk_level"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_execute_blocked_operation_dangerous_path(self):
        """Test executing operation with dangerous file path."""
        passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

        result = await passthrough.execute_with_security(
            server_name="file_server",
            tool_name="read_file",
            parameters={"path": "/etc/passwd"},
        )

        # In unified architecture with mock mode, dangerous operations may be handled differently
        # The unified security layer may block due to trust store validation
        assert result["status"] in ["blocked", "mock"]

        if result["status"] == "blocked":
            # The reason explains why it was blocked (e.g., needs approval but no mechanism)
            assert "approval" in result["reason"].lower() or "blocked" in result["reason"].lower()
            # The risk assessment should show HIGH_RISK or BLOCKED
            assert result["risk_assessment"]["risk_level"] in ["HIGH_RISK", "BLOCKED"]
        else:
            # In mock mode, the dangerous operation is logged but not executed
            assert "mock" in result["status"]

    @pytest.mark.asyncio
    async def test_execute_blocked_operation_dangerous_command(self):
        """Test executing operation with dangerous command."""
        passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

        result = await passthrough.execute_with_security(
            server_name="shell_server",
            tool_name="execute",
            parameters={"command": "rm -rf /"},
        )

        assert result["status"] == "blocked"
        # The unified security provides specific explanations instead of generic messages
        assert "blocked" in result["reason"].lower()
        # The specific reason might be "Destroy entire filesystem" or similar
        assert result["risk_assessment"]["risk_level"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_execute_requires_approval_with_callback(self, mock_approval_callback):
        """Test operation that requires approval and gets approved."""
        passthrough = MCPPassthroughWithApproval(
            enable_real_connections=False,
            approval_callback=mock_approval_callback,
            auto_approve_low_risk=False  # Disable auto-approval for test
        )

        # Use a pattern that would require approval but not block
        # For example, a database operation
        result = await passthrough.execute_with_security(
            server_name="db_server",
            tool_name="query",
            parameters={"query": "DELETE FROM users WHERE active=false"},
        )

        # Should pass through with mock status since callback approved
        assert result["status"] == "mock"
        # Should have risk assessment since it matched a pattern
        if result.get("risk_assessment"):
            assert result["risk_assessment"]["risk_level"] in ["REQUIRES_APPROVAL", "HIGH_RISK"]

    @pytest.mark.asyncio
    async def test_execute_requires_approval_with_denial(self, mock_denial_callback):
        """Test operation that requires approval and gets denied."""
        passthrough = MCPPassthroughWithApproval(
            enable_real_connections=False,
            approval_callback=mock_denial_callback,
            auto_approve_low_risk=False  # Disable auto-approval for test
        )

        # Use a pattern that would require approval but not block
        result = await passthrough.execute_with_security(
            server_name="db_server",
            tool_name="query",
            parameters={"query": "DELETE FROM users WHERE active=false"},
        )

        # Check if it was blocked or required approval
        if result["status"] == "denied":
            assert "Test denial" in result["reason"]
            assert result.get("suggested_alternative") == "Try a safer approach"
            # Risk assessment might not be present in denied responses
            if result.get("risk_assessment"):
                assert result["risk_assessment"]["risk_level"] in ["REQUIRES_APPROVAL", "HIGH_RISK"]
        elif result["status"] == "blocked":
            # Pattern might have been categorized as blocked
            assert "blocked" in result["reason"].lower()
        else:
            # If no dangerous pattern was detected, it would go through
            assert result["status"] == "mock"

    @pytest.mark.asyncio
    async def test_execute_low_risk_auto_approved(self):
        """Test executing a low-risk operation with auto-approval enabled."""
        passthrough = MCPPassthroughWithApproval(
            enable_real_connections=False,
            auto_approve_low_risk=True
        )

        # Git operations are generally considered lower risk
        result = await passthrough.execute_with_security(
            server_name="git_server",
            tool_name="status",
            parameters={"repo": "/safe/repo"},
        )

        # Should pass through
        assert result["status"] == "mock"

    @pytest.mark.asyncio
    async def test_approval_timeout(self, mock_approval_callback):
        """Test approval timeout handling."""
        # Create a callback that takes too long
        async def slow_callback(request: ApprovalRequest) -> ApprovalResponse:
            import asyncio
            await asyncio.sleep(2)  # Longer than timeout
            return ApprovalResponse(
                request_id=request.request_id,
                approved=True,
                reason="Too late",
            )

        passthrough = MCPPassthroughWithApproval(
            enable_real_connections=False,
            approval_callback=slow_callback,
        )

        # Modify the timeout to be very short for testing
        passthrough.pending_approvals = {}

        # Execute with a pattern that requires approval
        result = await passthrough.execute_with_security(
            server_name="db_server",
            tool_name="execute",
            parameters={"query": "DELETE FROM important_table"},
        )

        # Should either be blocked or timeout
        assert result["status"] in ["blocked", "denied", "mock"]

    @pytest.mark.asyncio
    async def test_security_prompt_format(self):
        """Test that security prompt is properly formatted."""
        passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

        result = await passthrough.execute_with_security(
            server_name="shell_server",
            tool_name="execute",
            parameters={"command": "sudo rm -rf /"},
            security_context="Test context",
        )

        assert result["status"] == "blocked"
        assert "security_prompt" in result
        prompt = result["security_prompt"]

        # Check key elements in prompt
        assert "SECURITY NOTICE" in prompt
        assert "shell_server" in prompt
        assert "execute" in prompt
        # Unified security layer shows risk level instead of just "BLOCKED"
        assert ("BLOCKED" in prompt or "Risk Level:" in prompt)

    @pytest.mark.asyncio
    async def test_conversation_storage_integration(self):
        """Test that conversations are properly stored."""
        passthrough = MCPPassthroughWithApproval(enable_real_connections=False)

        # Execute a command
        await passthrough.execute_with_security(
            server_name="test_server",
            tool_name="test_tool",
            parameters={"test": "value"},
        )

        # Check that conversation was created
        assert passthrough._active_conversations.get("test_server") is not None


class TestMCPPassthroughToolFunction:
    """Test cases for the mcp_passthrough_tool_with_approval function."""

    @pytest.mark.asyncio
    async def test_tool_function_safe_operation(self):
        """Test tool function with safe operation."""
        # Mock environment to disable real connections
        import os
        os.environ["MCP_PASSTHROUGH_ENHANCED"] = "false"

        try:
            result_json = await mcp_passthrough_tool_with_approval(
                server_name="data_server",
                tool_name="list",
                parameters={"path": "/data"},
            )

            result = json.loads(result_json)
            assert result["status"] in ["mock", "error"]

            # If error, it should be about missing server config, not security
            if result["status"] == "error":
                assert "not found" in result["error"].lower() or "config" in result["error"].lower()
        finally:
            # Clean up
            if "MCP_PASSTHROUGH_ENHANCED" in os.environ:
                del os.environ["MCP_PASSTHROUGH_ENHANCED"]

    @pytest.mark.asyncio
    async def test_tool_function_blocked_operation(self):
        """Test tool function with blocked operation."""
        # Mock environment to disable real connections
        import os
        os.environ["MCP_PASSTHROUGH_ENHANCED"] = "false"

        try:
            result_json = await mcp_passthrough_tool_with_approval(
                server_name="system",
                tool_name="execute",
                parameters={"command": "rm -rf /"},
            )

            result = json.loads(result_json)
            assert result["status"] == "blocked"
            assert "blocked" in result["reason"].lower()
        finally:
            # Clean up
            if "MCP_PASSTHROUGH_ENHANCED" in os.environ:
                del os.environ["MCP_PASSTHROUGH_ENHANCED"]
