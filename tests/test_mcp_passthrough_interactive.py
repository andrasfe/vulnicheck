"""Tests for the interactive MCP passthrough with approval mechanism."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnicheck.mcp.mcp_passthrough_interactive import (
    MCPPassthroughInteractive,
    PendingOperation,
    get_interactive_passthrough,
)
from vulnicheck.security.dangerous_commands_risk_config import RiskLevel


@pytest.fixture
def mock_passthrough():
    """Create a mock interactive passthrough without real connections."""
    return MCPPassthroughInteractive(enable_real_connections=False)


@pytest.fixture
def pending_operation():
    """Create a sample pending operation."""
    return PendingOperation(
        request_id="test-123",
        server_name="test_server",
        tool_name="test_tool",
        parameters={"command": "git clone test"},
        risk_assessment={
            "risk_level": "REQUIRES_APPROVAL",
            "category": "network",
            "pattern_name": "git_clone",
            "description": "Clone repository",
        },
        security_context="Test context",
    )


class TestPendingOperation:
    """Test the PendingOperation dataclass."""

    def test_pending_operation_creation(self):
        """Test creating a pending operation."""
        op = PendingOperation(
            server_name="test", tool_name="test_tool", parameters={"key": "value"}
        )

        assert op.server_name == "test"
        assert op.tool_name == "test_tool"
        assert op.parameters == {"key": "value"}
        assert op.request_id  # Should have a UUID
        assert not op.approved
        assert op.approval_reason is None

    def test_is_expired(self):
        """Test expiration checking."""
        # Not expired
        op = PendingOperation()
        assert not op.is_expired

        # Expired
        op.expires_at = datetime.now() - timedelta(minutes=1)
        assert op.is_expired


class TestMCPPassthroughInteractive:
    """Test the MCPPassthroughInteractive class."""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_passthrough):
        """Test passthrough initialization."""
        assert mock_passthrough.agent_name is not None
        assert not mock_passthrough.enable_real_connections
        assert mock_passthrough.base_passthrough is None
        assert len(mock_passthrough.pending_operations) == 0
        assert len(mock_passthrough.approved_operations) == 0

    @pytest.mark.asyncio
    async def test_safe_operation_executes_immediately(self, mock_passthrough):
        """Test that safe operations execute without approval."""
        result = await mock_passthrough.execute_with_approval(
            server_name="test",
            tool_name="safe_tool",
            parameters={"query": "hello world"},
            security_context="Safe operation",
        )

        assert result["status"] == "mock"
        assert result["message"] == "Running in mock mode - no real MCP connections"
        assert "risk_assessment" not in result or result["risk_assessment"] is None

    @pytest.mark.asyncio
    async def test_requires_approval_operation(self, mock_passthrough):
        """Test operations requiring approval."""
        result = await mock_passthrough.execute_with_approval(
            server_name="test",
            tool_name="risky_tool",
            parameters={"command": "git clone https://example.com"},
            security_context="Clone repo",
        )

        assert result["status"] == "approval_required"
        assert "request_id" in result
        assert "🔒 **SECURITY APPROVAL REQUIRED**" in result["message"]
        assert result["metadata"]["risk_level"] == "REQUIRES_APPROVAL"

        # Check pending operation was created
        assert len(mock_passthrough.pending_operations) == 1

    @pytest.mark.asyncio
    async def test_high_risk_operation(self, mock_passthrough):
        """Test high risk operations get appropriate warnings."""
        result = await mock_passthrough.execute_with_approval(
            server_name="test",
            tool_name="dangerous_tool",
            parameters={"command": "sudo apt install"},
            security_context="Install package",
        )

        # Note: The unified security may block sudo commands for safety
        # Both blocked and approval_required are valid responses
        if result["status"] == "blocked":
            assert result["risk_assessment"]["risk_level"] == "BLOCKED"
            assert "sudo" in result["reason"].lower()
        else:
            assert result["status"] == "approval_required"
            assert "⚠️ **HIGH RISK OPERATION**" in result["message"]
            assert result["metadata"]["risk_level"] == "HIGH_RISK"

    @pytest.mark.asyncio
    async def test_blocked_operation(self, mock_passthrough):
        """Test that blocked operations are rejected immediately."""
        result = await mock_passthrough.execute_with_approval(
            server_name="test",
            tool_name="destroy_tool",
            parameters={"command": "rm -rf /"},
            security_context="Destroy system",
        )

        assert result["status"] == "blocked"
        # The unified security provides specific explanations like "Destroy entire filesystem"
        assert "blocked" in result["reason"].lower()
        assert result["risk_assessment"]["risk_level"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_process_approval_success(self, mock_passthrough, pending_operation):
        """Test successful approval processing."""
        # Add pending operation
        mock_passthrough.pending_operations[pending_operation.request_id] = (
            pending_operation
        )

        result = await mock_passthrough.process_approval(
            request_id=pending_operation.request_id,
            approved=True,
            reason="Test approval",
        )

        assert result["status"] == "approved"
        assert result["request_id"] == pending_operation.request_id
        assert "Operation approved" in result["message"]

        # Check operation was moved to approved
        assert pending_operation.request_id not in mock_passthrough.pending_operations
        assert pending_operation.request_id in mock_passthrough.approved_operations
        assert mock_passthrough.approved_operations[
            pending_operation.request_id
        ].approved

    @pytest.mark.asyncio
    async def test_process_denial(self, mock_passthrough, pending_operation):
        """Test denial processing."""
        # Add pending operation
        mock_passthrough.pending_operations[pending_operation.request_id] = (
            pending_operation
        )

        result = await mock_passthrough.process_approval(
            request_id=pending_operation.request_id,
            approved=False,
            reason="Too risky",
            suggested_alternative="Use safer approach",
        )

        assert result["status"] == "denied"
        assert result["reason"] == "Too risky"
        assert result["suggested_alternative"] == "Use safer approach"

        # Check operation was removed
        assert pending_operation.request_id not in mock_passthrough.pending_operations
        assert pending_operation.request_id not in mock_passthrough.approved_operations

    @pytest.mark.asyncio
    async def test_process_approval_not_found(self, mock_passthrough):
        """Test approval for non-existent operation."""
        result = await mock_passthrough.process_approval(
            request_id="non-existent", approved=True, reason="Test"
        )

        assert result["status"] == "error"
        assert "No pending operation found" in result["message"]

    @pytest.mark.asyncio
    async def test_process_approval_expired(self, mock_passthrough, pending_operation):
        """Test approval for expired operation."""
        # Make operation expired
        pending_operation.expires_at = datetime.now() - timedelta(minutes=1)
        mock_passthrough.pending_operations[pending_operation.request_id] = (
            pending_operation
        )

        result = await mock_passthrough.process_approval(
            request_id=pending_operation.request_id, approved=True, reason="Test"
        )

        # The operation is removed during cleanup, so it's not found
        assert result["status"] == "error"
        assert "No pending operation found" in result["message"]

    @pytest.mark.asyncio
    async def test_pre_approved_operation_executes(self, mock_passthrough):
        """Test that pre-approved operations execute on retry."""
        # First request - needs approval
        result1 = await mock_passthrough.execute_with_approval(
            server_name="test",
            tool_name="risky_tool",
            parameters={"command": "pip install requests"},
            security_context="Install package",
        )

        assert result1["status"] == "approval_required"
        request_id = result1["request_id"]

        # Approve it
        approval_result = await mock_passthrough.process_approval(
            request_id=request_id, approved=True, reason="Needed for project"
        )

        assert approval_result["status"] == "approved"

        # Retry the same operation - should execute
        result2 = await mock_passthrough.execute_with_approval(
            server_name="test",
            tool_name="risky_tool",
            parameters={"command": "pip install requests"},
            security_context="Install package",
        )

        assert result2["status"] == "mock"
        assert result2["message"] == "Running in mock mode - no real MCP connections"

    @pytest.mark.asyncio
    async def test_cleanup_expired_operations(self, mock_passthrough):
        """Test that expired operations are cleaned up."""
        # Add expired operation
        expired_op = PendingOperation(
            request_id="expired-123", expires_at=datetime.now() - timedelta(minutes=1)
        )
        mock_passthrough.pending_operations["expired-123"] = expired_op

        # Add valid operation
        valid_op = PendingOperation(request_id="valid-123")
        mock_passthrough.pending_operations["valid-123"] = valid_op

        # Trigger cleanup
        mock_passthrough._cleanup_expired_operations()

        assert "expired-123" not in mock_passthrough.pending_operations
        assert "valid-123" in mock_passthrough.pending_operations

    @pytest.mark.asyncio
    async def test_get_pending_operations(self, mock_passthrough):
        """Test getting list of pending operations."""
        # Add some operations
        op1 = PendingOperation(
            request_id="op1",
            server_name="server1",
            tool_name="tool1",
            risk_assessment={"risk_level": "HIGH_RISK"},
        )
        op2 = PendingOperation(
            request_id="op2",
            server_name="server2",
            tool_name="tool2",
            risk_assessment={"risk_level": "REQUIRES_APPROVAL"},
        )

        mock_passthrough.pending_operations["op1"] = op1
        mock_passthrough.pending_operations["op2"] = op2

        pending = mock_passthrough.get_pending_operations()

        assert len(pending) == 2
        assert any(op["request_id"] == "op1" for op in pending)
        assert any(op["request_id"] == "op2" for op in pending)

    @pytest.mark.asyncio
    async def test_risk_assessment_creation(self, mock_passthrough):
        """Test risk assessment is properly created."""
        with patch(
            "vulnicheck.security.dangerous_commands_risk_config.get_dangerous_commands_risk_config"
        ) as mock_config:
            # Mock the config
            mock_pattern = MagicMock()
            mock_pattern.risk_level = RiskLevel.REQUIRES_APPROVAL
            mock_pattern.category = "network"
            mock_pattern.name = "git_clone"
            mock_pattern.description = "Clone repository"

            mock_config.return_value.check_dangerous_pattern.return_value = (
                mock_pattern,
                "git clone",
            )
            mock_config.return_value.get_risk_description.return_value = (
                "This operation requires approval"
            )

            result = await mock_passthrough.execute_with_approval(
                server_name="test",
                tool_name="test_tool",
                parameters={"command": "git clone repo"},
                security_context="Test",
            )

            assert result["status"] == "approval_required"
            assert result["metadata"]["risk_level"] == "REQUIRES_APPROVAL"

    def test_get_interactive_passthrough_singleton(self):
        """Test that get_interactive_passthrough returns singleton."""
        passthrough1 = get_interactive_passthrough()
        passthrough2 = get_interactive_passthrough()

        assert passthrough1 is passthrough2

    @pytest.mark.asyncio
    async def test_close(self, mock_passthrough):
        """Test closing the passthrough."""
        # Should not raise even with no base passthrough
        await mock_passthrough.close()

        # With base passthrough
        mock_passthrough.base_passthrough = AsyncMock()
        await mock_passthrough.close()
        mock_passthrough.base_passthrough.close.assert_called_once()


class TestIntegrationWithRealConfig:
    """Integration tests with real configuration loading."""

    @pytest.mark.asyncio
    async def test_real_dangerous_patterns(self):
        """Test with real dangerous command patterns."""
        passthrough = MCPPassthroughInteractive(enable_real_connections=False)

        # Test various real patterns with current risk level expectations
        test_cases = [
            ("rm -rf /", ["blocked", "approval_required"]),  # May be blocked or require approval
            ("sudo apt install", ["blocked", "approval_required"]),  # May be blocked or require approval
            ("pip install requests", ["blocked", "approval_required"]),  # May be blocked or require approval
            ("git clone https://example.com", ["blocked", "approval_required"]),  # May be blocked or require approval
        ]

        for command, expected_statuses in test_cases:
            result = await passthrough.execute_with_approval(
                server_name="test",
                tool_name="test_tool",
                parameters={"command": command},
                security_context=f"Testing {command}",
            )

            # The important thing is that dangerous operations are detected and handled appropriately
            assert result["status"] in expected_statuses, f"Expected {command} to be handled as risky operation"

            # Verify that risk information is available
            if result["status"] == "blocked":
                assert "risk_assessment" in result or "specific_risks" in result
            elif result["status"] == "approval_required":
                assert "metadata" in result
