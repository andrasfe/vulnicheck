"""
Comprehensive tests for unified MCP passthrough implementation.

This test suite verifies that the unified implementation maintains
complete backward compatibility with all three original implementations.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from vulnicheck.mcp.unified_passthrough import (
    ApprovalMode,
    ApprovalResult,
    ApprovalStatus,
    AutoApprovalStrategy,
    CallbackApprovalStrategy,
    InteractiveApprovalStrategy,
    MCPPassthrough,
    MCPPassthroughInteractive,
    MCPPassthroughWithApproval,
    Operation,
    UnifiedPassthrough,
)
from vulnicheck.security import RiskLevel


class TestUnifiedPassthrough:
    """Test the core unified passthrough implementation."""

    def test_initialization_modes(self):
        """Test initialization with different approval modes."""
        # Auto mode
        passthrough = UnifiedPassthrough(approval_mode=ApprovalMode.AUTO)
        assert isinstance(passthrough.approval_strategy, AutoApprovalStrategy)

        # Callback mode
        async def callback(op: Operation) -> ApprovalResult:
            return ApprovalResult(approved=True, reason="test")

        passthrough = UnifiedPassthrough(
            approval_mode=ApprovalMode.CALLBACK,
            approval_callback=callback
        )
        assert isinstance(passthrough.approval_strategy, CallbackApprovalStrategy)

        # Interactive mode
        passthrough = UnifiedPassthrough(approval_mode=ApprovalMode.INTERACTIVE)
        assert isinstance(passthrough.approval_strategy, InteractiveApprovalStrategy)

    @pytest.mark.asyncio
    async def test_execute_with_security_safe_operation(self):
        """Test execution of safe operations across all modes."""
        for mode in ApprovalMode:
            passthrough = UnifiedPassthrough(
                approval_mode=mode,
                enable_real_connections=False
            )

            result = await passthrough.execute_with_security(
                server_name="test-server",
                tool_name="safe_tool",
                parameters={"action": "list"},
                security_context="Test context"
            )

            assert result["status"] == "mock"
            assert "requested_call" in result
            assert result["requested_call"]["server"] == "test-server"
            assert result["requested_call"]["tool"] == "safe_tool"

    @pytest.mark.asyncio
    async def test_execute_with_security_blocked_operation(self):
        """Test that dangerous operations are blocked in all modes."""
        dangerous_params = {
            "file_path": "/etc/shadow"  # Known dangerous path
        }

        for mode in ApprovalMode:
            passthrough = UnifiedPassthrough(
                approval_mode=mode,
                enable_real_connections=False
            )

            result = await passthrough.execute_with_security(
                server_name="file-server",
                tool_name="read_file",
                parameters=dangerous_params,
                security_context="Dangerous test"
            )

            assert result["status"] == "blocked"
            assert "reason" in result

    def test_validate_server_access(self):
        """Test server access validation."""
        passthrough = UnifiedPassthrough()

        # Valid servers
        assert passthrough.validate_server_access("my-server") is True
        assert passthrough.validate_server_access("data-processor") is True

        # Blocked servers
        assert passthrough.validate_server_access("system") is False
        assert passthrough.validate_server_access("admin") is False
        assert passthrough.validate_server_access("root") is False


class TestBackwardCompatibility:
    """Test backward compatibility with original implementations."""

    def test_mcp_passthrough_compatibility(self):
        """Test MCPPassthrough wrapper maintains compatibility."""
        passthrough = MCPPassthrough(enable_real_connections=False)

        # Check attributes exist
        assert hasattr(passthrough, "agent_name")
        assert hasattr(passthrough, "security_prompt_template")
        assert hasattr(passthrough, "execute_with_security")
        assert hasattr(passthrough, "validate_server_access")

        # Check security prompt template
        assert "SECURITY NOTICE" in passthrough.security_prompt_template
        assert "{server_name}" in passthrough.security_prompt_template

    def test_mcp_passthrough_with_approval_compatibility(self):
        """Test MCPPassthroughWithApproval wrapper maintains compatibility."""
        async def callback(op: Operation) -> ApprovalResult:
            return ApprovalResult(approved=True, reason="test")

        passthrough = MCPPassthroughWithApproval(
            approval_callback=callback,
            auto_approve_low_risk=True,
            enable_real_connections=False
        )

        # Check attributes exist
        assert hasattr(passthrough, "approval_callback")
        assert hasattr(passthrough, "auto_approve_low_risk")
        assert hasattr(passthrough, "pending_approvals")
        assert hasattr(passthrough, "security_prompt_template")

        # Check values
        assert passthrough.approval_callback == callback
        assert passthrough.auto_approve_low_risk is True
        assert isinstance(passthrough.pending_approvals, dict)

    def test_mcp_passthrough_interactive_compatibility(self):
        """Test MCPPassthroughInteractive wrapper maintains compatibility."""
        passthrough = MCPPassthroughInteractive(enable_real_connections=False)

        # Check attributes exist
        assert hasattr(passthrough, "pending_operations")
        assert hasattr(passthrough, "approved_operations")
        assert hasattr(passthrough, "execute_with_approval")
        assert hasattr(passthrough, "process_approval")
        assert hasattr(passthrough, "_cleanup_expired_operations")
        assert hasattr(passthrough, "base_passthrough")

        # Check types
        assert isinstance(passthrough.pending_operations, dict)
        assert isinstance(passthrough.approved_operations, dict)

    @pytest.mark.asyncio
    async def test_interactive_execute_with_approval(self):
        """Test interactive mode's execute_with_approval method."""
        passthrough = MCPPassthroughInteractive(enable_real_connections=False)

        # Safe operation should execute
        result = await passthrough.execute_with_approval(
            server_name="test-server",
            tool_name="list_files",
            parameters={"path": "/home/user"},
            security_context="Test"
        )

        assert result["status"] == "mock"

    @pytest.mark.asyncio
    async def test_interactive_approval_flow(self):
        """Test the interactive approval flow."""
        passthrough = MCPPassthroughInteractive(enable_real_connections=False)

        # Simulate a risky operation that needs approval
        with patch.object(passthrough.security, 'assess_request') as mock_assess:
            # Mock assessment to require approval
            mock_assessment = MagicMock()
            mock_assessment.is_blocked = False
            mock_assessment.requires_approval = True
            mock_assessment.risk_level = RiskLevel.HIGH_RISK
            mock_assessment.explanation = "High risk operation"
            mock_assessment.specific_risks = ["Risk 1", "Risk 2"]
            mock_assess.return_value = mock_assessment

            # Execute operation - should return approval request
            result = await passthrough.execute_with_approval(
                server_name="risky-server",
                tool_name="delete_files",
                parameters={"path": "/important/data"},
                security_context="Test deletion"
            )

            assert result["status"] == "approval_required"
            assert "request_id" in result
            request_id = result["request_id"]

            # Verify operation is pending
            assert request_id in passthrough.pending_operations

            # Process approval
            approval_result = await passthrough.process_approval(
                request_id=request_id,
                approved=True,
                reason="Test approval"
            )

            assert approval_result["status"] == "approved"
            assert request_id in passthrough.approved_operations

            # Re-execute should use pre-approval
            result2 = await passthrough.execute_with_approval(
                server_name="risky-server",
                tool_name="delete_files",
                parameters={"path": "/important/data"},
                security_context="Test deletion"
            )

            assert result2["status"] == "mock"  # Should execute in mock mode

    @pytest.mark.asyncio
    async def test_callback_approval_flow(self):
        """Test the callback-based approval flow."""
        approval_called = False

        async def approval_callback(operation: Operation) -> ApprovalResult:
            nonlocal approval_called
            approval_called = True
            return ApprovalResult(
                approved=True,
                reason="Approved in test"
            )

        passthrough = MCPPassthroughWithApproval(
            approval_callback=approval_callback,
            auto_approve_low_risk=False,
            enable_real_connections=False
        )

        with patch.object(passthrough.security, 'assess_request') as mock_assess:
            # Mock assessment to require approval
            mock_assessment = MagicMock()
            mock_assessment.is_blocked = False
            mock_assessment.requires_approval = True
            mock_assessment.risk_level = RiskLevel.REQUIRES_APPROVAL
            mock_assessment.explanation = "Needs approval"
            mock_assessment.specific_risks = ["Risk 1"]
            mock_assess.return_value = mock_assessment

            result = await passthrough.execute_with_security(
                server_name="test-server",
                tool_name="modify_data",
                parameters={"data": "test"},
                security_context="Test"
            )

            assert approval_called
            assert result["status"] == "mock"  # Should execute after approval


class TestApprovalStrategies:
    """Test individual approval strategies."""

    @pytest.mark.asyncio
    async def test_auto_approval_strategy(self):
        """Test AutoApprovalStrategy behavior."""
        strategy = AutoApprovalStrategy()

        # Create test operation
        operation = Operation(
            server_name="test",
            tool_name="test_tool",
            parameters={}
        )

        # Test with safe assessment
        safe_assessment = MagicMock()
        safe_assessment.is_blocked = False
        safe_assessment.risk_level = RiskLevel.SAFE

        result = await strategy.handle_approval(operation, safe_assessment)
        assert result == {}  # Empty dict signals proceed
        assert strategy.should_auto_execute(safe_assessment) is True

        # Test with blocked assessment
        blocked_assessment = MagicMock()
        blocked_assessment.is_blocked = True
        blocked_assessment.risk_level = RiskLevel.BLOCKED
        blocked_assessment.explanation = "Dangerous operation"
        blocked_assessment.specific_risks = ["Risk 1"]

        result = await strategy.handle_approval(operation, blocked_assessment)
        assert result["status"] == "blocked"
        assert strategy.should_auto_execute(blocked_assessment) is False

    @pytest.mark.asyncio
    async def test_callback_approval_strategy(self):
        """Test CallbackApprovalStrategy behavior."""
        callback_invoked = False

        async def test_callback(op: Operation) -> ApprovalResult:
            nonlocal callback_invoked
            callback_invoked = True
            return ApprovalResult(approved=True, reason="Test")

        strategy = CallbackApprovalStrategy(
            callback=test_callback,
            auto_approve_low_risk=True
        )

        operation = Operation(
            server_name="test",
            tool_name="test_tool",
            parameters={}
        )

        # Test auto-approve for low risk
        low_risk_assessment = MagicMock()
        low_risk_assessment.is_blocked = False
        low_risk_assessment.risk_level = RiskLevel.LOW_RISK
        low_risk_assessment.requires_approval = False

        result = await strategy.handle_approval(operation, low_risk_assessment)
        assert result == {}  # Should auto-approve
        assert not callback_invoked
        assert strategy.should_auto_execute(low_risk_assessment) is True

        # Test callback invocation for high risk
        high_risk_assessment = MagicMock()
        high_risk_assessment.is_blocked = False
        high_risk_assessment.risk_level = RiskLevel.HIGH_RISK
        high_risk_assessment.requires_approval = True

        result = await strategy.handle_approval(operation, high_risk_assessment)
        assert callback_invoked
        assert result == {}  # Approved via callback

    @pytest.mark.asyncio
    async def test_interactive_approval_strategy(self):
        """Test InteractiveApprovalStrategy behavior."""
        strategy = InteractiveApprovalStrategy()

        operation = Operation(
            server_name="test",
            tool_name="test_tool",
            parameters={"test": "value"}
        )

        # Test approval required
        needs_approval = MagicMock()
        needs_approval.is_blocked = False
        needs_approval.requires_approval = True
        needs_approval.risk_level = RiskLevel.REQUIRES_APPROVAL
        needs_approval.explanation = "Needs review"
        needs_approval.specific_risks = ["Risk 1"]

        result = await strategy.handle_approval(operation, needs_approval)
        assert result["status"] == "approval_required"
        assert "request_id" in result
        request_id = result["request_id"]

        # Verify operation is pending
        assert request_id in strategy.pending_operations

        # Process approval
        approval_result = await strategy.process_approval_decision(
            request_id=request_id,
            approved=True,
            reason="Approved"
        )

        assert approval_result["status"] == "approved"
        assert request_id in strategy.approved_operations

        # Check pre-approval detection
        pre_approved = strategy.check_pre_approved(operation)
        assert pre_approved is not None
        assert pre_approved.request_id == request_id


class TestOperationManagement:
    """Test Operation dataclass and management."""

    def test_operation_creation(self):
        """Test Operation creation and properties."""
        operation = Operation(
            server_name="test-server",
            tool_name="test-tool",
            parameters={"key": "value"}
        )

        assert operation.server_name == "test-server"
        assert operation.tool_name == "test-tool"
        assert operation.parameters == {"key": "value"}
        assert operation.status == ApprovalStatus.PENDING
        assert not operation.is_expired

        # Test request_id is generated
        assert operation.request_id is not None
        assert len(operation.request_id) > 0

    def test_operation_expiration(self):
        """Test operation expiration logic."""
        from datetime import datetime, timedelta

        # Create expired operation
        operation = Operation(
            server_name="test",
            tool_name="test",
            created_at=datetime.now() - timedelta(minutes=10),
            expires_at=datetime.now() - timedelta(minutes=5)
        )

        assert operation.is_expired

    def test_approval_result(self):
        """Test ApprovalResult creation."""
        result = ApprovalResult(
            approved=True,
            reason="Test approval",
            suggested_alternative="Use safer method"
        )

        assert result.approved is True
        assert result.reason == "Test approval"
        assert result.suggested_alternative == "Use safer method"


class TestConversationIntegration:
    """Test conversation storage integration."""

    @pytest.mark.asyncio
    async def test_conversation_tracking(self):
        """Test that conversations are properly tracked."""
        passthrough = UnifiedPassthrough(
            approval_mode=ApprovalMode.AUTO,
            enable_real_connections=False
        )

        # Execute an operation
        await passthrough.execute_with_security(
            server_name="test-server",
            tool_name="test-tool",
            parameters={"test": "value"},
            security_context="Test context"
        )

        # Verify conversation was created
        assert len(passthrough._active_conversations) > 0
        assert "test-server" in passthrough._active_conversations


class TestErrorHandling:
    """Test error handling and edge cases."""

    @pytest.mark.asyncio
    async def test_invalid_approval_mode(self):
        """Test handling of invalid approval mode."""
        with pytest.raises(ValueError):
            UnifiedPassthrough(approval_mode="invalid")

    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test timeout handling in callback mode."""
        async def slow_callback(op: Operation) -> ApprovalResult:
            await asyncio.sleep(60)  # Longer than timeout
            return ApprovalResult(approved=True, reason="Too late")

        passthrough = UnifiedPassthrough(
            approval_mode=ApprovalMode.CALLBACK,
            approval_callback=slow_callback,
            enable_real_connections=False
        )

        with patch.object(passthrough.security, 'assess_request') as mock_assess:
            mock_assessment = MagicMock()
            mock_assessment.is_blocked = False
            mock_assessment.requires_approval = True
            mock_assessment.risk_level = RiskLevel.HIGH_RISK
            mock_assessment.explanation = "High risk"
            mock_assessment.specific_risks = []
            mock_assess.return_value = mock_assessment

            # Use a shorter timeout for testing
            with patch('asyncio.wait_for', side_effect=asyncio.TimeoutError):
                result = await passthrough.execute_with_security(
                    server_name="test",
                    tool_name="test",
                    parameters={},
                    security_context="Test"
                )

                assert result["status"] == "timeout"

    @pytest.mark.asyncio
    async def test_expired_operation_handling(self):
        """Test handling of expired operations in interactive mode."""
        passthrough = MCPPassthroughInteractive(enable_real_connections=False)

        # Create an expired operation manually
        from datetime import datetime, timedelta

        expired_op = Operation(
            server_name="test",
            tool_name="test",
            expires_at=datetime.now() - timedelta(minutes=1)
        )

        strategy = passthrough.approval_strategy
        if isinstance(strategy, InteractiveApprovalStrategy):
            # Don't add to pending_operations as cleanup will remove it
            # Instead, test the cleanup mechanism directly
            strategy.pending_operations[expired_op.request_id] = expired_op

            # Verify cleanup works
            strategy._cleanup_expired()
            assert expired_op.request_id not in strategy.pending_operations

            # Now add it back and test process_approval_decision directly
            strategy.pending_operations[expired_op.request_id] = expired_op

            # Don't call cleanup in process_approval - just check expiration
            await strategy.process_approval_decision(
                request_id=expired_op.request_id,
                approved=True,
                reason="Too late",
                suggested_alternative=None
            )

            # The cleanup will have removed it, so we get "not found"
            # But we can check that an expired operation gets proper handling
            # Let's directly test without cleanup
            expired_op2 = Operation(
                server_name="test2",
                tool_name="test2",
                expires_at=datetime.now() + timedelta(minutes=1)  # Not expired yet
            )
            strategy.pending_operations[expired_op2.request_id] = expired_op2

            # Now expire it
            expired_op2.expires_at = datetime.now() - timedelta(minutes=1)

            result2 = await strategy.process_approval_decision(
                request_id=expired_op2.request_id,
                approved=True,
                reason="Test",
                suggested_alternative=None
            )

            assert result2["status"] == "error"
            assert "expired" in result2["message"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
