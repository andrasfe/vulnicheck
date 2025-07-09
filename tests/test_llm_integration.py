"""Integration tests for LLM risk assessor with MCP passthrough."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnicheck.mcp_passthrough_with_approval import MCPPassthroughWithApproval


class TestLLMIntegration:
    """Test LLM integration with MCP passthrough."""

    @pytest.mark.asyncio
    async def test_llm_verdict_skips_pattern_matching(self):
        """Test that when LLM provides a verdict, pattern matching is skipped."""
        # Mock LLM assessor to return a HIGH_RISK verdict
        with patch("vulnicheck.mcp_passthrough_with_approval.get_risk_assessor") as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = True
            mock_assessor.assess_request = AsyncMock(
                return_value=(False, "HIGH_RISK", "LLM detected security risk")
            )
            mock_get_assessor.return_value = mock_assessor

            # Mock pattern matching config to track if it's called
            with patch("vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config") as mock_get_config:
                mock_config = MagicMock()
                mock_config.check_dangerous_pattern = MagicMock(return_value=None)
                mock_get_config.return_value = mock_config

                # Create passthrough without approval callback (will block risky ops)
                passthrough = MCPPassthroughWithApproval(
                    agent_name="test",
                    enable_real_connections=False,
                    approval_callback=None,
                )

                # Execute a potentially dangerous operation
                result = await passthrough.execute_with_security(
                    "test_server",
                    "execute_command",
                    {"command": "rm -rf /"},
                )

                # Verify LLM was called
                mock_assessor.assess_request.assert_called_once()

                # Verify pattern matching was NOT called
                mock_get_config.assert_not_called()
                mock_config.check_dangerous_pattern.assert_not_called()

                # Verify operation was blocked due to no approval mechanism
                assert result["status"] == "blocked"
                assert "requires approval" in result["reason"]
                assert result["risk_assessment"]["assessment_type"] == "ai"
                assert result["risk_assessment"]["assessment_method"] == "llm_risk_assessor"

    @pytest.mark.asyncio
    async def test_llm_safe_verdict_skips_pattern_matching(self):
        """Test that when LLM says operation is safe, pattern matching is skipped."""
        # Mock LLM assessor to return safe verdict
        with patch("vulnicheck.mcp_passthrough_with_approval.get_risk_assessor") as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = True
            mock_assessor.assess_request = AsyncMock(
                return_value=(True, "SAFE", "Operation is safe")
            )
            mock_get_assessor.return_value = mock_assessor

            # Mock pattern matching config to track if it's called
            with patch("vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config") as mock_get_config:
                mock_config = MagicMock()
                mock_config.check_dangerous_pattern = MagicMock(return_value=None)
                mock_get_config.return_value = mock_config

                # Create passthrough
                passthrough = MCPPassthroughWithApproval(
                    agent_name="test",
                    enable_real_connections=False,
                )

                # Execute an operation
                result = await passthrough.execute_with_security(
                    "test_server",
                    "list_files",
                    {"path": "/home"},
                )

                # Verify LLM was called
                mock_assessor.assess_request.assert_called_once()

                # Verify pattern matching was NOT called
                mock_get_config.assert_not_called()
                mock_config.check_dangerous_pattern.assert_not_called()

                # Verify operation was allowed
                assert result["status"] == "mock"  # Since real connections are disabled

    @pytest.mark.asyncio
    async def test_llm_disabled_falls_back_to_pattern_matching(self):
        """Test that when LLM is disabled, pattern matching is used."""
        # Mock LLM assessor as disabled
        with patch("vulnicheck.mcp_passthrough_with_approval.get_risk_assessor") as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = False
            mock_get_assessor.return_value = mock_assessor

            # Mock pattern matching config
            with patch("vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config") as mock_get_config:
                mock_config = MagicMock()
                # Return None to indicate no dangerous pattern found
                mock_config.check_dangerous_pattern = MagicMock(return_value=None)
                mock_get_config.return_value = mock_config

                # Create passthrough
                passthrough = MCPPassthroughWithApproval(
                    agent_name="test",
                    enable_real_connections=False,
                )

                # Execute an operation
                result = await passthrough.execute_with_security(
                    "test_server",
                    "list_files",
                    {"path": "/home"},
                )

                # Verify LLM was NOT called (since it's disabled)
                assert not hasattr(mock_assessor, "assess_request") or not mock_assessor.assess_request.called

                # Verify pattern matching WAS called
                mock_get_config.assert_called_once()
                mock_config.check_dangerous_pattern.assert_called_once()

                # Verify operation was allowed (no dangerous pattern)
                assert result["status"] == "mock"

    @pytest.mark.asyncio
    async def test_llm_error_falls_back_to_pattern_matching(self):
        """Test that when LLM fails with error, pattern matching is used as fallback."""
        # Mock LLM assessor to raise an error
        with patch("vulnicheck.mcp_passthrough_with_approval.get_risk_assessor") as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = True
            mock_assessor.assess_request = AsyncMock(
                side_effect=Exception("LLM API error")
            )
            mock_get_assessor.return_value = mock_assessor

            # Mock pattern matching config
            with patch("vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config") as mock_get_config:
                mock_config = MagicMock()
                # Return None to indicate no dangerous pattern found
                mock_config.check_dangerous_pattern = MagicMock(return_value=None)
                mock_get_config.return_value = mock_config

                # Create passthrough
                passthrough = MCPPassthroughWithApproval(
                    agent_name="test",
                    enable_real_connections=False,
                )

                # Execute an operation
                result = await passthrough.execute_with_security(
                    "test_server",
                    "list_files",
                    {"path": "/home"},
                )

                # Verify LLM was called and failed
                mock_assessor.assess_request.assert_called_once()

                # Verify pattern matching WAS called as fallback
                mock_get_config.assert_called_once()
                mock_config.check_dangerous_pattern.assert_called_once()

                # Verify operation was allowed (no dangerous pattern)
                assert result["status"] == "mock"

    @pytest.mark.asyncio
    async def test_llm_blocked_verdict_returns_immediately(self):
        """Test that when LLM returns BLOCKED verdict, operation is blocked immediately."""
        # Mock LLM assessor to return BLOCKED verdict
        with patch("vulnicheck.mcp_passthrough_with_approval.get_risk_assessor") as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = True
            mock_assessor.assess_request = AsyncMock(
                return_value=(False, "BLOCKED", "Operation is too dangerous")
            )
            mock_get_assessor.return_value = mock_assessor

            # Mock pattern matching config to track if it's called
            with patch("vulnicheck.mcp_passthrough_with_approval.get_dangerous_commands_risk_config") as mock_get_config:
                mock_config = MagicMock()
                mock_get_config.return_value = mock_config

                # Create passthrough
                passthrough = MCPPassthroughWithApproval(
                    agent_name="test",
                    enable_real_connections=False,
                )

                # Execute a dangerous operation
                result = await passthrough.execute_with_security(
                    "test_server",
                    "execute_command",
                    {"command": "rm -rf /"},
                )

                # Verify LLM was called
                mock_assessor.assess_request.assert_called_once()

                # Verify pattern matching was NOT called
                mock_get_config.assert_not_called()

                # Verify operation was blocked
                assert result["status"] == "blocked"
                assert "LLM security assessment blocked operation" in result["reason"]
                assert result["risk_assessment"]["assessment_type"] == "ai"
                assert result["risk_assessment"]["risk_level"] == "BLOCKED"
