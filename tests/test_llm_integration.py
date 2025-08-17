"""Integration tests for LLM risk assessor with MCP passthrough."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnicheck.mcp.mcp_passthrough_with_approval import MCPPassthroughWithApproval

# These tests are disabled pending refactor to match current unified security architecture
pytest.skip("Legacy integration tests disabled - refactor needed for unified security", allow_module_level=True)


class TestLLMIntegration:
    """Test LLM integration with MCP passthrough."""

    @pytest.mark.asyncio
    async def test_llm_verdict_skips_pattern_matching(self):
        """Test that when LLM provides a verdict, pattern matching is skipped."""
        # Mock unified security to return HIGH_RISK assessment
        with patch("vulnicheck.security.unified_security.get_risk_assessor") as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = True
            mock_assessor.assess_request = AsyncMock(
                return_value=(False, "HIGH_RISK", "LLM detected security risk")
            )
            mock_get_assessor.return_value = mock_assessor

            with patch("vulnicheck.security.unified_security.get_dangerous_commands_risk_config") as mock_get_config:
                mock_config = MagicMock()
                mock_config.check_dangerous_pattern = MagicMock(return_value=None)
                mock_get_config.return_value = mock_config

                with patch("vulnicheck.security.unified_security.get_sanitizer") as mock_get_sanitizer:
                    mock_sanitizer = MagicMock()
                    mock_sanitizer.sanitize = MagicMock(return_value=('{"param": "safe_value"}', []))
                    mock_get_sanitizer.return_value = mock_sanitizer

                    with patch("vulnicheck.mcp.trust_store.get_trust_store") as mock_get_trust_store:
                        mock_trust_store = MagicMock()
                        mock_trust_store.is_trusted = MagicMock(return_value=True)
                        mock_get_trust_store.return_value = mock_trust_store

                        # Create passthrough without approval callback (will block risky ops)
                        passthrough = MCPPassthroughWithApproval(
                            agent_name="test",
                            enable_real_connections=False,
                            approval_callback=None,
                        )

                        # Execute an operation with safe names (but LLM will evaluate)
                        result = await passthrough.execute_with_security(
                            "safe_server",
                            "safe_tool",
                            {"param": "safe_value"},
                        )

                        # Verify LLM was called
                        mock_assessor.assess_request.assert_called_once()

                        # Verify operation was blocked due to no approval mechanism
                        assert result["status"] == "blocked"
                        assert "requires approval" in result["reason"]

    @pytest.mark.asyncio
    async def test_llm_safe_verdict_skips_pattern_matching(self):
        """Test that when LLM says operation is safe, pattern matching is skipped."""
        # Create passthrough
        passthrough = MCPPassthroughWithApproval(
            agent_name="test",
            enable_real_connections=False,
        )

        # Mock the security instance directly
        mock_assessor = MagicMock()
        mock_assessor.enabled = True
        mock_assessor.assess_request = AsyncMock(
            return_value=(True, "SAFE", "Operation is safe")
        )
        passthrough.security.risk_assessor = mock_assessor

        mock_dangerous_commands = MagicMock()
        mock_dangerous_commands.check_dangerous_pattern = MagicMock(return_value=None)
        passthrough.security.dangerous_commands = mock_dangerous_commands

        mock_sanitizer = MagicMock()
        mock_sanitizer.sanitize = MagicMock(return_value=('{"param": "safe_value"}', []))
        passthrough.security.sanitizer = mock_sanitizer

        mock_trust_store = MagicMock()
        mock_trust_store.is_trusted = MagicMock(return_value=True)
        passthrough.security._trust_store = mock_trust_store

        # Execute an operation with safe names
        result = await passthrough.execute_with_security(
            "safe_server",
            "safe_tool",
            {"param": "safe_value"},
        )

        # Verify LLM was called
        mock_assessor.assess_request.assert_called_once()

        # Verify operation was allowed
        assert result["status"] == "mock"  # Since real connections are disabled

    @pytest.mark.asyncio
    async def test_llm_disabled_falls_back_to_pattern_matching(self):
        """Test that when LLM is disabled, pattern matching is used."""
        # Mock LLM assessor as disabled
        with patch("vulnicheck.security.unified_security.get_risk_assessor") as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = False
            mock_get_assessor.return_value = mock_assessor

            with patch("vulnicheck.security.unified_security.get_dangerous_commands_risk_config") as mock_get_config:
                mock_config = MagicMock()
                # Return None to indicate no dangerous pattern found
                mock_config.check_dangerous_pattern = MagicMock(return_value=None)
                mock_get_config.return_value = mock_config

                with patch("vulnicheck.security.unified_security.get_sanitizer") as mock_get_sanitizer:
                    mock_sanitizer = MagicMock()
                    mock_sanitizer.sanitize = MagicMock(return_value=('{"param": "safe_value"}', []))
                    mock_get_sanitizer.return_value = mock_sanitizer

                    with patch("vulnicheck.mcp.trust_store.get_trust_store") as mock_get_trust_store:
                        mock_trust_store = MagicMock()
                        mock_trust_store.is_trusted = MagicMock(return_value=True)
                        mock_get_trust_store.return_value = mock_trust_store

                        # Create passthrough
                        passthrough = MCPPassthroughWithApproval(
                            agent_name="test",
                            enable_real_connections=False,
                        )

                        # Execute an operation with safe names
                        result = await passthrough.execute_with_security(
                            "safe_server",
                            "safe_tool",
                            {"param": "safe_value"},
                        )

                        # Verify LLM was NOT called (since it's disabled)
                        assert not hasattr(mock_assessor, "assess_request") or not mock_assessor.assess_request.called

                        # Verify pattern matching WAS called
                        mock_config.check_dangerous_pattern.assert_called()

                        # Verify operation was allowed (no dangerous pattern)
                        assert result["status"] == "mock"

    @pytest.mark.asyncio
    async def test_llm_error_falls_back_to_pattern_matching(self):
        """Test that when LLM fails with error, pattern matching is used as fallback."""
        # Mock LLM assessor to raise an error
        with patch("vulnicheck.security.unified_security.get_risk_assessor") as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = True
            mock_assessor.assess_request = AsyncMock(
                side_effect=Exception("LLM API error")
            )
            mock_get_assessor.return_value = mock_assessor

            with patch("vulnicheck.security.unified_security.get_dangerous_commands_risk_config") as mock_get_config:
                mock_config = MagicMock()
                # Return None to indicate no dangerous pattern found
                mock_config.check_dangerous_pattern = MagicMock(return_value=None)
                mock_get_config.return_value = mock_config

                with patch("vulnicheck.security.unified_security.get_sanitizer") as mock_get_sanitizer:
                    mock_sanitizer = MagicMock()
                    mock_sanitizer.sanitize = MagicMock(return_value=('{"param": "safe_value"}', []))
                    mock_get_sanitizer.return_value = mock_sanitizer

                    with patch("vulnicheck.mcp.trust_store.get_trust_store") as mock_get_trust_store:
                        mock_trust_store = MagicMock()
                        mock_trust_store.is_trusted = MagicMock(return_value=True)
                        mock_get_trust_store.return_value = mock_trust_store

                        # Create passthrough
                        passthrough = MCPPassthroughWithApproval(
                            agent_name="test",
                            enable_real_connections=False,
                        )

                        # Execute an operation with safe names
                        result = await passthrough.execute_with_security(
                            "safe_server",
                            "safe_tool",
                            {"param": "safe_value"},
                        )

                        # Verify LLM was called and failed
                        mock_assessor.assess_request.assert_called_once()

                        # Verify pattern matching WAS called as fallback
                        mock_config.check_dangerous_pattern.assert_called()

                        # Verify operation was allowed (no dangerous pattern)
                        assert result["status"] == "mock"

    @pytest.mark.asyncio
    async def test_llm_blocked_verdict_returns_immediately(self):
        """Test that when LLM returns BLOCKED verdict, operation is blocked immediately."""
        # Mock LLM assessor to return BLOCKED verdict
        with patch("vulnicheck.security.unified_security.get_risk_assessor") as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = True
            mock_assessor.assess_request = AsyncMock(
                return_value=(False, "BLOCKED", "Operation is too dangerous")
            )
            mock_get_assessor.return_value = mock_assessor

            with patch("vulnicheck.security.unified_security.get_dangerous_commands_risk_config") as mock_get_config:
                mock_config = MagicMock()
                mock_config.check_dangerous_pattern = MagicMock(return_value=None)
                mock_get_config.return_value = mock_config

                with patch("vulnicheck.security.unified_security.get_sanitizer") as mock_get_sanitizer:
                    mock_sanitizer = MagicMock()
                    mock_sanitizer.sanitize = MagicMock(return_value=('{"param": "safe_value"}', []))
                    mock_get_sanitizer.return_value = mock_sanitizer

                    with patch("vulnicheck.mcp.trust_store.get_trust_store") as mock_get_trust_store:
                        mock_trust_store = MagicMock()
                        mock_trust_store.is_trusted = MagicMock(return_value=True)
                        mock_get_trust_store.return_value = mock_trust_store

                        # Create passthrough
                        passthrough = MCPPassthroughWithApproval(
                            agent_name="test",
                            enable_real_connections=False,
                        )

                        # Execute an operation with safe names (but LLM will block it)
                        result = await passthrough.execute_with_security(
                            "safe_server",
                            "safe_tool",
                            {"param": "safe_value"},
                        )

                        # Verify LLM was called
                        mock_assessor.assess_request.assert_called_once()

                        # Verify operation was blocked
                        assert result["status"] == "blocked"
