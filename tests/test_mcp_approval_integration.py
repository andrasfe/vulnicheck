"""
Tests for the MCP approval integration.
"""

import pytest

from vulnicheck.mcp.mcp_approval_integration import (
    MCPApprovalIntegration,
    get_mcp_integration,
    mcp_approval_callback,
)
from vulnicheck.mcp.mcp_passthrough_with_approval import (
    ApprovalRequest,
)
from vulnicheck.security.dangerous_commands_risk_config import RiskLevel


class TestMCPApprovalIntegration:
    """Test the MCP approval integration functionality."""

    def test_init(self):
        """Test initialization of MCPApprovalIntegration."""
        integration = MCPApprovalIntegration()
        assert integration.pending_approvals == {}

    @pytest.mark.asyncio
    async def test_request_client_approval(self):
        """Test formatting an approval request for MCP client."""
        integration = MCPApprovalIntegration()

        request = ApprovalRequest(
            server_name="test_server",
            tool_name="dangerous_tool",
            parameters={"command": "rm -rf /tmp/test"},
            risk_assessment={
                "risk_level": RiskLevel.HIGH_RISK.value,
                "category": "filesystem",
                "pattern_name": "rm_recursive",
                "matched_text": "rm -rf",
                "description": "Delete directory recursively",
                "risk_explanation": "This operation is high risk",
            },
        )

        result = await integration.request_client_approval(request)

        assert result["status"] == "approval_required"
        assert result["request_id"] == request.request_id
        assert "SECURITY APPROVAL REQUIRED" in result["display_message"]
        assert "HIGH RISK OPERATION" in result["display_message"]
        assert request.request_id in integration.pending_approvals

    @pytest.mark.asyncio
    async def test_request_client_approval_requires_approval(self):
        """Test formatting an approval request for REQUIRES_APPROVAL level."""
        integration = MCPApprovalIntegration()

        request = ApprovalRequest(
            server_name="test_server",
            tool_name="install_tool",
            parameters={"package": "requests"},
            risk_assessment={
                "risk_level": RiskLevel.REQUIRES_APPROVAL.value,
                "category": "package",
                "pattern_name": "pip_install",
                "matched_text": "pip install",
                "description": "Install Python package",
                "risk_explanation": "This operation requires approval",
            },
            security_context="Installing package for API testing",
        )

        result = await integration.request_client_approval(request)

        assert result["status"] == "approval_required"
        assert "APPROVAL REQUIRED" in result["display_message"]
        assert "Installing package for API testing" in result["display_message"]

    @pytest.mark.asyncio
    async def test_process_approval_decision_approved(self):
        """Test processing an approval decision."""
        integration = MCPApprovalIntegration()

        # First create a pending request
        request = ApprovalRequest(
            server_name="test_server",
            tool_name="test_tool",
            parameters={"test": "value"},
            risk_assessment={"risk_level": "HIGH_RISK"},
        )
        integration.pending_approvals[request.request_id] = request

        # Process approval
        response = await integration.process_approval_decision(
            request_id=request.request_id, approved=True, reason="Testing purposes"
        )

        assert response.request_id == request.request_id
        assert response.approved is True
        assert response.reason == "Testing purposes"
        assert request.request_id not in integration.pending_approvals

    @pytest.mark.asyncio
    async def test_process_approval_decision_denied(self):
        """Test processing a denial decision."""
        integration = MCPApprovalIntegration()

        # First create a pending request
        request = ApprovalRequest(
            server_name="test_server",
            tool_name="test_tool",
            parameters={"test": "value"},
            risk_assessment={"risk_level": "HIGH_RISK"},
        )
        integration.pending_approvals[request.request_id] = request

        # Process denial
        response = await integration.process_approval_decision(
            request_id=request.request_id,
            approved=False,
            reason="Too risky",
            suggested_alternative="Use read-only operation",
        )

        assert response.request_id == request.request_id
        assert response.approved is False
        assert response.reason == "Too risky"
        assert response.suggested_alternative == "Use read-only operation"
        assert request.request_id not in integration.pending_approvals

    @pytest.mark.asyncio
    async def test_process_approval_decision_not_found(self):
        """Test processing approval for non-existent request."""
        integration = MCPApprovalIntegration()

        with pytest.raises(ValueError, match="No pending approval found"):
            await integration.process_approval_decision(
                request_id="nonexistent", approved=True, reason="Test"
            )

    def test_get_pending_approval(self):
        """Test getting a pending approval request."""
        integration = MCPApprovalIntegration()

        request = ApprovalRequest(
            server_name="test_server",
            tool_name="test_tool",
            parameters={"test": "value"},
            risk_assessment={"risk_level": "HIGH_RISK"},
        )
        integration.pending_approvals[request.request_id] = request

        # Get existing request
        retrieved = integration.get_pending_approval(request.request_id)
        assert retrieved == request

        # Get non-existent request
        assert integration.get_pending_approval("nonexistent") is None

    @pytest.mark.asyncio
    async def test_mcp_approval_callback_high_risk(self):
        """Test the approval callback for high-risk operations."""
        request = ApprovalRequest(
            server_name="test_server",
            tool_name="dangerous_tool",
            parameters={"command": "sudo rm -rf /"},
            risk_assessment={
                "risk_level": RiskLevel.HIGH_RISK.value,
                "category": "privilege",
                "description": "Run command as root",
            },
        )

        response = await mcp_approval_callback(request)

        assert response.approved is False
        assert "explicit user confirmation" in response.reason
        assert response.suggested_alternative is not None

    @pytest.mark.asyncio
    async def test_mcp_approval_callback_requires_approval_test_context(self):
        """Test the approval callback with test context."""
        request = ApprovalRequest(
            server_name="test_server",
            tool_name="install_tool",
            parameters={"package": "pytest"},
            risk_assessment={
                "risk_level": RiskLevel.REQUIRES_APPROVAL.value,
                "category": "package",
                "description": "Install Python package",
            },
            security_context="Installing package for testing demo",
        )

        response = await mcp_approval_callback(request)

        assert response.approved is True
        assert "testing/demo purposes" in response.reason

    @pytest.mark.asyncio
    async def test_mcp_approval_callback_requires_approval_readonly(self):
        """Test the approval callback with read-only parameters."""
        request = ApprovalRequest(
            server_name="test_server",
            tool_name="git_tool",
            parameters={"command": "git log --oneline", "readonly": True},
            risk_assessment={
                "risk_level": RiskLevel.REQUIRES_APPROVAL.value,
                "category": "command",
                "description": "Run git command",
            },
        )

        response = await mcp_approval_callback(request)

        assert response.approved is True
        assert "read-only or safe" in response.reason

    @pytest.mark.asyncio
    async def test_mcp_approval_callback_low_risk(self):
        """Test the approval callback for low-risk operations."""
        request = ApprovalRequest(
            server_name="test_server",
            tool_name="list_tool",
            parameters={"path": "/tmp"},
            risk_assessment={
                "risk_level": RiskLevel.LOW_RISK.value,
                "category": "filesystem",
                "description": "List directory contents",
            },
        )

        response = await mcp_approval_callback(request)

        assert response.approved is True
        assert "acceptable risk level" in response.reason

    def test_get_mcp_integration(self):
        """Test getting the global MCP integration instance."""
        integration1 = get_mcp_integration()
        integration2 = get_mcp_integration()

        # Should return the same instance
        assert integration1 is integration2
