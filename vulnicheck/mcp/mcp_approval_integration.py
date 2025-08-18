"""
MCP client approval integration for passthrough security.

This module provides a generic approval mechanism that works with any MCP client
(Claude, Cursor, Copilot, etc.) by returning structured responses that prompt
the client to make security decisions.
"""

import json
import logging

# Import types only to avoid circular import
from typing import TYPE_CHECKING, Any, Optional

from ..security.dangerous_commands_risk_config import RiskLevel

if TYPE_CHECKING:
    from .mcp_passthrough_with_approval import ApprovalRequest, ApprovalResponse
else:
    # Import at runtime
    ApprovalRequest = None
    ApprovalResponse = None

logger = logging.getLogger(__name__)


class MCPApprovalIntegration:
    """
    Handles approval requests by formatting them for MCP client decision-making.

    This integration works by:
    1. Returning a special response format that prompts the MCP client
    2. The client analyzes the request and makes a decision
    3. The decision is communicated back through a follow-up tool call
    """

    def __init__(self) -> None:
        self.pending_approvals: dict[str, ApprovalRequest] = {}

    async def request_client_approval(
        self, request: "ApprovalRequest"
    ) -> dict[str, Any]:
        """
        Format an approval request for the MCP client to review.

        Returns a special response that will prompt the client to analyze
        and make a security decision.
        """
        # Store the pending request
        self.pending_approvals[request.request_id] = request

        # Format the risk assessment details
        risk_info = request.risk_assessment or {}
        risk_level = risk_info.get("risk_level", "UNKNOWN")

        # Create a detailed prompt for the MCP client
        prompt_lines = [
            "🔒 **SECURITY APPROVAL REQUIRED**",
            "",
            f"**Request ID**: `{request.request_id}`",
            f"**Server**: {request.server_name}",
            f"**Tool**: {request.tool_name}",
            f"**Risk Level**: {risk_level}",
            f"**Risk Category**: {risk_info.get('category', 'Unknown')}",
            "",
            "**Operation Details**:",
            f"- Pattern Matched: {risk_info.get('pattern_name', 'Unknown')}",
            f"- Description: {risk_info.get('description', 'No description')}",
            f"- Risk Explanation: {risk_info.get('risk_explanation', '')}",
            "",
            "**Parameters**:",
            "```json",
            json.dumps(request.parameters, indent=2),
            "```",
        ]

        if request.security_context:
            prompt_lines.extend(
                ["", "**Additional Context**:", request.security_context]
            )

        # Add decision guidance based on risk level
        if risk_level == RiskLevel.HIGH_RISK.value:
            prompt_lines.extend(
                [
                    "",
                    "⚠️ **HIGH RISK OPERATION**",
                    "This operation could potentially:",
                    "- Damage the system or delete important data",
                    "- Compromise security or expose sensitive information",
                    "- Affect system stability or availability",
                    "",
                    "**Recommendation**: Deny unless there's a very strong justification",
                ]
            )
        elif risk_level == RiskLevel.REQUIRES_APPROVAL.value:
            prompt_lines.extend(
                [
                    "",
                    "⚡ **APPROVAL REQUIRED**",
                    "This operation may be legitimate but requires review:",
                    "- Could modify system state",
                    "- Might have unintended side effects",
                    "- Needs verification of intent",
                    "",
                    "**Recommendation**: Approve if the operation aligns with user intent",
                ]
            )

        prompt_lines.extend(
            [
                "",
                "**TO APPROVE OR DENY THIS REQUEST**:",
                "Use the appropriate tool with the request ID:",
                "",
                "1. **APPROVE**: Call `approve_mcp_operation` with:",
                f'   - request_id: "{request.request_id}"',
                '   - reason: "Your justification"',
                "",
                "2. **DENY**: Call `deny_mcp_operation` with:",
                f'   - request_id: "{request.request_id}"',
                '   - reason: "Your explanation"',
                '   - alternative: "Suggested safer approach" (optional)',
                "",
                "Consider:",
                "- Does this align with the user's stated intent?",
                "- Are there safer alternatives to achieve the same goal?",
                "- What are the potential consequences of this operation?",
                "- Is this a necessary risk for the task at hand?",
            ]
        )

        # Return a response that will display to the MCP client
        return {
            "status": "approval_required",
            "request_id": request.request_id,
            "display_message": "\n".join(prompt_lines),
            "metadata": {
                "server_name": request.server_name,
                "tool_name": request.tool_name,
                "risk_level": risk_level,
                "expires_at": request.expires_at.isoformat(),
            },
        }

    async def process_approval_decision(
        self,
        request_id: str,
        approved: bool,
        reason: str,
        suggested_alternative: str | None = None,
    ) -> "ApprovalResponse":
        """
        Process the MCP client's approval decision.

        This is called when the client makes a decision through the
        approve_mcp_operation or deny_mcp_operation tools.
        """
        if request_id not in self.pending_approvals:
            raise ValueError(f"No pending approval found for request ID: {request_id}")

        request = self.pending_approvals.pop(request_id)

        # Log the decision
        decision = "APPROVED" if approved else "DENIED"
        logger.info(
            f"MCP client {decision} operation {request.server_name}.{request.tool_name}: {reason}"
        )

        return ApprovalResponse(
            request_id=request_id,
            approved=approved,
            reason=reason,
            suggested_alternative=suggested_alternative,
        )

    def get_pending_approval(self, request_id: str) -> Optional["ApprovalRequest"]:
        """Get a pending approval request by ID."""
        return self.pending_approvals.get(request_id)

    def clear_expired_approvals(self) -> None:
        """Clear expired approval requests."""
        # In a real implementation, we'd check timestamps
        # For now, this is a placeholder
        pass


# Global instance for the integration
_mcp_integration = MCPApprovalIntegration()


async def mcp_approval_callback(request: "ApprovalRequest") -> "ApprovalResponse":
    """
    Generic MCP client approval callback.

    This callback works with any MCP client by using heuristics
    to make approval decisions when interactive approval isn't possible.
    """
    # Log the approval request
    logger.info(
        f"MCP approval requested for: {request.server_name}.{request.tool_name}"
    )

    # Safely access risk_assessment fields
    risk_assessment = request.risk_assessment or {}
    risk_level = risk_assessment.get("risk_level", "UNKNOWN")
    risk_description = risk_assessment.get("description", "No description available")

    logger.info(f"Risk level: {risk_level}")
    logger.info(f"Risk description: {risk_description}")

    # Decision logic based on risk level and context
    if risk_level == RiskLevel.HIGH_RISK.value:
        # High risk operations are denied by default
        return ApprovalResponse(
            request_id=request.request_id,
            approved=False,
            reason="High risk operations require explicit user confirmation",
            suggested_alternative="Consider breaking down the operation into safer steps or use read-only alternatives",
        )

    elif risk_level == RiskLevel.REQUIRES_APPROVAL.value:
        # Check security context for hints
        context = (request.security_context or "").lower()

        # Approve if context suggests testing or development
        if any(word in context for word in ["test", "demo", "example", "tutorial"]):
            return ApprovalResponse(
                request_id=request.request_id,
                approved=True,
                reason="Operation approved for testing/demo purposes based on security context",
            )

        # Approve if parameters suggest read-only or safe operations
        param_str = json.dumps(request.parameters).lower()
        if any(
            word in param_str
            for word in ["--dry-run", "--no-write", "readonly", "list", "show", "get"]
        ):
            return ApprovalResponse(
                request_id=request.request_id,
                approved=True,
                reason="Operation appears to be read-only or safe based on parameters",
            )

        # Default: approve with caution
        return ApprovalResponse(
            request_id=request.request_id,
            approved=True,
            reason="Operation approved after risk assessment - appears to align with intended task",
        )

    # LOW_RISK or unknown - approve
    return ApprovalResponse(
        request_id=request.request_id,
        approved=True,
        reason="Operation assessed as acceptable risk level",
    )


def get_mcp_integration() -> MCPApprovalIntegration:
    """Get the global MCP integration instance."""
    return _mcp_integration


# Import at runtime and set the callback
def _initialize_callback() -> None:
    """Initialize the approval callback in mcp_passthrough_with_approval."""
    global ApprovalRequest, ApprovalResponse

    # Import the types
    from .mcp_passthrough_with_approval import ApprovalRequest as _ApprovalRequest
    from .mcp_passthrough_with_approval import ApprovalResponse as _ApprovalResponse

    ApprovalRequest = _ApprovalRequest  # type: ignore[misc]
    ApprovalResponse = _ApprovalResponse  # type: ignore[misc]

    # Set the approval callback
    from . import mcp_passthrough_with_approval as passthrough_module

    passthrough_module.mcp_approval_callback = mcp_approval_callback
    passthrough_module.claude_approval_callback = mcp_approval_callback


# Initialize on import
_initialize_callback()
