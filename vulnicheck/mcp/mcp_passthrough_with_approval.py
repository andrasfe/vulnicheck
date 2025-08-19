"""
Compatibility wrapper for MCPPassthroughWithApproval.

This module maintains backward compatibility by re-exporting the unified implementation.
All functionality has been consolidated into unified_passthrough.py.
"""

import json
from typing import Any

# Import unified implementation
from .unified_passthrough import (
    ApprovalCallback,
    ApprovalResult,
    ApprovalStatus,
    Operation,
)
from .unified_passthrough import (
    MCPPassthroughWithApproval as UnifiedMCPPassthroughWithApproval,
)


# Create compatibility wrapper class that adds missing methods
class MCPPassthroughWithApproval(UnifiedMCPPassthroughWithApproval):
    """Compatibility wrapper for MCPPassthroughWithApproval with legacy API."""

    def _format_security_prompt(self, risk_assessment: dict[str, Any]) -> str:
        """
        Legacy compatibility method for formatting security prompts.

        Args:
            risk_assessment: Dict containing risk assessment details

        Returns:
            Formatted security prompt string
        """
        # Format the prompt to match what the test expects
        template = """
Security Assessment for MCP Operation:
- Server: {server_name}
- Tool: {tool_name}
- Risk Level: {risk_level}
- Category: {category}
- Pattern: {pattern_name}
- Description: {description}
- Risk Explanation: {risk_explanation}

Please review this operation carefully before proceeding.
"""

        return template.format(
            server_name=risk_assessment.get("server_name", "unknown"),
            tool_name=risk_assessment.get("tool_name", "unknown"),
            risk_level=risk_assessment.get("risk_level", "UNKNOWN"),
            category=risk_assessment.get("category", "unknown"),
            pattern_name=risk_assessment.get("pattern_name", "unknown"),
            description=risk_assessment.get("description", "No description"),
            risk_explanation=risk_assessment.get("risk_explanation", "No explanation")
        ).strip()

# Legacy compatibility classes
ApprovalRequest = Operation  # Map old name to new
ApprovalResponse = ApprovalResult  # Map old name to new

# Re-export other classes for compatibility
__all__ = [
    "MCPPassthroughWithApproval",
    "ApprovalStatus",
    "ApprovalRequest",
    "ApprovalResponse",
    "ApprovalCallback",
    "mcp_passthrough_tool_with_approval",
    "default_approval_callback",
    "mcp_approval_callback",
    "claude_approval_callback",
]


# Default approval callback - will be replaced by real implementation
async def default_approval_callback(request: Operation) -> ApprovalResult:
    """Default approval callback that denies high-risk operations."""
    from ..security import RiskLevel

    if request.risk_assessment and request.risk_assessment.get("risk_level") == RiskLevel.HIGH_RISK.value:
        return ApprovalResult(
            approved=False,
            reason="High risk operations require manual review",
            suggested_alternative="Consider using a safer alternative",
        )
    return ApprovalResult(
        approved=True,
        reason="Operation approved after risk assessment",
    )


# These will be set by mcp_approval_integration to avoid circular import
mcp_approval_callback = default_approval_callback
claude_approval_callback = default_approval_callback  # Backwards compatibility


# Enhanced tool function for the passthrough with approval
async def mcp_passthrough_tool_with_approval(
    server_name: str,
    tool_name: str,
    parameters: dict[str, Any] | None = None,
    security_context: str | None = None,
    agent_name: str | None = None,
) -> str:
    """
    Enhanced MCP tool call with risk assessment and approval flow.

    This version adds:
    - Risk level assessment (BLOCKED, HIGH_RISK, REQUIRES_APPROVAL, LOW_RISK)
    - Interactive approval mechanism for risky operations
    - Better risk explanations and suggested alternatives
    """
    if parameters is None:
        parameters = {}

    # Get or create passthrough with approval callback
    passthrough = MCPPassthroughWithApproval(
        agent_name=agent_name, approval_callback=mcp_approval_callback  # type: ignore[arg-type]
    )

    # Execute with enhanced security
    result = await passthrough.execute_with_security(
        server_name=server_name,
        tool_name=tool_name,
        parameters=parameters,
        security_context=security_context,
    )

    return json.dumps(result, indent=2)
