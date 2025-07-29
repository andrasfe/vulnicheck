"""
Enhanced MCP passthrough with interactive approval mechanism.

This module provides a true interactive approval flow where execution
pauses until the user explicitly approves or denies the operation.
"""

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ..core.agent_detector import detect_agent
from ..security.dangerous_commands_risk_config import (
    DangerousPattern,
    RiskLevel,
    get_dangerous_commands_risk_config,
)
from .conversation_storage import ConversationStorage
from .mcp_passthrough import MCPPassthrough

logger = logging.getLogger(__name__)


@dataclass
class PendingOperation:
    """Represents an operation waiting for approval."""

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    server_name: str = ""
    tool_name: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    risk_assessment: dict[str, Any] = field(default_factory=dict)
    security_context: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime = field(
        default_factory=lambda: datetime.now() + timedelta(minutes=5)
    )
    approved: bool = False
    approval_reason: str | None = None

    @property
    def is_expired(self) -> bool:
        """Check if this operation has expired."""
        return datetime.now() > self.expires_at


class MCPPassthroughInteractive:
    """
    Enhanced MCP passthrough with true interactive approval.

    This implementation returns a special response for operations requiring
    approval, allowing the client to make an informed decision before proceeding.
    """

    def __init__(
        self, agent_name: str | None = None, enable_real_connections: bool = True
    ):
        """Initialize the interactive passthrough."""
        self.agent_name = agent_name or detect_agent()
        self.enable_real_connections = enable_real_connections
        # Don't initialize connection pool here - let base passthrough handle it
        self.base_passthrough = (
            MCPPassthrough(agent_name=self.agent_name)
            if enable_real_connections
            else None
        )

        # Store pending operations
        self.pending_operations: dict[str, PendingOperation] = {}
        # Store approved operations for retry
        self.approved_operations: dict[str, PendingOperation] = {}

        # Conversation storage will be initialized on first use
        self._conversation_storage: ConversationStorage | None = None
        self._active_conversations: dict[str, str] = {}  # server -> conversation_id

        logger.info(
            f"Initialized interactive MCP passthrough for agent: {self.agent_name}"
        )

    def _get_conversation_storage(self) -> ConversationStorage:
        """Get or create conversation storage on demand."""
        if self._conversation_storage is None:
            self._conversation_storage = ConversationStorage()
        return self._conversation_storage

    def _get_or_create_conversation(self, server_name: str) -> str:
        """Get or create a conversation for a server."""
        if server_name in self._active_conversations:
            return self._active_conversations[server_name]

        storage = self._get_conversation_storage()

        # Try to get an active conversation
        conv = storage.get_active_conversation(self.agent_name, server_name)
        if conv:
            self._active_conversations[server_name] = conv.id
            return conv.id

        # Create a new conversation
        conv = storage.start_conversation(
            client=self.agent_name,
            server=server_name,
            metadata={"passthrough_mode": "interactive"}
        )
        self._active_conversations[server_name] = conv.id
        return conv.id

    async def execute_with_approval(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        security_context: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute an MCP tool call with interactive approval for risky operations.

        Returns either:
        - The tool result (for safe operations)
        - An approval request (for risky operations)
        - A blocked response (for dangerous operations)
        """
        # Get or create conversation
        conversation_id = self._get_or_create_conversation(server_name)
        storage = self._get_conversation_storage()

        # Log request to conversation
        storage.add_request(
            conversation_id=conversation_id,
            client=self.agent_name,
            server=server_name,
            tool=tool_name,
            parameters=parameters
        )

        # Clean up expired operations
        self._cleanup_expired_operations()

        # Check if this operation was previously approved
        for request_id, approved_op in list(self.approved_operations.items()):
            if (
                approved_op.server_name == server_name
                and approved_op.tool_name == tool_name
                and approved_op.parameters == parameters
            ):
                # Found a matching approved operation
                logger.info(f"Found pre-approved operation: {request_id}")
                del self.approved_operations[request_id]

                # Execute the approved operation
                response = await self._execute_operation(
                    server_name, tool_name, parameters, approved_op.risk_assessment
                )
                # Log response to conversation
                storage.add_response(
                    conversation_id=conversation_id,
                    client=self.agent_name,
                    server=server_name,
                    tool=tool_name,
                    result=response,
                    risk_assessment=approved_op.risk_assessment
                )
                return response

        # Check for dangerous patterns
        config = get_dangerous_commands_risk_config()
        check_str = json.dumps(
            {"server": server_name, "tool": tool_name, "params": parameters}
        ).lower()

        result = config.check_dangerous_pattern(check_str)

        if result:
            pattern, matched_text = result
            risk_assessment = self._create_risk_assessment(
                server_name, tool_name, pattern, matched_text, config
            )

            if pattern.risk_level == RiskLevel.BLOCKED:
                # Always block these operations
                response = {
                    "status": "blocked",
                    "reason": f"Operation blocked: {pattern.description}",
                    "risk_assessment": risk_assessment,
                }
                # Log response to conversation
                storage.add_response(
                    conversation_id=conversation_id,
                    client=self.agent_name,
                    server=server_name,
                    tool=tool_name,
                    result=response,
                    risk_assessment=risk_assessment
                )
                return response

            elif pattern.risk_level in [
                RiskLevel.HIGH_RISK,
                RiskLevel.REQUIRES_APPROVAL,
            ]:
                # Create pending operation
                operation = PendingOperation(
                    server_name=server_name,
                    tool_name=tool_name,
                    parameters=parameters,
                    risk_assessment=risk_assessment,
                    security_context=security_context,
                )

                self.pending_operations[operation.request_id] = operation

                # Return approval request
                approval_request = self._create_approval_request(operation)
                # Log response to conversation (approval request)
                storage.add_response(
                    conversation_id=conversation_id,
                    client=self.agent_name,
                    server=server_name,
                    tool=tool_name,
                    result=approval_request,
                    risk_assessment=risk_assessment
                )
                return approval_request

            elif pattern.risk_level == RiskLevel.LOW_RISK:
                # Log and proceed
                logger.info(f"LOW_RISK operation detected: {pattern.name}")
                response = await self._execute_operation(
                    server_name, tool_name, parameters, risk_assessment
                )
                # Log response to conversation
                storage.add_response(
                    conversation_id=conversation_id,
                    client=self.agent_name,
                    server=server_name,
                    tool=tool_name,
                    result=response,
                    risk_assessment=risk_assessment
                )
                return response

        # No dangerous patterns, execute normally
        response = await self._execute_operation(server_name, tool_name, parameters, None)
        # Log response to conversation
        storage.add_response(
            conversation_id=conversation_id,
            client=self.agent_name,
            server=server_name,
            tool=tool_name,
            result=response
        )
        return response

    async def process_approval(
        self,
        request_id: str,
        approved: bool,
        reason: str,
        suggested_alternative: str | None = None,
    ) -> dict[str, Any]:
        """Process an approval decision for a pending operation."""

        # Clean up expired operations
        self._cleanup_expired_operations()

        # Find pending operation
        operation = self.pending_operations.get(request_id)
        if not operation:
            return {
                "status": "error",
                "message": f"No pending operation found for request ID: {request_id}",
            }

        # Remove from pending
        del self.pending_operations[request_id]

        if operation.is_expired:
            return {
                "status": "error",
                "message": "Operation has expired",
                "request_id": request_id,
            }

        if approved:
            # Record the approval - don't execute yet
            logger.info(
                f"Approved operation: {operation.server_name}.{operation.tool_name}"
            )

            # Store approval for when the operation is retried
            operation.approved = True
            operation.approval_reason = reason
            self.approved_operations[request_id] = operation

            return {
                "status": "approved",
                "request_id": request_id,
                "operation": f"{operation.server_name}.{operation.tool_name}",
                "message": "Operation approved. Please retry the original tool call.",
                "risk_level": operation.risk_assessment.get("risk_level"),
            }
        else:
            # Operation denied
            return {
                "status": "denied",
                "request_id": request_id,
                "operation": f"{operation.server_name}.{operation.tool_name}",
                "reason": reason,
                "suggested_alternative": suggested_alternative,
                "risk_assessment": operation.risk_assessment,
            }

    def _create_approval_request(self, operation: PendingOperation) -> dict[str, Any]:
        """Create an approval request response."""
        risk_info = operation.risk_assessment

        # Create detailed message for the user
        lines = [
            "🔒 **SECURITY APPROVAL REQUIRED**",
            "",
            f"**Request ID**: `{operation.request_id}`",
            f"**Server**: {operation.server_name}",
            f"**Tool**: {operation.tool_name}",
            f"**Risk Level**: {risk_info.get('risk_level', 'UNKNOWN')}",
            f"**Risk Category**: {risk_info.get('category', 'Unknown')}",
            "",
            "**Operation Details**:",
            f"- Pattern Matched: {risk_info.get('pattern_name', 'Unknown')}",
            f"- Description: {risk_info.get('description', 'No description')}",
            "",
            "**Parameters**:",
            "```json",
            json.dumps(operation.parameters, indent=2),
            "```",
        ]

        if operation.security_context:
            lines.extend(["", "**Additional Context**:", operation.security_context])

        # Add risk-specific guidance
        risk_level = risk_info.get("risk_level")
        if risk_level == RiskLevel.HIGH_RISK.value:
            lines.extend(
                [
                    "",
                    "⚠️ **HIGH RISK OPERATION**",
                    "This operation could potentially:",
                    "- Damage the system or delete important data",
                    "- Compromise security or expose sensitive information",
                    "- Affect system stability or availability",
                    "",
                    "**Recommendation**: Carefully review before approving",
                ]
            )
        elif risk_level == RiskLevel.REQUIRES_APPROVAL.value:
            lines.extend(
                [
                    "",
                    "⚡ **APPROVAL REQUIRED**",
                    "This operation may be legitimate but requires review:",
                    "- Could modify system state",
                    "- Might have unintended side effects",
                    "- Needs verification of intent",
                    "",
                    "**Recommendation**: Approve if it aligns with your intent",
                ]
            )

        lines.extend(
            [
                "",
                "**TO APPROVE OR DENY**:",
                "",
                f'✅ **APPROVE**: `approve_mcp_operation(request_id="{operation.request_id}", reason="...")`',
                f'❌ **DENY**: `deny_mcp_operation(request_id="{operation.request_id}", reason="...", alternative="...")`',
                "",
                "⏱️ **Expires in**: 5 minutes",
            ]
        )

        return {
            "status": "approval_required",
            "request_id": operation.request_id,
            "message": "\n".join(lines),
            "metadata": {
                "server_name": operation.server_name,
                "tool_name": operation.tool_name,
                "risk_level": risk_level,
                "expires_at": operation.expires_at.isoformat(),
            },
        }

    def _create_risk_assessment(
        self,
        server_name: str,
        tool_name: str,
        pattern: DangerousPattern,
        matched_text: str,
        config: Any,
    ) -> dict[str, Any]:
        """Create a risk assessment dictionary."""
        risk_explanation = config.get_risk_description(pattern.risk_level)

        return {
            "server_name": server_name,
            "tool_name": tool_name,
            "risk_level": pattern.risk_level.value,
            "category": pattern.category,
            "pattern_name": pattern.name,
            "matched_text": matched_text,
            "description": pattern.description,
            "risk_explanation": risk_explanation,
        }

    async def _execute_operation(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        risk_assessment: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Execute the actual MCP operation."""
        if not self.enable_real_connections:
            return {
                "status": "mock",
                "message": "Running in mock mode - no real MCP connections",
                "requested_call": {
                    "server": server_name,
                    "tool": tool_name,
                    "parameters": parameters,
                },
                "risk_assessment": risk_assessment,
            }

        try:
            # Use the base passthrough for actual execution
            if self.base_passthrough:
                logger.debug(f"Base passthrough type: {type(self.base_passthrough)}")
                logger.debug(
                    f"Available methods: {[m for m in dir(self.base_passthrough) if 'execute' in m]}"
                )

                # Verify the method exists
                if not hasattr(self.base_passthrough, "execute_with_security"):
                    raise AttributeError(
                        f"Base passthrough {type(self.base_passthrough)} does not have 'execute_with_security' method. "
                        f"Available methods: {[m for m in dir(self.base_passthrough) if not m.startswith('_')]}"
                    )

                result = await self.base_passthrough.execute_with_security(
                    server_name=server_name,
                    tool_name=tool_name,
                    parameters=parameters,
                    security_context=None,
                )
            else:
                # Mock response for testing
                result = {
                    "status": "mock",
                    "message": "Operation would be executed",
                    "result": {
                        "content": [{"type": "text", "text": "Mock execution result"}]
                    },
                }

            # Add risk assessment to successful result
            if risk_assessment:
                result["risk_assessment"] = risk_assessment

            return result

        except Exception as e:
            import traceback

            logger.error(f"Error executing MCP operation: {e}")
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {
                "status": "error",
                "message": str(e),
                "traceback": traceback.format_exc(),
                "risk_assessment": risk_assessment,
            }

    def _cleanup_expired_operations(self) -> None:
        """Remove expired operations from pending list."""
        expired = [
            request_id
            for request_id, op in self.pending_operations.items()
            if op.is_expired
        ]

        for request_id in expired:
            logger.info(f"Removing expired operation: {request_id}")
            del self.pending_operations[request_id]

    def get_pending_operations(self) -> list[dict[str, Any]]:
        """Get list of pending operations."""
        self._cleanup_expired_operations()

        return [
            {
                "request_id": op.request_id,
                "server_name": op.server_name,
                "tool_name": op.tool_name,
                "risk_level": op.risk_assessment.get("risk_level"),
                "created_at": op.created_at.isoformat(),
                "expires_at": op.expires_at.isoformat(),
            }
            for op in self.pending_operations.values()
        ]

    async def close(self) -> None:
        """Clean up resources."""
        self.pending_operations.clear()
        if self.base_passthrough and hasattr(self.base_passthrough, "close"):
            await self.base_passthrough.close()


# Global instance for interactive passthrough
_interactive_passthrough: MCPPassthroughInteractive | None = None


def get_interactive_passthrough() -> MCPPassthroughInteractive:
    """Get or create the global interactive passthrough instance."""
    global _interactive_passthrough
    if _interactive_passthrough is None:
        logger.info("Creating new interactive passthrough instance")
        _interactive_passthrough = MCPPassthroughInteractive()
    else:
        logger.debug("Returning existing interactive passthrough instance")
    return _interactive_passthrough


async def mcp_passthrough_interactive(
    server_name: str,
    tool_name: str,
    parameters: dict[str, Any] | None = None,
    security_context: str | None = None,
) -> str:
    """
    Execute MCP tool call with interactive approval.

    This function returns immediately with either:
    - The tool result (for safe operations)
    - An approval request (for risky operations)
    - A blocked response (for dangerous operations)
    """
    if parameters is None:
        parameters = {}

    passthrough = get_interactive_passthrough()
    result = await passthrough.execute_with_approval(
        server_name=server_name,
        tool_name=tool_name,
        parameters=parameters,
        security_context=security_context,
    )

    return json.dumps(result, indent=2)
