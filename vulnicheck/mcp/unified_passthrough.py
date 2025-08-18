"""
Unified MCP Passthrough Implementation with Strategy Pattern.

This module consolidates all three MCP passthrough implementations using
modern Python patterns while maintaining 100% backward compatibility.
"""

import asyncio
import json
import logging
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from ..core.agent_detector import detect_agent
from ..core.logging_config import configure_mcp_logging
from ..security import RiskLevel, get_integrated_security
from .conversation_storage import ConversationStorage
from .mcp_client import MCPClient, MCPConnection
from .mcp_config_cache import MCPConfigCache

logger = logging.getLogger(__name__)
interaction_logger = logging.getLogger("vulnicheck.mcp_interactions")


class ApprovalMode(Enum):
    """Defines the approval handling strategy."""
    AUTO = "auto"  # Basic passthrough - auto approve/reject based on risk
    CALLBACK = "callback"  # With approval - uses callback function
    INTERACTIVE = "interactive"  # Interactive - returns pending state


class ApprovalStatus(Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    AUTO_APPROVED = "auto_approved"
    AUTO_BLOCKED = "auto_blocked"


@dataclass
class Operation:
    """Represents an MCP operation with its context."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    server_name: str = ""
    tool_name: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    security_context: str | None = None
    risk_assessment: dict[str, Any] | None = None
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime = field(
        default_factory=lambda: datetime.now() + timedelta(minutes=5)
    )
    status: ApprovalStatus = ApprovalStatus.PENDING
    approval_reason: str | None = None
    conversation_id: str | None = None

    @property
    def is_expired(self) -> bool:
        """Check if this operation has expired."""
        return datetime.now() > self.expires_at


@dataclass
class ApprovalResult:
    """Result of an approval decision."""
    approved: bool
    reason: str
    suggested_alternative: str | None = None
    request_id: str | None = None


@runtime_checkable
class ApprovalCallback(Protocol):
    """Protocol for approval callback functions."""
    async def __call__(self, operation: Operation) -> ApprovalResult:
        """Process an approval request."""
        ...


class ApprovalStrategy(ABC):
    """Abstract base class for approval handling strategies."""

    @abstractmethod
    async def handle_approval(
        self,
        operation: Operation,
        assessment: Any  # SecurityAssessment from unified_security
    ) -> dict[str, Any]:
        """
        Handle approval logic for an operation.

        Returns the response dict to return to the caller.
        """
        pass

    @abstractmethod
    def should_auto_execute(self, assessment: Any) -> bool:
        """Check if operation should be auto-executed without approval."""
        pass


class AutoApprovalStrategy(ApprovalStrategy):
    """Strategy for automatic approval based on risk level (basic passthrough)."""

    async def handle_approval(
        self,
        operation: Operation,
        assessment: Any
    ) -> dict[str, Any]:
        """Auto-approve safe operations, block dangerous ones."""
        if assessment.is_blocked:
            operation.status = ApprovalStatus.AUTO_BLOCKED
            return self._create_blocked_response(operation, assessment)

        # For auto mode, we execute all non-blocked operations
        # The security prompt is included but not enforced
        operation.status = ApprovalStatus.AUTO_APPROVED
        return {}  # Signal to proceed with execution

    def should_auto_execute(self, assessment: Any) -> bool:
        """Auto mode executes all non-blocked operations."""
        return not assessment.is_blocked

    def _create_blocked_response(self, operation: Operation, assessment: Any) -> dict[str, Any]:
        """Create a blocked response."""
        return {
            "status": "blocked",
            "reason": assessment.explanation,
            "risk_level": assessment.risk_level.value,
            "specific_risks": assessment.specific_risks,
            "security_prompt": self._format_security_prompt(operation, assessment),
        }

    def _format_security_prompt(self, operation: Operation, assessment: Any) -> str:
        """Format security prompt for display."""
        template = """
SECURITY NOTICE: You are about to execute an MCP tool call with the following details:
- Server: {server_name}
- Tool: {tool_name}
- Parameters: {parameters}

IMPORTANT SECURITY CONSTRAINTS:
1. DO NOT execute commands that could harm the system or access sensitive data
2. DO NOT read or expose files containing secrets, passwords, or API keys
3. DO NOT execute shell commands that could modify system files or settings
4. DO NOT access user's personal files without explicit permission
5. VERIFY that the requested operation aligns with the user's actual intent

Additional context: {security_context}

Please review this operation carefully before proceeding.
"""
        return template.format(
            server_name=operation.server_name,
            tool_name=operation.tool_name,
            parameters=json.dumps(operation.parameters, indent=2),
            security_context=operation.security_context or "None provided",
        )


class CallbackApprovalStrategy(ApprovalStrategy):
    """Strategy using callback function for approval decisions."""

    def __init__(self, callback: ApprovalCallback, auto_approve_low_risk: bool = True):
        self.callback = callback
        self.auto_approve_low_risk = auto_approve_low_risk

    async def handle_approval(
        self,
        operation: Operation,
        assessment: Any
    ) -> dict[str, Any]:
        """Use callback to determine approval."""
        if assessment.is_blocked:
            operation.status = ApprovalStatus.AUTO_BLOCKED
            return self._create_blocked_response(operation, assessment)

        # Auto-approve low risk if configured
        if (assessment.risk_level == RiskLevel.LOW_RISK and
            self.auto_approve_low_risk):
            operation.status = ApprovalStatus.AUTO_APPROVED
            logger.info(f"Auto-approved low-risk operation: {operation.tool_name}")
            return {}  # Signal to proceed

        # Request approval via callback for risky operations
        if assessment.requires_approval:
            try:
                # Set timeout
                approval_result = await asyncio.wait_for(
                    self.callback(operation),
                    timeout=30.0
                )

                if approval_result.approved:
                    operation.status = ApprovalStatus.APPROVED
                    operation.approval_reason = approval_result.reason
                    return {}  # Signal to proceed
                else:
                    operation.status = ApprovalStatus.DENIED
                    return self._create_denied_response(
                        operation,
                        approval_result.reason,
                        approval_result.suggested_alternative
                    )
            except asyncio.TimeoutError:
                operation.status = ApprovalStatus.TIMEOUT
                return self._create_timeout_response(operation)

        # Safe operations proceed
        return {}

    def should_auto_execute(self, assessment: Any) -> bool:
        """Check if should execute without approval."""
        if assessment.is_blocked:
            return False
        if assessment.risk_level == RiskLevel.SAFE:
            return True
        return assessment.risk_level == RiskLevel.LOW_RISK and self.auto_approve_low_risk

    def _create_blocked_response(self, operation: Operation, assessment: Any) -> dict[str, Any]:
        """Create a blocked response with enhanced formatting."""
        return {
            "status": "blocked",
            "reason": assessment.explanation,
            "risk_assessment": self._build_risk_assessment(operation, assessment),
            "security_prompt": self._format_enhanced_security_prompt(operation, assessment),
        }

    def _create_denied_response(
        self,
        operation: Operation,
        reason: str,
        alternative: str | None
    ) -> dict[str, Any]:
        """Create a denied response."""
        response = {
            "status": "denied",
            "reason": reason,
            "risk_assessment": operation.risk_assessment,
            "security_prompt": self._format_enhanced_security_prompt(operation, None),
        }
        if alternative:
            response["suggested_alternative"] = alternative
        return response

    def _create_timeout_response(self, operation: Operation) -> dict[str, Any]:
        """Create a timeout response."""
        return {
            "status": "timeout",
            "reason": "Approval request timed out",
            "risk_assessment": operation.risk_assessment,
        }

    def _build_risk_assessment(self, operation: Operation, assessment: Any) -> dict[str, Any]:
        """Build risk assessment dict for compatibility."""
        return {
            "risk_level": assessment.risk_level.value,
            "category": "unified_security",
            "pattern_name": "unified_assessment",
            "matched_text": f"{operation.server_name}.{operation.tool_name}",
            "description": assessment.explanation,
            "risk_explanation": assessment.explanation,
            "server_name": operation.server_name,
            "tool_name": operation.tool_name,
            "specific_risks": assessment.specific_risks,
        }

    def _format_enhanced_security_prompt(self, operation: Operation, assessment: Any) -> str:
        """Format enhanced security prompt."""
        template = """
SECURITY NOTICE: MCP operation flagged for review
==================================================
Server: {server_name}
Tool: {tool_name}
Risk Level: {risk_level}
Risk Category: {risk_category}
Assessment Type: {assessment_type}

Operation Details:
{parameters}

Risk Assessment:
- Pattern Matched: {pattern_matched}
- Description: {risk_description}
- Assessment Method: {assessment_method}

{additional_context}

This operation requires approval before proceeding.
"""
        risk_info = operation.risk_assessment or {}
        return template.format(
            server_name=operation.server_name,
            tool_name=operation.tool_name,
            risk_level=risk_info.get("risk_level", "Unknown"),
            risk_category=risk_info.get("category", "Unknown"),
            assessment_type="UNIFIED",
            parameters=json.dumps(operation.parameters, indent=2),
            pattern_matched=risk_info.get("pattern_name", "Unknown"),
            risk_description=risk_info.get("description", "No description"),
            assessment_method="Unified Security Layer",
            additional_context=operation.security_context or "",
        )


class InteractiveApprovalStrategy(ApprovalStrategy):
    """Strategy for interactive approval with pending state."""

    def __init__(self) -> None:
        self.pending_operations: dict[str, Operation] = {}
        self.approved_operations: dict[str, Operation] = {}

    async def handle_approval(
        self,
        operation: Operation,
        assessment: Any
    ) -> dict[str, Any]:
        """Return approval request for risky operations."""
        if assessment.is_blocked:
            operation.status = ApprovalStatus.AUTO_BLOCKED
            return self._create_blocked_response(operation, assessment)

        if assessment.requires_approval:
            # Store as pending and return approval request
            self.pending_operations[operation.request_id] = operation
            return self._create_approval_request(operation, assessment)

        # Safe operations proceed
        return {}

    def should_auto_execute(self, assessment: dict[str, Any]) -> bool:
        """Interactive mode only auto-executes safe operations."""
        return assessment.get("risk_level") == RiskLevel.SAFE

    def check_pre_approved(self, operation: Operation) -> Operation | None:
        """Check if operation was pre-approved."""
        for request_id, approved_op in list(self.approved_operations.items()):
            if (approved_op.server_name == operation.server_name and
                approved_op.tool_name == operation.tool_name and
                approved_op.parameters == operation.parameters):
                del self.approved_operations[request_id]
                return approved_op
        return None

    async def process_approval_decision(
        self,
        request_id: str,
        approved: bool,
        reason: str,
        suggested_alternative: str | None = None
    ) -> dict[str, Any]:
        """Process an approval decision."""
        # Check if operation exists first, before cleanup
        operation = self.pending_operations.get(request_id)
        if not operation:
            return {
                "status": "error",
                "message": f"No pending operation found for request ID: {request_id}",
            }

        # Check expiration before removing
        if operation.is_expired:
            # Remove from pending since it's expired
            del self.pending_operations[request_id]
            return {
                "status": "error",
                "message": "Operation has expired",
                "request_id": request_id,
            }

        # Now safe to remove from pending
        del self.pending_operations[request_id]

        # Clean up other expired operations
        self._cleanup_expired()

        if approved:
            operation.approval_reason = reason
            operation.status = ApprovalStatus.APPROVED
            self.approved_operations[request_id] = operation

            return {
                "status": "approved",
                "request_id": request_id,
                "operation": f"{operation.server_name}.{operation.tool_name}",
                "message": "Operation approved. Please retry the original tool call.",
                "risk_level": operation.risk_assessment.get("risk_level") if operation.risk_assessment else None,
            }
        else:
            operation.status = ApprovalStatus.DENIED
            return {
                "status": "denied",
                "request_id": request_id,
                "operation": f"{operation.server_name}.{operation.tool_name}",
                "reason": reason,
                "suggested_alternative": suggested_alternative,
                "risk_assessment": operation.risk_assessment,
            }

    def _cleanup_expired(self) -> None:
        """Remove expired operations."""

        # Clean pending
        expired_pending = [
            rid for rid, op in self.pending_operations.items()
            if op.is_expired
        ]
        for rid in expired_pending:
            del self.pending_operations[rid]

        # Clean approved
        expired_approved = [
            rid for rid, op in self.approved_operations.items()
            if op.is_expired
        ]
        for rid in expired_approved:
            del self.approved_operations[rid]

    def _create_blocked_response(self, operation: Operation, assessment: Any) -> dict[str, Any]:
        """Create a blocked response."""
        risk_assessment = self._build_risk_assessment(operation, assessment)
        return {
            "status": "blocked",
            "reason": assessment.explanation,
            "risk_assessment": risk_assessment,
        }

    def _create_approval_request(self, operation: Operation, assessment: Any) -> dict[str, Any]:
        """Create an interactive approval request."""
        operation.risk_assessment = self._build_risk_assessment(operation, assessment)
        risk_info = operation.risk_assessment

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
            lines.extend([
                "",
                "⚠️ **HIGH RISK OPERATION**",
                "This operation could potentially:",
                "- Damage the system or delete important data",
                "- Compromise security or expose sensitive information",
                "- Affect system stability or availability",
                "",
                "**Recommendation**: Carefully review before approving",
            ])
        elif risk_level == RiskLevel.REQUIRES_APPROVAL.value:
            lines.extend([
                "",
                "⚡ **APPROVAL REQUIRED**",
                "This operation may be legitimate but requires review:",
                "- Could modify system state",
                "- Might have unintended side effects",
                "- Needs verification of intent",
                "",
                "**Recommendation**: Approve if it aligns with your intent",
            ])

        lines.extend([
            "",
            "**TO APPROVE OR DENY**:",
            "",
            f'✅ **APPROVE**: `approve_mcp_operation(request_id="{operation.request_id}", reason="...")`',
            f'❌ **DENY**: `deny_mcp_operation(request_id="{operation.request_id}", reason="...", alternative="...")`',
            "",
            "⏱️ **Expires in**: 5 minutes",
        ])

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

    def _build_risk_assessment(self, operation: Operation, assessment: Any) -> dict[str, Any]:
        """Build risk assessment dict."""
        return {
            "risk_level": assessment.risk_level.value,
            "category": "unified_security",
            "pattern_name": "unified_assessment",
            "matched_text": f"{operation.server_name}.{operation.tool_name}",
            "description": assessment.explanation,
            "risk_explanation": assessment.explanation,
            "server_name": operation.server_name,
            "tool_name": operation.tool_name,
            "specific_risks": assessment.specific_risks,
        }


class MCPConnectionPool:
    """Manages a pool of MCP server connections."""

    def __init__(self, config_cache: MCPConfigCache, mcp_client: MCPClient):
        self.config_cache = config_cache
        self.mcp_client = mcp_client
        self._connections: dict[tuple[str, str], MCPConnection] = {}
        self._lock = asyncio.Lock()

    async def get_connection(self, agent_name: str, server_name: str) -> MCPConnection:
        """Get or create a connection to an MCP server."""
        key = (agent_name, server_name)

        async with self._lock:
            if key in self._connections:
                return self._connections[key]

            config = await self.config_cache.get_server_config(agent_name, server_name)
            if not config:
                raise ValueError(f"Server '{server_name}' not found in {agent_name} configuration")

            # Get integrated security to handle trust store
            security = get_integrated_security()
            config_dict = config.model_dump(exclude_none=True)
            security.update_trust_store(server_name, config_dict)

            try:
                connection = await self.mcp_client.connect(server_name, config)
                self._connections[key] = connection
                return connection
            except Exception as e:
                logger.error(f"Failed to connect to {server_name}: {e}")
                raise

    async def close_all(self) -> None:
        """Close all connections."""
        async with self._lock:
            for connection in self._connections.values():
                try:
                    await connection.close()
                except Exception as e:
                    logger.error(f"Error closing connection: {e}")
            self._connections.clear()


class UnifiedPassthrough:
    """
    Unified MCP Passthrough implementation using Strategy pattern.

    This class consolidates all three passthrough implementations while
    maintaining complete backward compatibility.
    """

    approval_strategy: ApprovalStrategy

    def __init__(
        self,
        agent_name: str | None = None,
        approval_mode: ApprovalMode = ApprovalMode.AUTO,
        approval_callback: ApprovalCallback | None = None,
        auto_approve_low_risk: bool = True,
        enable_real_connections: bool | None = None,
    ):
        """
        Initialize unified passthrough.

        Args:
            agent_name: Name of the agent (claude, cursor, etc.)
            approval_mode: Strategy for handling approvals
            approval_callback: Callback function for CALLBACK mode
            auto_approve_low_risk: Auto-approve low risk in CALLBACK mode
            enable_real_connections: Enable real MCP connections
        """
        # Core configuration
        self.agent_name = detect_agent(agent_name)
        self.approval_mode = approval_mode

        # Initialize approval strategy
        self._init_approval_strategy(approval_callback, auto_approve_low_risk)

        # Configure logging
        self._configure_logging()

        # Determine connection mode
        if enable_real_connections is None:
            enable_real_connections = (
                os.environ.get("MCP_PASSTHROUGH_ENHANCED", "true").lower() == "true"
            )
        self.enable_real_connections = enable_real_connections

        # Initialize MCP components
        self._init_mcp_components()

        # Initialize security and storage
        self.security = get_integrated_security(strict_mode=False)
        self._conversation_storage: ConversationStorage | None = None
        self._active_conversations: dict[str, str] = {}

        logger.info(
            f"Initialized unified MCP passthrough - agent: {self.agent_name}, "
            f"mode: {self.approval_mode.value}, connections: {self.enable_real_connections}"
        )

    def _init_approval_strategy(
        self,
        callback: ApprovalCallback | None,
        auto_approve_low_risk: bool
    ) -> None:
        """Initialize the appropriate approval strategy."""
        if self.approval_mode == ApprovalMode.AUTO:
            self.approval_strategy = AutoApprovalStrategy()
        elif self.approval_mode == ApprovalMode.CALLBACK:
            if callback is None:
                # Use default callback that denies high-risk
                async def default_callback(operation: Operation) -> ApprovalResult:
                    if operation.risk_assessment and \
                       operation.risk_assessment.get("risk_level") == RiskLevel.HIGH_RISK.value:
                        return ApprovalResult(
                            approved=False,
                            reason="High risk operations require manual review",
                            suggested_alternative="Consider using a safer alternative"
                        )
                    return ApprovalResult(
                        approved=True,
                        reason="Operation approved after risk assessment"
                    )
                callback = default_callback
            self.approval_strategy = CallbackApprovalStrategy(callback, auto_approve_low_risk)
        elif self.approval_mode == ApprovalMode.INTERACTIVE:
            self.approval_strategy = InteractiveApprovalStrategy()
        else:
            raise ValueError(f"Unknown approval mode: {self.approval_mode}")

    def _configure_logging(self) -> None:
        """Configure MCP interaction logging."""
        log_dir = os.path.expanduser("~/.vulnicheck/logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "mcp_interactions.log")

        configure_mcp_logging(
            log_file=log_file,
            log_level=os.environ.get("VULNICHECK_LOG_LEVEL", "INFO"),
            enable_console=os.environ.get("VULNICHECK_LOG_CONSOLE", "false").lower() == "true"
        )

        interaction_logger.info(
            f"MCP passthrough initialized for {self.agent_name}",
            extra={
                "event": "passthrough_init",
                "agent": self.agent_name,
                "mode": self.approval_mode.value,
            }
        )

    def _init_mcp_components(self) -> None:
        """Initialize MCP connection components."""
        self.config_cache: MCPConfigCache | None = None
        self.mcp_client: MCPClient | None = None
        self.connection_pool: MCPConnectionPool | None = None

        if self.enable_real_connections:
            try:
                self.config_cache = MCPConfigCache()
                self.mcp_client = MCPClient()
                self.connection_pool = MCPConnectionPool(
                    self.config_cache, self.mcp_client
                )
                logger.info("Real MCP connections enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize MCP components: {e}")
                logger.warning("Falling back to mock mode")
                self.enable_real_connections = False
                self.config_cache = None
                self.mcp_client = None
                self.connection_pool = None
        else:
            logger.info("Running in mock mode (no real MCP connections)")

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

        conv = storage.get_active_conversation(self.agent_name, server_name)
        if conv:
            self._active_conversations[server_name] = conv.id
            return conv.id

        conv = storage.start_conversation(
            client=self.agent_name,
            server=server_name,
            metadata={"passthrough_mode": self.approval_mode.value}
        )
        self._active_conversations[server_name] = conv.id
        return conv.id

    async def execute_with_security(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        security_context: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute an MCP tool call with unified security and approval handling.

        This is the main entry point that maintains backward compatibility
        with all three original implementations.
        """
        # Create operation
        operation = Operation(
            server_name=server_name,
            tool_name=tool_name,
            parameters=parameters,
            security_context=security_context,
            conversation_id=self._get_or_create_conversation(server_name),
        )

        # Log to conversation storage
        storage = self._get_conversation_storage()
        storage.add_request(
            conversation_id=operation.conversation_id or operation.request_id,
            client=self.agent_name,
            server=server_name,
            tool=tool_name,
            parameters=parameters
        )

        # Check for pre-approved operations (interactive mode)
        if isinstance(self.approval_strategy, InteractiveApprovalStrategy):
            pre_approved = self.approval_strategy.check_pre_approved(operation)
            if pre_approved:
                operation = pre_approved
                logger.info(f"Found pre-approved operation: {operation.request_id}")
                result = await self._execute_operation(operation)
                storage.add_response(
                    conversation_id=operation.conversation_id or operation.request_id,
                    client=self.agent_name,
                    server=server_name,
                    tool=tool_name,
                    result=result,
                    risk_assessment=operation.risk_assessment
                )
                return result

        # Perform security assessment
        server_config = await self._get_server_config(server_name)
        assessment = await self.security.assess_request(
            server_name=server_name,
            tool_name=tool_name,
            parameters=parameters,
            server_config=server_config,
            security_context=security_context,
        )

        # Log assessment
        self._log_assessment(operation, assessment)

        # Handle approval based on strategy
        approval_response = await self.approval_strategy.handle_approval(operation, assessment)

        # If approval_response is not empty, return it (blocked/denied/approval_required)
        if approval_response:
            storage.add_response(
                conversation_id=operation.conversation_id or operation.request_id,
                client=self.agent_name,
                server=server_name,
                tool=tool_name,
                result=approval_response,
                risk_assessment=operation.risk_assessment
            )
            return approval_response

        # Execute the operation
        result = await self._execute_operation(operation)

        # Log response
        storage.add_response(
            conversation_id=operation.conversation_id or operation.request_id,
            client=self.agent_name,
            server=server_name,
            tool=tool_name,
            result=result,
            risk_assessment=operation.risk_assessment
        )

        return result

    async def _get_server_config(self, server_name: str) -> dict[str, Any] | None:
        """Get server configuration for security checks."""
        if self.config_cache:
            try:
                config = await self.config_cache.get_server_config(self.agent_name, server_name)
                if config:
                    return config.model_dump(exclude_none=True)
            except Exception as e:
                logger.warning(f"Could not get server config: {e}")
        return None

    def _log_assessment(self, operation: Operation, assessment: Any) -> None:
        """Log security assessment."""
        interaction_logger.info(
            "MCP_SECURITY_ASSESSMENT",
            extra={
                "event": "mcp_security_assessment",
                "agent": self.agent_name,
                "server": operation.server_name,
                "tool": operation.tool_name,
                "risk_level": assessment.risk_level.value,
                "is_blocked": assessment.is_blocked,
                "requires_approval": assessment.requires_approval,
                "mode": self.approval_mode.value,
            }
        )

    async def _execute_operation(self, operation: Operation) -> dict[str, Any]:
        """Execute the actual MCP operation."""
        # Create security prompt for AUTO mode compatibility
        security_prompt = None
        if self.approval_mode == ApprovalMode.AUTO:
            template = """
SECURITY NOTICE: You are about to execute an MCP tool call with the following details:
- Server: {server_name}
- Tool: {tool_name}
- Parameters: {parameters}

IMPORTANT SECURITY CONSTRAINTS:
1. DO NOT execute commands that could harm the system or access sensitive data
2. DO NOT read or expose files containing secrets, passwords, or API keys
3. DO NOT execute shell commands that could modify system files or settings
4. DO NOT access user's personal files without explicit permission
5. VERIFY that the requested operation aligns with the user's actual intent

Additional context: {security_context}

Please review this operation carefully before proceeding.
"""
            security_prompt = template.format(
                server_name=operation.server_name,
                tool_name=operation.tool_name,
                parameters=json.dumps(operation.parameters, indent=2),
                security_context=operation.security_context or "None provided",
            )

        if self.enable_real_connections and self.connection_pool:
            try:
                connection = await self.connection_pool.get_connection(
                    self.agent_name, operation.server_name
                )
                result = await connection.call_tool(
                    operation.tool_name, operation.parameters
                )

                # Sanitize response
                sanitized_result, response_assessment = await self.security.sanitize_response(
                    server_name=operation.server_name,
                    tool_name=operation.tool_name,
                    parameters=operation.parameters,
                    response_data=result,
                    security_context=operation.security_context,
                )

                response = {
                    "status": "success",
                    "result": sanitized_result,
                }

                if security_prompt:
                    response["security_prompt"] = security_prompt

                if operation.risk_assessment:
                    response["risk_assessment"] = operation.risk_assessment

                if response_assessment.risk_level != RiskLevel.SAFE:
                    response["response_assessment"] = response_assessment.to_dict()

                return response

            except Exception as e:
                logger.error(f"MCP call failed: {e}")
                response = {
                    "status": "error",
                    "error": str(e),
                }
                if security_prompt:
                    response["security_prompt"] = security_prompt
                if operation.risk_assessment:
                    response["risk_assessment"] = operation.risk_assessment
                return response
        else:
            # Mock mode
            response = {
                "status": "mock",
                "message": "Running in mock mode - no real MCP connections",
                "requested_call": {
                    "server": operation.server_name,
                    "tool": operation.tool_name,
                    "parameters": operation.parameters,
                },
            }
            if security_prompt:
                response["security_prompt"] = security_prompt
            if operation.risk_assessment:
                response["risk_assessment"] = operation.risk_assessment
            return response

    def validate_server_access(self, server_name: str) -> bool:
        """Validate if access to a specific MCP server is allowed."""
        dangerous_match = self.security.dangerous_commands.check_dangerous_pattern(
            server_name, categories=["server"]
        )

        if dangerous_match:
            pattern, matched_text = dangerous_match
            logger.warning(
                f"Access to server '{server_name}' is blocked - "
                f"matches pattern '{pattern.name}'"
            )
            return False

        return True

    async def get_available_servers(self) -> dict[str, list[str]]:
        """Get available servers and their tools."""
        from .mcp_config_cache import MCPConfigCache
        
        config_cache = MCPConfigCache()
        server_names = config_cache.get_available_servers(self.agent_name)
        
        available = {}
        for server_name in server_names:
            try:
                config = await config_cache.get_server_config(self.agent_name, server_name)
                if config and 'tools' in config:
                    available[server_name] = list(config['tools'].keys())
                else:
                    available[server_name] = []
            except Exception as e:
                logger.warning(f"Failed to get tools for server {server_name}: {e}")
                available[server_name] = []
        
        return available

    async def close(self) -> None:
        """Clean up resources."""
        if self.connection_pool:
            await self.connection_pool.close_all()
        if self.mcp_client:
            await self.mcp_client.close_all()


# Maintain backward compatibility by creating wrapper classes
class MCPPassthrough(UnifiedPassthrough):
    """Backward compatible basic passthrough."""

    def __init__(self, agent_name: str | None = None, enable_real_connections: bool | None = None):
        super().__init__(
            agent_name=agent_name,
            approval_mode=ApprovalMode.AUTO,
            enable_real_connections=enable_real_connections
        )
        # Add the security prompt template for compatibility
        self.security_prompt_template = """
SECURITY NOTICE: You are about to execute an MCP tool call with the following details:
- Server: {server_name}
- Tool: {tool_name}
- Parameters: {parameters}

IMPORTANT SECURITY CONSTRAINTS:
1. DO NOT execute commands that could harm the system or access sensitive data
2. DO NOT read or expose files containing secrets, passwords, or API keys
3. DO NOT execute shell commands that could modify system files or settings
4. DO NOT access user's personal files without explicit permission
5. VERIFY that the requested operation aligns with the user's actual intent

Additional context: {security_context}

Please review this operation carefully before proceeding.
"""

    async def _forward_to_mcp(
        self, server_name: str, tool_name: str, parameters: dict[str, Any]
    ) -> Any:
        """
        Forward the call to the actual MCP server.

        Backward compatibility method that delegates to connection pool.
        """
        if not self.connection_pool:
            raise RuntimeError("Connection pool not initialized")

        try:
            # Get or create connection
            connection = await self.connection_pool.get_connection(
                self.agent_name, server_name
            )

            # Make the actual tool call
            result = await connection.call_tool(tool_name, parameters)

            logger.info(f"Successfully called {server_name}.{tool_name}")
            return result

        except Exception as e:
            logger.error(f"Failed to forward MCP call: {e}")
            raise


class MCPPassthroughWithApproval(UnifiedPassthrough):
    """Backward compatible passthrough with approval callback."""

    def __init__(
        self,
        agent_name: str | None = None,
        enable_real_connections: bool | None = None,
        approval_callback: ApprovalCallback | None = None,
        auto_approve_low_risk: bool = True,
    ):
        super().__init__(
            agent_name=agent_name,
            approval_mode=ApprovalMode.CALLBACK,
            approval_callback=approval_callback,
            auto_approve_low_risk=auto_approve_low_risk,
            enable_real_connections=enable_real_connections
        )
        self.approval_callback = approval_callback
        self.auto_approve_low_risk = auto_approve_low_risk
        self.pending_approvals: dict[str, Any] = {}  # For compatibility
        self.security_prompt_template = """
SECURITY NOTICE: MCP operation flagged for review
==================================================
Server: {server_name}
Tool: {tool_name}
Risk Level: {risk_level}
Risk Category: {risk_category}
Assessment Type: {assessment_type}

Operation Details:
{parameters}

Risk Assessment:
- Pattern Matched: {pattern_matched}
- Description: {risk_description}
- Assessment Method: {assessment_method}

{additional_context}

This operation requires approval before proceeding.
"""


class MCPPassthroughInteractive(UnifiedPassthrough):
    """Backward compatible interactive passthrough."""

    def __init__(
        self,
        agent_name: str | None = None,
        enable_real_connections: bool = True
    ):
        super().__init__(
            agent_name=agent_name,
            approval_mode=ApprovalMode.INTERACTIVE,
            enable_real_connections=enable_real_connections
        )
        # Expose strategy's operations for compatibility
        strategy = self.approval_strategy
        if isinstance(strategy, InteractiveApprovalStrategy):
            self.pending_operations = strategy.pending_operations
            self.approved_operations = strategy.approved_operations

        # Add base_passthrough for compatibility with tests
        self.base_passthrough = self if enable_real_connections else None

    async def execute_with_approval(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        security_context: str | None = None,
    ) -> dict[str, Any]:
        """Compatibility method for interactive mode."""
        return await self.execute_with_security(
            server_name, tool_name, parameters, security_context
        )

    async def process_approval(
        self,
        request_id: str,
        approved: bool,
        reason: str,
        suggested_alternative: str | None = None,
    ) -> dict[str, Any]:
        """Process an approval decision."""
        strategy = self.approval_strategy
        if isinstance(strategy, InteractiveApprovalStrategy):
            return await strategy.process_approval_decision(
                request_id, approved, reason, suggested_alternative
            )
        raise RuntimeError("Not in interactive mode")

    def _cleanup_expired_operations(self) -> None:
        """Compatibility method."""
        strategy = self.approval_strategy
        if isinstance(strategy, InteractiveApprovalStrategy):
            strategy._cleanup_expired()
