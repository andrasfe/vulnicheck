"""
Enhanced MCP Passthrough with interactive approval mechanism.

This module provides a passthrough mechanism that intercepts MCP server calls,
performs risk assessment, and can request approval for risky operations.
"""

import asyncio
import json
import logging
import os
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .agent_detector import detect_agent
from .conversation_storage import ConversationStorage
from .dangerous_commands_risk_config import (
    RiskLevel,
    get_dangerous_commands_risk_config,
)
from .llm_risk_assessor import get_risk_assessor
from .mcp_client import MCPClient
from .mcp_config_cache import MCPConfigCache

logger = logging.getLogger(__name__)

# Create a separate logger for MCP interactions
interaction_logger = logging.getLogger("vulnicheck.mcp_interactions")


class ApprovalStatus(Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"


class ApprovalRequest(BaseModel):
    """Model for an approval request."""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    server_name: str
    tool_name: str
    parameters: dict[str, Any]
    risk_assessment: dict[str, Any]
    security_context: str | None = None
    timeout_seconds: int = 30
    status: ApprovalStatus = ApprovalStatus.PENDING
    response_reason: str | None = None


class ApprovalResponse(BaseModel):
    """Model for an approval response."""

    request_id: str
    approved: bool
    reason: str
    suggested_alternative: str | None = None


# Type alias for approval callback
ApprovalCallback = Callable[[ApprovalRequest], Awaitable[ApprovalResponse]]


class MCPPassthroughWithApproval:
    """
    Enhanced passthrough handler with risk assessment and approval mechanism.
    """

    def __init__(
        self,
        agent_name: str | None = None,
        enable_real_connections: bool | None = None,
        approval_callback: ApprovalCallback | None = None,
        auto_approve_low_risk: bool = True,
    ):
        """
        Initialize the enhanced passthrough handler.

        Args:
            agent_name: Name of the agent (claude, cursor, etc.)
            enable_real_connections: Whether to enable real MCP connections
            approval_callback: Async function to call for approval requests
            auto_approve_low_risk: Whether to auto-approve LOW_RISK operations
        """
        # Detect agent using shared detector
        self.agent_name = detect_agent(agent_name)
        logger.info(
            f"Initialized MCP passthrough with approval for agent: {self.agent_name}"
        )

        # Determine if we should enable real connections
        if enable_real_connections is None:
            enable_real_connections = (
                os.environ.get("MCP_PASSTHROUGH_ENHANCED", "true").lower() == "true"
            )

        self.enable_real_connections = enable_real_connections
        self.approval_callback = approval_callback
        self.auto_approve_low_risk = auto_approve_low_risk

        # Conversation storage will be initialized on first use
        self._conversation_storage: ConversationStorage | None = None
        self._active_conversations: dict[str, str] = {}  # server -> conversation_id

        # Track pending approvals
        self.pending_approvals: dict[str, ApprovalRequest] = {}

        # Initialize MCP components if real connections are enabled
        self.config_cache: MCPConfigCache | None = None
        self.mcp_client: MCPClient | None = None
        self.connection_pool = None

        if self.enable_real_connections:
            try:
                from .mcp_passthrough import MCPConnectionPool

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
            metadata={"passthrough_mode": "with_approval"}
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
        Execute an MCP tool call with enhanced security checks and approval flow.
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

        # Log the incoming request with risk assessment
        interaction_logger.info(
            "MCP_REQUEST_WITH_APPROVAL",
            extra={
                "event": "mcp_request",
                "agent": self.agent_name,
                "server": server_name,
                "tool": tool_name,
                "parameters": parameters,
                "security_context": security_context,
                "has_real_connections": self.enable_real_connections,
                "approval_enabled": True,
                "auto_approve_low_risk": self.auto_approve_low_risk,
            }
        )

        # Initialize risk assessment to None
        risk_assessment = None

        # First, check with LLM risk assessor if available
        risk_assessor = get_risk_assessor()
        llm_assessment_successful = False

        if risk_assessor.enabled:
            try:
                is_safe, llm_risk_level, llm_explanation = await risk_assessor.assess_request(
                    server_name, tool_name, parameters, security_context
                )
                llm_assessment_successful = True

                # Log LLM assessment performed
                interaction_logger.info(
                    "MCP_LLM_ASSESSMENT",
                    extra={
                        "event": "mcp_llm_assessment",
                        "agent": self.agent_name,
                        "server": server_name,
                        "tool": tool_name,
                        "assessment_type": "ai",
                        "assessment_method": "llm_request_analysis",
                        "is_safe": is_safe,
                        "llm_risk_level": llm_risk_level,
                        "has_explanation": bool(llm_explanation),
                    }
                )

                # Handle LLM assessment results
                if not is_safe:
                    # LLM identified a risk
                    # Handle based on LLM risk level
                    if llm_risk_level == "BLOCKED":
                        # Create risk assessment for blocked operation
                        blocked_risk_assessment = {
                            "risk_level": llm_risk_level,
                            "category": "llm_security",
                            "pattern_name": "llm_assessment",
                            "matched_text": f"{server_name}.{tool_name}",
                            "description": llm_explanation or "LLM identified security risk",
                            "risk_explanation": "AI-powered security assessment detected risk",
                            "server_name": server_name,
                            "tool_name": tool_name,
                            "assessment_type": "ai",
                            "assessment_method": "llm_risk_assessor",
                        }

                        interaction_logger.warning(
                            "MCP_SECURITY_BLOCKED",
                            extra={
                                "event": "mcp_security_decision",
                                "decision": "blocked",
                                "agent": self.agent_name,
                                "server": server_name,
                                "tool": tool_name,
                                "risk_level": llm_risk_level,
                                "reason": f"LLM assessment: {llm_explanation}",
                                "assessment_type": "ai",
                                "assessment_method": "llm_risk_assessor",
                            }
                        )
                        response = self._create_blocked_response(
                            blocked_risk_assessment, f"LLM security assessment blocked operation: {llm_explanation}"
                        )
                        # Log response to conversation
                        storage.add_response(
                            conversation_id=conversation_id,
                            client=self.agent_name,
                            server=server_name,
                            tool=tool_name,
                            result=response,
                            risk_assessment=blocked_risk_assessment
                        )
                        return response

                    # For non-BLOCKED risks from LLM, continue with approval flow
                    # This handles HIGH_RISK, REQUIRES_APPROVAL, etc.
                    interaction_logger.info(
                        "MCP_RISK_ASSESSMENT",
                        extra={
                            "event": "mcp_risk_assessment",
                            "agent": self.agent_name,
                            "server": server_name,
                            "tool": tool_name,
                            "risk_level": llm_risk_level,
                            "assessment_type": "ai",
                            "assessment_method": "llm_risk_assessor",
                        }
                    )
                    # Skip pattern matching - go directly to approval flow
                    # which is handled after the pattern matching section

                    # Important: Set risk_assessment here so we skip pattern matching
                    # and go directly to the approval flow at the end
                    risk_assessment = {
                        "risk_level": llm_risk_level,
                        "category": "llm_security",
                        "pattern_name": "llm_assessment",
                        "matched_text": f"{server_name}.{tool_name}",
                        "description": llm_explanation or "LLM identified security risk",
                        "risk_explanation": "AI-powered security assessment detected risk",
                        "server_name": server_name,
                        "tool_name": tool_name,
                        "assessment_type": "ai",
                        "assessment_method": "llm_risk_assessor",
                    }

                elif is_safe:
                    # LLM says it's safe - allow without pattern checking
                    interaction_logger.info(
                        "MCP_SECURITY_ALLOWED",
                        extra={
                            "event": "mcp_security_decision",
                            "agent": self.agent_name,
                            "server": server_name,
                            "tool": tool_name,
                            "risk_level": "SAFE",
                            "decision": "allowed",
                            "assessment_type": "ai",
                            "assessment_method": "llm_risk_assessor",
                        }
                    )
                    # Execute the operation
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

            except Exception as e:
                # LLM assessment failed - log and fall back to pattern matching
                interaction_logger.warning(
                    "MCP_LLM_ASSESSMENT_FAILED",
                    extra={
                        "event": "mcp_llm_assessment_error",
                        "agent": self.agent_name,
                        "server": server_name,
                        "tool": tool_name,
                        "error": str(e),
                        "fallback": "pattern_matching",
                    }
                )
                llm_assessment_successful = False

        # Only use pattern matching if LLM is not available or failed
        if not llm_assessment_successful:
            # Get the dangerous commands configuration
            config = get_dangerous_commands_risk_config()

            # Check for dangerous patterns
            check_str = f"{server_name} {tool_name} {json.dumps(parameters)}"
            match_result = config.check_dangerous_pattern(check_str)

            if match_result:
                pattern, matched_text = match_result

                # Build risk assessment
                risk_assessment = {
                    "risk_level": pattern.risk_level.value,
                    "category": pattern.category,
                    "pattern_name": pattern.name,
                    "matched_text": matched_text,
                    "description": pattern.description,
                    "risk_explanation": config.get_risk_description(pattern.risk_level),
                    "server_name": server_name,
                    "tool_name": tool_name,
                    "assessment_type": "pattern",
                    "assessment_method": "regex_pattern_matching",
                }

                # Log risk assessment
                interaction_logger.info(
                    "MCP_RISK_ASSESSMENT",
                    extra={
                        "event": "mcp_risk_assessment",
                        "agent": self.agent_name,
                        "server": server_name,
                        "tool": tool_name,
                        "risk_level": pattern.risk_level.value,
                        "category": pattern.category,
                        "pattern": pattern.name,
                        "matched_text": matched_text,
                        "description": pattern.description,
                        "assessment_type": "pattern",
                        "assessment_method": "regex_pattern_matching",
                    }
                )

                # Handle based on risk level
                if pattern.risk_level == RiskLevel.BLOCKED:
                    # Always block these
                    interaction_logger.warning(
                        "MCP_SECURITY_BLOCKED",
                        extra={
                        "event": "mcp_security_decision",
                        "decision": "blocked",
                        "agent": self.agent_name,
                        "server": server_name,
                        "tool": tool_name,
                        "risk_level": pattern.risk_level.value,
                        "reason": f"Operation blocked: {pattern.description}",
                        "assessment_type": "pattern",
                        "assessment_method": "regex_pattern_matching",
                    }
                )
                    response = self._create_blocked_response(
                        risk_assessment, f"Operation blocked: {pattern.description}"
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

                elif (
                    pattern.risk_level == RiskLevel.LOW_RISK and self.auto_approve_low_risk
                ):
                    # Auto-approve low risk operations
                    interaction_logger.info(
                        "MCP_SECURITY_AUTO_APPROVED",
                        extra={
                            "event": "mcp_security_decision",
                            "decision": "auto_approved",
                            "agent": self.agent_name,
                            "server": server_name,
                            "tool": tool_name,
                            "risk_level": pattern.risk_level.value,
                            "reason": "Low risk operation auto-approved",
                            "assessment_type": "pattern",
                            "assessment_method": "regex_pattern_matching",
                        }
                    )
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

                elif pattern.risk_level in [
                    RiskLevel.HIGH_RISK,
                    RiskLevel.REQUIRES_APPROVAL,
                ]:
                    # Request approval
                    if self.approval_callback:
                        interaction_logger.info(
                            "MCP_APPROVAL_REQUESTED",
                            extra={
                                "event": "mcp_approval_request",
                                "agent": self.agent_name,
                                "server": server_name,
                                "tool": tool_name,
                                "risk_level": pattern.risk_level.value,
                                "category": pattern.category,
                            }
                        )

                        approval_response = await self._request_approval(
                            server_name,
                            tool_name,
                            parameters,
                            risk_assessment,
                            security_context,
                        )

                        if approval_response.approved:
                            interaction_logger.info(
                                "MCP_SECURITY_APPROVED",
                                extra={
                                    "event": "mcp_security_decision",
                                    "decision": "approved",
                                    "agent": self.agent_name,
                                    "server": server_name,
                                    "tool": tool_name,
                                    "risk_level": pattern.risk_level.value,
                                    "reason": approval_response.reason,
                                    "request_id": approval_response.request_id,
                                }
                            )
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
                        else:
                            interaction_logger.warning(
                                "MCP_SECURITY_DENIED",
                                extra={
                                    "event": "mcp_security_decision",
                                    "decision": "denied",
                                    "agent": self.agent_name,
                                    "server": server_name,
                                    "tool": tool_name,
                                    "risk_level": pattern.risk_level.value,
                                    "reason": approval_response.reason,
                                    "request_id": approval_response.request_id,
                                    "alternative": approval_response.suggested_alternative,
                                }
                            )
                            response = self._create_denied_response(
                                risk_assessment,
                                approval_response.reason,
                                approval_response.suggested_alternative,
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
                    else:
                        # No approval callback, must block
                        interaction_logger.warning(
                            "MCP_SECURITY_BLOCKED",
                            extra={
                                "event": "mcp_security_decision",
                                "decision": "blocked",
                                "agent": self.agent_name,
                                "server": server_name,
                                "tool": tool_name,
                                "risk_level": pattern.risk_level.value,
                                "reason": "Operation requires approval but no approval mechanism configured",
                            }
                        )
                        response = self._create_blocked_response(
                            risk_assessment,
                            "Operation requires approval but no approval mechanism configured",
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

        # Handle approval flow if we have a risk assessment (from either LLM or pattern)
        if risk_assessment:
            risk_level_str = risk_assessment["risk_level"]

            # Auto-approve low risk
            if risk_level_str == "LOW_RISK" and self.auto_approve_low_risk:
                interaction_logger.info(
                    "MCP_SECURITY_AUTO_APPROVED",
                    extra={
                        "event": "mcp_security_decision",
                        "decision": "auto_approved",
                        "agent": self.agent_name,
                        "server": server_name,
                        "tool": tool_name,
                        "risk_level": risk_level_str,
                        "reason": "Low risk operation auto-approved",
                        "assessment_type": risk_assessment.get("assessment_type", "unknown"),
                        "assessment_method": risk_assessment.get("assessment_method", "unknown"),
                    }
                )
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

            # Request approval for HIGH_RISK or REQUIRES_APPROVAL
            elif risk_level_str in ["HIGH_RISK", "REQUIRES_APPROVAL"]:
                if self.approval_callback:
                    interaction_logger.info(
                        "MCP_APPROVAL_REQUESTED",
                        extra={
                            "event": "mcp_approval_request",
                            "agent": self.agent_name,
                            "server": server_name,
                            "tool": tool_name,
                            "risk_level": risk_level_str,
                            "assessment_type": risk_assessment.get("assessment_type", "unknown"),
                        }
                    )

                    approval_response = await self._request_approval(
                        server_name,
                        tool_name,
                        parameters,
                        risk_assessment,
                        security_context,
                    )

                    if approval_response.approved:
                        interaction_logger.info(
                            "MCP_SECURITY_APPROVED",
                            extra={
                                "event": "mcp_security_decision",
                                "decision": "approved",
                                "agent": self.agent_name,
                                "server": server_name,
                                "tool": tool_name,
                                "risk_level": risk_level_str,
                                "reason": approval_response.reason,
                                "request_id": approval_response.request_id,
                                "assessment_type": risk_assessment.get("assessment_type", "unknown"),
                                "assessment_method": risk_assessment.get("assessment_method", "unknown"),
                            }
                        )
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
                    else:
                        interaction_logger.warning(
                            "MCP_SECURITY_DENIED",
                            extra={
                                "event": "mcp_security_decision",
                                "decision": "denied",
                                "agent": self.agent_name,
                                "server": server_name,
                                "tool": tool_name,
                                "risk_level": risk_level_str,
                                "reason": approval_response.reason,
                                "request_id": approval_response.request_id,
                                "alternative": approval_response.suggested_alternative,
                                "assessment_type": risk_assessment.get("assessment_type", "unknown"),
                                "assessment_method": risk_assessment.get("assessment_method", "unknown"),
                            }
                        )
                        response = self._create_denied_response(
                            risk_assessment,
                            approval_response.reason,
                            approval_response.suggested_alternative,
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
                else:
                    # No approval callback, must block
                    interaction_logger.warning(
                        "MCP_SECURITY_BLOCKED",
                        extra={
                            "event": "mcp_security_decision",
                            "decision": "blocked",
                            "agent": self.agent_name,
                            "server": server_name,
                            "tool": tool_name,
                            "risk_level": risk_level_str,
                            "reason": "Operation requires approval but no approval mechanism configured",
                            "assessment_type": risk_assessment.get("assessment_type", "unknown"),
                            "assessment_method": risk_assessment.get("assessment_method", "unknown"),
                        }
                    )
                    response = self._create_blocked_response(
                        risk_assessment,
                        "Operation requires approval but no approval mechanism configured",
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

        # No risk assessment at all - allow (no dangerous patterns or LLM found it safe)
        interaction_logger.info(
            "MCP_SECURITY_ALLOWED",
            extra={
                "event": "mcp_security_decision",
                "decision": "allowed",
                "agent": self.agent_name,
                "server": server_name,
                "tool": tool_name,
                "risk_level": "SAFE",
                "reason": "No dangerous patterns detected",
                "assessment_type": "pattern",
                "assessment_method": "no_match",
            }
        )
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

    async def _request_approval(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        risk_assessment: dict[str, Any],
        security_context: str | None,
    ) -> ApprovalResponse:
        """Request approval for a risky operation."""

        # Create approval request
        request = ApprovalRequest(
            server_name=server_name,
            tool_name=tool_name,
            parameters=parameters,
            risk_assessment=risk_assessment,
            security_context=security_context,
        )

        # Store pending request
        self.pending_approvals[request.request_id] = request

        try:
            # Set timeout
            timeout_task = asyncio.create_task(
                self._approval_timeout(request.request_id, request.timeout_seconds)
            )

            # Request approval
            if self.approval_callback is not None:
                # Create a coroutine from the awaitable
                callback = self.approval_callback  # capture non-None value
                async def _call_approval() -> ApprovalResponse:
                    return await callback(request)

                approval_task: asyncio.Task[ApprovalResponse] = asyncio.create_task(
                    _call_approval()
                )
            else:
                # This shouldn't happen because we check above, but satisfy mypy
                raise RuntimeError("Approval callback is None")

            # Wait for either approval or timeout
            done, pending = await asyncio.wait(
                [approval_task, timeout_task], return_when=asyncio.FIRST_COMPLETED
            )

            # Cancel the other task
            for task in pending:
                task.cancel()

            # Get result
            if approval_task in done:
                response = await approval_task
                request.status = (
                    ApprovalStatus.APPROVED
                    if response.approved
                    else ApprovalStatus.DENIED
                )
                request.response_reason = response.reason
                return response
            else:
                # Timeout
                request.status = ApprovalStatus.TIMEOUT
                timeout_response = ApprovalResponse(
                    request_id=request.request_id,
                    approved=False,
                    reason="Approval request timed out",
                )
                return timeout_response

        finally:
            # Clean up
            if request.request_id in self.pending_approvals:
                del self.pending_approvals[request.request_id]

    async def _approval_timeout(self, request_id: str, timeout_seconds: int) -> None:
        """Handle approval timeout."""
        await asyncio.sleep(timeout_seconds)
        if request_id in self.pending_approvals:
            self.pending_approvals[request_id].status = ApprovalStatus.TIMEOUT

    async def _execute_operation(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        risk_assessment: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Execute the actual operation."""

        if self.enable_real_connections and self.connection_pool:
            try:
                # Get or create connection
                connection = await self.connection_pool.get_connection(
                    self.agent_name, server_name
                )

                # Make the actual tool call
                result = await connection.call_tool(tool_name, parameters)

                # Check response with LLM risk assessor if available
                risk_assessor = get_risk_assessor()
                if risk_assessor.enabled:
                    is_safe, llm_risk_level, llm_explanation = await risk_assessor.assess_response(
                        server_name, tool_name, parameters, result, None
                    )

                    # Log LLM response assessment performed
                    interaction_logger.info(
                        "MCP_LLM_RESPONSE_ASSESSMENT",
                        extra={
                            "event": "mcp_llm_response_assessment",
                            "agent": self.agent_name,
                            "server": server_name,
                            "tool": tool_name,
                            "assessment_type": "ai",
                            "assessment_method": "llm_response_analysis",
                            "is_safe": is_safe,
                            "llm_risk_level": llm_risk_level,
                            "has_explanation": bool(llm_explanation),
                        }
                    )

                    if not is_safe and llm_risk_level in ["HIGH_RISK", "REQUIRES_APPROVAL"]:
                        # Response contains security risks - need approval to proceed
                        interaction_logger.warning(
                            "MCP_LLM_RESPONSE_RISK",
                            extra={
                                "event": "mcp_response_risk",
                                "agent": self.agent_name,
                                "server": server_name,
                                "tool": tool_name,
                                "risk_level": llm_risk_level,
                                "reason": f"LLM assessment: {llm_explanation}",
                                "assessment_type": "ai",
                                "assessment_method": "llm_response_analysis",
                            }
                        )

                        # Create enhanced risk assessment
                        enhanced_risk_assessment = risk_assessment or {}
                        enhanced_risk_assessment.update({
                            "response_risk_level": llm_risk_level,
                            "response_risk_explanation": llm_explanation,
                            "sensitive_content_detected": True,
                        })

                        # If we have an approval callback, request approval for risky response
                        if self.approval_callback and llm_risk_level in ["HIGH_RISK", "REQUIRES_APPROVAL"]:
                            approval_response = await self._request_approval(
                                server_name,
                                tool_name,
                                parameters,
                                enhanced_risk_assessment,
                                f"Response contains sensitive content: {llm_explanation}",
                            )

                            if not approval_response.approved:
                                interaction_logger.warning(
                                    "MCP_LLM_RESPONSE_DENIED",
                                    extra={
                                        "event": "mcp_security_decision",
                                        "decision": "response_denied",
                                        "agent": self.agent_name,
                                        "server": server_name,
                                        "tool": tool_name,
                                        "risk_level": llm_risk_level,
                                        "reason": approval_response.reason,
                                    }
                                )
                                return self._create_denied_response(
                                    enhanced_risk_assessment,
                                    f"Response denied due to security risks: {approval_response.reason}",
                                    approval_response.suggested_alternative,
                                )

                response = {
                    "status": "success",
                    "result": result,
                    "risk_assessment": risk_assessment,
                }

                # Log successful response
                interaction_logger.info(
                    "MCP_RESPONSE",
                    extra={
                        "event": "mcp_response",
                        "agent": self.agent_name,
                        "server": server_name,
                        "tool": tool_name,
                        "status": "success",
                        "has_result": result is not None,
                        "risk_level": risk_assessment.get("risk_level") if risk_assessment else "SAFE",
                    }
                )

                return response

            except Exception as e:
                logger.error(f"MCP call failed: {e}")

                response = {
                    "status": "error",
                    "error": str(e),
                    "risk_assessment": risk_assessment,
                }

                # Log error response
                interaction_logger.error(
                    "MCP_RESPONSE_ERROR",
                    extra={
                        "event": "mcp_response",
                        "agent": self.agent_name,
                        "server": server_name,
                        "tool": tool_name,
                        "status": "error",
                        "error": str(e),
                        "risk_level": risk_assessment.get("risk_level") if risk_assessment else "SAFE",
                    }
                )

                return response
        else:
            # Mock mode
            response = {
                "status": "mock",
                "message": "Running in mock mode - no real MCP connections",
                "requested_call": {
                    "server": server_name,
                    "tool": tool_name,
                    "parameters": parameters,
                },
                "risk_assessment": risk_assessment,
            }

            # Log mock response
            interaction_logger.info(
                "MCP_RESPONSE",
                extra={
                    "event": "mcp_response",
                    "agent": self.agent_name,
                    "server": server_name,
                    "tool": tool_name,
                    "status": "mock",
                    "risk_level": risk_assessment.get("risk_level") if risk_assessment else "SAFE",
                }
            )

            return response

    def _create_blocked_response(
        self, risk_assessment: dict[str, Any], reason: str
    ) -> dict[str, Any]:
        """Create a blocked response."""
        response = {
            "status": "blocked",
            "reason": reason,
            "risk_assessment": risk_assessment,
            "security_prompt": self._format_security_prompt(risk_assessment),
        }

        # Log blocked response
        interaction_logger.info(
            "MCP_RESPONSE",
            extra={
                "event": "mcp_response",
                "agent": self.agent_name,
                "server": risk_assessment.get("server_name", "Unknown"),
                "tool": risk_assessment.get("tool_name", "Unknown"),
                "status": "blocked",
                "risk_level": risk_assessment.get("risk_level", "BLOCKED"),
                "reason": reason,
            }
        )

        return response

    def _create_denied_response(
        self,
        risk_assessment: dict[str, Any],
        reason: str,
        suggested_alternative: str | None,
    ) -> dict[str, Any]:
        """Create a denied response."""
        response = {
            "status": "denied",
            "reason": reason,
            "risk_assessment": risk_assessment,
            "security_prompt": self._format_security_prompt(risk_assessment),
        }

        if suggested_alternative:
            response["suggested_alternative"] = suggested_alternative

        # Log denied response
        interaction_logger.info(
            "MCP_RESPONSE",
            extra={
                "event": "mcp_response",
                "agent": self.agent_name,
                "server": risk_assessment.get("server_name", "Unknown"),
                "tool": risk_assessment.get("tool_name", "Unknown"),
                "status": "denied",
                "risk_level": risk_assessment.get("risk_level", "Unknown"),
                "reason": reason,
                "alternative": suggested_alternative,
            }
        )

        return response

    def _format_security_prompt(self, risk_assessment: dict[str, Any]) -> str:
        """Format a security prompt for display."""
        return self.security_prompt_template.format(
            server_name=risk_assessment.get("server_name", "Unknown"),
            tool_name=risk_assessment.get("tool_name", "Unknown"),
            risk_level=risk_assessment.get("risk_level", "Unknown"),
            risk_category=risk_assessment.get("category", "Unknown"),
            assessment_type=risk_assessment.get("assessment_type", "Unknown").upper(),
            parameters="<parameters hidden for security>",
            pattern_matched=risk_assessment.get("pattern_name", "Unknown"),
            risk_description=risk_assessment.get("description", "No description"),
            assessment_method=risk_assessment.get("assessment_method", "Unknown"),
            additional_context=risk_assessment.get("risk_explanation", ""),
        )

    async def close(self) -> None:
        """Clean up resources."""
        if self.connection_pool:
            await self.connection_pool.close_all()
        if self.mcp_client:
            await self.mcp_client.close_all()


# Default approval callback - will be replaced by real implementation
async def default_approval_callback(request: ApprovalRequest) -> ApprovalResponse:
    """Default approval callback that denies high-risk operations."""
    if request.risk_assessment.get("risk_level") == RiskLevel.HIGH_RISK.value:
        return ApprovalResponse(
            request_id=request.request_id,
            approved=False,
            reason="High risk operations require manual review",
            suggested_alternative="Consider using a safer alternative",
        )
    return ApprovalResponse(
        request_id=request.request_id,
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
    # Uses the generic MCP approval callback by default
    passthrough = MCPPassthroughWithApproval(
        agent_name=agent_name, approval_callback=mcp_approval_callback
    )

    # Execute with enhanced security
    result = await passthrough.execute_with_security(
        server_name=server_name,
        tool_name=tool_name,
        parameters=parameters,
        security_context=security_context,
    )

    return json.dumps(result, indent=2)
