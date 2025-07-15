"""
Safety advisor module for pre-operation risk assessment.

This module provides risk assessment for operations before they are executed,
using LLM-based analysis when available or structured risk assessment framework
as fallback.
"""

import logging
from typing import Any

from .llm_risk_assessor import get_risk_assessor

logger = logging.getLogger(__name__)


class SafetyAdvisor:
    """Provides safety advice for operations before execution."""

    def __init__(self) -> None:
        """Initialize the safety advisor."""
        self.risk_assessor = get_risk_assessor()
        self.has_llm = self.risk_assessor.enabled

    async def assess_operation(
        self,
        operation_type: str,
        operation_details: dict[str, str | list[str] | dict[str, str]],
        context: str | None = None,
    ) -> dict[str, str | list[str] | bool]:
        """
        Assess the safety of an operation before execution.

        Args:
            operation_type: Type of operation (e.g., "file_write", "file_delete", "command_execution")
            operation_details: Details about the operation
            context: Additional context about why this operation is being performed

        Returns:
            Dict containing:
                - assessment: Safety assessment result
                - risks: List of identified risks
                - recommendations: List of recommendations
                - requires_human_approval: Whether human approval is needed
        """
        if self.has_llm:
            return await self._llm_assessment(operation_type, operation_details, context)
        else:
            return self._structured_assessment(operation_type, operation_details, context)

    async def _llm_assessment(
        self,
        operation_type: str,
        operation_details: dict[str, str | list[str] | dict[str, str]],
        context: str | None = None,
    ) -> dict[str, str | list[str] | bool]:
        """Use LLM to assess operation safety."""
        # Format the operation for assessment
        operation_description = self._format_operation(operation_type, operation_details, context)

        try:
            # Use the risk assessor to evaluate the operation as a request
            is_safe, risk_level, explanation = await self.risk_assessor.assess_request(
                "safety_advisor",  # Mock server name
                operation_type,    # Use operation type as tool name
                {
                    "operation_details": operation_details,
                    "context": context,
                    "description": operation_description
                },
                context
            )

            # Parse the LLM response
            if not is_safe or risk_level not in ["SAFE", "LOW_RISK", None]:
                risks = []
                if explanation:
                    # Extract specific risks from explanation if mentioned
                    if "Specific risks:" in explanation:
                        risks_part = explanation.split("Specific risks:")[-1].strip()
                        risks = [r.strip() for r in risks_part.split(",") if r.strip()]
                    else:
                        risks = [explanation]
                else:
                    risks = ["Potential security risk identified"]

                return {
                    "assessment": f"LLM Risk Assessment: {risk_level or 'UNKNOWN'}",
                    "risks": risks,
                    "recommendations": ["Review operation carefully before proceeding"],
                    "requires_human_approval": risk_level in ["HIGH_RISK", "BLOCKED", "REQUIRES_APPROVAL"],
                }
            else:
                return {
                    "assessment": "Operation assessed as safe by LLM",
                    "risks": [],
                    "recommendations": ["Proceed with standard precautions"],
                    "requires_human_approval": False,
                }
        except Exception as e:
            logger.warning(f"LLM assessment failed, falling back to structured assessment: {e}")
            return self._structured_assessment(operation_type, operation_details, context)

    def _structured_assessment(
        self,
        operation_type: str,
        operation_details: dict[str, str | list[str] | dict[str, str]],
        context: str | None = None,
    ) -> dict[str, str | list[str] | bool]:
        """Provide structured risk assessment without LLM."""
        risks: list[str] = []
        recommendations: list[str] = []
        requires_approval = False

        # Risk patterns for different operation types
        risk_patterns: dict[str, dict[str, Any]] = {
            "file_write": {
                "patterns": [
                    (["/.ssh/", "/.gnupg/", "/.aws/"], "Writing to sensitive configuration directory"),
                    (["/etc/", "/sys/", "/proc/"], "Writing to system directory"),
                    ([".env", "config", "credentials", "token", "key"], "Potentially overwriting sensitive files"),
                    (["~", "/home/"], "Writing to user home directory"),
                ],
                "recommendations": [
                    "Verify the file path is correct",
                    "Consider backing up existing files before overwriting",
                    "Ensure sensitive data is properly protected",
                ]
            },
            "file_delete": {
                "patterns": [
                    (["*", "?"], "Using wildcards in deletion"),
                    (["/", "~", "/home/"], "Deleting from root or home directory"),
                    ([".git", ".env", "node_modules"], "Deleting important project files"),
                    (["/.ssh/", "/.gnupg/"], "Deleting security credentials"),
                ],
                "recommendations": [
                    "Double-check the file path before deletion",
                    "Consider moving to trash instead of permanent deletion",
                    "Ensure you have backups of important data",
                ]
            },
            "command_execution": {
                "patterns": [
                    (["sudo", "su", "chmod", "chown"], "Elevated privilege command"),
                    (["rm", "del", "format", "dd"], "Destructive command"),
                    (["|", ";", "&&", "||"], "Command chaining detected"),
                    (["curl", "wget", "git clone"], "Network operation"),
                    (["eval", "exec"], "Dynamic code execution"),
                ],
                "recommendations": [
                    "Review the command carefully before execution",
                    "Consider running in a sandboxed environment first",
                    "Verify the source of any downloaded content",
                ]
            },
            "api_call": {
                "patterns": [
                    (["password", "token", "key", "secret"], "Potential credential exposure"),
                    (["production", "prod", "live"], "Production environment operation"),
                    (["delete", "remove", "destroy"], "Destructive API operation"),
                ],
                "recommendations": [
                    "Ensure credentials are not logged or exposed",
                    "Test on non-production environment first",
                    "Implement proper error handling and rollback",
                ]
            }
        }

        # Get patterns for this operation type
        if operation_type in risk_patterns:
            patterns: list[tuple[list[str], str]] = risk_patterns[operation_type]["patterns"]
            base_recommendations = risk_patterns[operation_type]["recommendations"]

            # Check operation details against patterns
            details_str = str(operation_details).lower()
            for triggers, risk_description in patterns:
                for trigger in triggers:
                    if trigger in details_str:
                        risks.append(risk_description)
                        if any(critical in trigger for critical in ["sudo", "rm", "delete", "format", "production"]):
                            requires_approval = True

            if isinstance(base_recommendations, list):
                recommendations.extend(base_recommendations)
        else:
            # Generic assessment for unknown operation types
            risks.append("Unknown operation type - unable to perform specific risk assessment")
            recommendations.append("Carefully review this operation before proceeding")
            requires_approval = True

        # Add context-based recommendations
        if context:
            recommendations.append(f"Consider the context: {context}")

        # Format the structured response
        if not self.has_llm:
            recommendations.insert(0,
                "You should evaluate based on your risk aversion whether this is a safe thing to do. "
                "As a first step, enumerate the risks involved, then assess each risk. "
                "Finally, if you identify risks, ask the human if they are willing to accept them."
            )

        return {
            "assessment": "Structured risk assessment (no LLM available)" if not self.has_llm else "Structured risk assessment",
            "risks": risks if risks else ["No specific risks identified"],
            "recommendations": recommendations,
            "requires_human_approval": requires_approval or len(risks) > 0,
        }

    def _format_operation(
        self,
        operation_type: str,
        operation_details: dict[str, str | list[str] | dict[str, str]],
        context: str | None = None,
    ) -> str:
        """Format operation details for display."""
        parts = []
        for key, value in operation_details.items():
            if isinstance(value, list):
                parts.append(f"{key}: {', '.join(str(v) for v in value)}")
            elif isinstance(value, dict):
                parts.append(f"{key}: {value}")
            else:
                parts.append(f"{key}: {value}")
        return "; ".join(parts)


async def assess_operation_safety(
    operation_type: str,
    operation_details: dict[str, str | list[str] | dict[str, str]],
    context: str | None = None,
) -> dict[str, str | list[str] | bool]:
    """
    Assess the safety of an operation.

    This is the main entry point for the safety advisor tool.
    """
    advisor = SafetyAdvisor()
    return await advisor.assess_operation(operation_type, operation_details, context)
