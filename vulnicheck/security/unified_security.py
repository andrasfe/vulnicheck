"""
Integrated security layer for MCP passthrough operations.

This module combines all security checks (trust store, response sanitizer,
LLM risk assessor, and dangerous commands) into a single, consistent API
for all passthrough variants.

Copyright 2025 VulniCheck Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import json
import logging
from enum import Enum
from typing import Any

from .dangerous_commands_risk_config import (
    RiskLevel as PatternRiskLevel,
)
from .dangerous_commands_risk_config import (
    get_dangerous_commands_risk_config,
)
from .llm_risk_assessor import get_risk_assessor
from .response_sanitizer import get_sanitizer

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Unified risk levels for security assessment."""
    BLOCKED = "BLOCKED"
    HIGH_RISK = "HIGH_RISK"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    LOW_RISK = "LOW_RISK"
    SAFE = "SAFE"


class SecurityAssessment:
    """Container for security assessment results."""

    def __init__(
        self,
        risk_level: RiskLevel,
        is_blocked: bool,
        requires_approval: bool,
        explanation: str,
        specific_risks: list[str] | None = None,
        sanitization_issues: list[str] | None = None,
        matched_patterns: list[tuple[str, str, str]] | None = None,
    ):
        self.risk_level = risk_level
        self.is_blocked = is_blocked
        self.requires_approval = requires_approval
        self.explanation = explanation
        self.specific_risks = specific_risks or []
        self.sanitization_issues = sanitization_issues or []
        self.matched_patterns = matched_patterns or []

    def to_dict(self) -> dict[str, Any]:
        """Convert assessment to dictionary."""
        return {
            "risk_level": self.risk_level.value,
            "is_blocked": self.is_blocked,
            "requires_approval": self.requires_approval,
            "explanation": self.explanation,
            "specific_risks": self.specific_risks,
            "sanitization_issues": self.sanitization_issues,
            "matched_patterns": [
                {"category": cat, "pattern": pat, "match": match}
                for cat, pat, match in self.matched_patterns
            ],
        }


class IntegratedSecurity:
    """
    Integrated security layer combining all security mechanisms.

    This provides a single API for all passthrough variants to use,
    ensuring consistent security enforcement across the codebase.
    """

    def __init__(self, strict_mode: bool = False):
        """
        Initialize unified security.

        Args:
            strict_mode: Enable strict sanitization mode
        """
        self._trust_store: Any = None  # Lazy loaded, typed as Any to avoid circular import
        self.risk_assessor = get_risk_assessor()
        self.sanitizer = get_sanitizer(strict_mode)
        self.dangerous_commands = get_dangerous_commands_risk_config()
        self.strict_mode = strict_mode

        logger.info(
            f"Integrated security initialized (strict_mode={strict_mode}, "
            f"llm_enabled={self.risk_assessor.enabled})"
        )

    @property
    def trust_store(self) -> Any:  # Type is Any to avoid circular import
        """Lazy load trust store to avoid circular imports."""
        if self._trust_store is None:
            from ..mcp.trust_store import get_trust_store
            self._trust_store = get_trust_store()
        return self._trust_store

    async def assess_request(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        server_config: dict[str, Any] | None = None,
        security_context: str | None = None,
    ) -> SecurityAssessment:
        """
        Perform comprehensive security assessment on an MCP request.

        This method:
        1. Checks trust store (blocks untrusted servers)
        2. Sanitizes parameters for dangerous content
        3. Checks dangerous command patterns
        4. Uses LLM risk assessment when available
        5. Returns unified risk assessment

        Args:
            server_name: Target MCP server
            tool_name: Tool to be called
            parameters: Parameters for the tool
            server_config: Server configuration (for trust validation)
            security_context: Additional security context

        Returns:
            SecurityAssessment with comprehensive risk analysis
        """
        specific_risks = []
        sanitization_issues = []
        matched_patterns = []

        # Step 1: Trust store validation (if config provided)
        if server_config is not None and not self.trust_store.is_trusted(server_name, server_config):
            logger.warning(f"Server '{server_name}' is not in trust store or config mismatch")
            return SecurityAssessment(
                risk_level=RiskLevel.BLOCKED,
                is_blocked=True,
                requires_approval=False,
                explanation=f"Server '{server_name}' is not trusted or configuration has been modified",
                specific_risks=["Untrusted server configuration"],
            )

        # Step 2: Pre-execution parameter sanitization
        param_str = json.dumps(parameters)
        sanitized_params, param_issues = self.sanitizer.sanitize(param_str)

        if param_issues:
            sanitization_issues.extend(param_issues)
            # Check if any issues are injection attempts
            injection_detected = any(
                "prompt injection" in issue.lower() for issue in param_issues
            )
            if injection_detected:
                specific_risks.append("Prompt injection attempt in parameters")

        # Step 3: Dangerous command pattern matching with risk levels
        # First check server name alone to catch blocked servers
        server_match = self.dangerous_commands.check_dangerous_pattern(
            server_name, categories=["server"]
        )
        if server_match:
            pattern, matched_text = server_match
            if pattern.risk_level == PatternRiskLevel.BLOCKED:
                # Blocked server names should always block
                return SecurityAssessment(
                    risk_level=RiskLevel.BLOCKED,
                    is_blocked=True,
                    requires_approval=False,
                    explanation=f"Blocked server: {pattern.description}",
                    specific_risks=[f"Server '{server_name}' is not allowed"],
                    sanitization_issues=sanitization_issues,
                    matched_patterns=[(pattern.category, pattern.name, matched_text)],
                )

        # Then check the full context - prioritize BLOCKED patterns
        check_str = f"{server_name} {tool_name} {param_str}"

        # First check for BLOCKED patterns specifically, excluding server category
        # (server patterns were already checked against server name alone)
        non_server_categories = ["filesystem", "path", "privilege", "system", "network",
                                "database", "package", "command", "input"]
        blocked_match = self.dangerous_commands.check_dangerous_pattern(
            check_str, categories=non_server_categories, max_risk_level=PatternRiskLevel.BLOCKED
        )
        if blocked_match:
            pattern, matched_text = blocked_match
            matched_patterns.append((pattern.category, pattern.name, matched_text))
            return SecurityAssessment(
                risk_level=RiskLevel.BLOCKED,
                is_blocked=True,
                requires_approval=False,
                explanation=f"Blocked: {pattern.description}",
                specific_risks=[f"Dangerous pattern: {pattern.description}"],
                sanitization_issues=sanitization_issues,
                matched_patterns=matched_patterns,
            )

        # If not blocked, check for any other dangerous patterns (excluding server category)
        dangerous_match = self.dangerous_commands.check_dangerous_pattern(
            check_str, categories=non_server_categories
        )
        if dangerous_match:
            pattern, matched_text = dangerous_match
            matched_patterns.append((pattern.category, pattern.name, matched_text))
            specific_risks.append(f"Dangerous pattern: {pattern.description}")

            if pattern.risk_level == PatternRiskLevel.HIGH_RISK:
                specific_risks.append("High-risk pattern detected")
            # REQUIRES_APPROVAL will be handled later in final risk determination

        # Step 4: LLM risk assessment (when available)
        if self.risk_assessor.enabled:
            try:
                is_safe, llm_risk_level, llm_explanation = await self.risk_assessor.assess_request(
                    server_name, tool_name, parameters, security_context
                )

                if not is_safe and llm_risk_level:
                    # Map LLM risk levels to our unified levels
                    if llm_risk_level == "BLOCKED":
                        return SecurityAssessment(
                            risk_level=RiskLevel.BLOCKED,
                            is_blocked=True,
                            requires_approval=False,
                            explanation=llm_explanation or "Blocked by AI security assessment",
                            specific_risks=specific_risks,
                            sanitization_issues=sanitization_issues,
                            matched_patterns=matched_patterns,
                        )
                    elif llm_risk_level == "HIGH_RISK":
                        specific_risks.append("High risk identified by AI assessment")
                        return SecurityAssessment(
                            risk_level=RiskLevel.HIGH_RISK,
                            is_blocked=False,
                            requires_approval=True,
                            explanation=llm_explanation or "High risk operation requiring approval",
                            specific_risks=specific_risks,
                            sanitization_issues=sanitization_issues,
                            matched_patterns=matched_patterns,
                        )
                    elif llm_risk_level == "REQUIRES_APPROVAL":
                        return SecurityAssessment(
                            risk_level=RiskLevel.REQUIRES_APPROVAL,
                            is_blocked=False,
                            requires_approval=True,
                            explanation=llm_explanation or "Operation requires approval",
                            specific_risks=specific_risks,
                            sanitization_issues=sanitization_issues,
                            matched_patterns=matched_patterns,
                        )

                # Add LLM insights to risks if any
                if llm_explanation and "risk" in llm_explanation.lower():
                    specific_risks.append(f"AI assessment: {llm_explanation}")

            except Exception as e:
                logger.error(f"LLM risk assessment failed: {e}")
                specific_risks.append("LLM assessment unavailable")

        # Step 5: Determine final risk level
        if matched_patterns or specific_risks:
            # We have some concerns but not blocking
            if len(specific_risks) > 2 or any("high" in risk.lower() for risk in specific_risks):
                return SecurityAssessment(
                    risk_level=RiskLevel.HIGH_RISK,
                    is_blocked=False,
                    requires_approval=True,
                    explanation="Multiple security concerns detected",
                    specific_risks=specific_risks,
                    sanitization_issues=sanitization_issues,
                    matched_patterns=matched_patterns,
                )
            else:
                return SecurityAssessment(
                    risk_level=RiskLevel.REQUIRES_APPROVAL,
                    is_blocked=False,
                    requires_approval=True,
                    explanation="Security concerns detected, approval recommended",
                    specific_risks=specific_risks,
                    sanitization_issues=sanitization_issues,
                    matched_patterns=matched_patterns,
                )

        # No significant risks found
        explanation = "Operation assessed as low risk"
        if sanitization_issues:
            explanation += f" (sanitized {len(sanitization_issues)} issues)"

        return SecurityAssessment(
            risk_level=RiskLevel.LOW_RISK if sanitization_issues else RiskLevel.SAFE,
            is_blocked=False,
            requires_approval=False,
            explanation=explanation,
            specific_risks=specific_risks,
            sanitization_issues=sanitization_issues,
            matched_patterns=matched_patterns,
        )

    async def sanitize_response(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        response_data: Any,
        security_context: str | None = None,
    ) -> tuple[Any, SecurityAssessment]:
        """
        Sanitize and assess an MCP response.

        This method:
        1. Sanitizes response for ANSI/injection patterns
        2. Uses LLM to check for sensitive data exposure
        3. Returns sanitized response and security assessment

        Args:
            server_name: MCP server that provided response
            tool_name: Tool that was called
            parameters: Parameters that were sent
            response_data: The response to sanitize
            security_context: Additional security context

        Returns:
            Tuple of (sanitized_response, SecurityAssessment)
        """
        specific_risks = []

        # Step 1: Response sanitization
        sanitized_response, sanitization_issues = self.sanitizer.sanitize(response_data)

        # Check for injection attempts in response
        has_injection, injection_issues = self.sanitizer.check_for_injection(response_data)
        if has_injection:
            specific_risks.extend(injection_issues)

        # Step 2: LLM response assessment (when available)
        if self.risk_assessor.enabled:
            try:
                is_safe, llm_risk_level, llm_explanation = await self.risk_assessor.assess_response(
                    server_name, tool_name, parameters, response_data, security_context
                )

                if not is_safe and llm_risk_level and llm_risk_level in ["BLOCKED", "HIGH_RISK"]:
                    # Response contains sensitive data
                    specific_risks.append("Sensitive data detected in response")

                    # In strict mode, heavily redact
                    if self.strict_mode:
                        sanitized_response = self._redact_sensitive_response(sanitized_response)

                    return sanitized_response, SecurityAssessment(
                        risk_level=RiskLevel.HIGH_RISK,
                        is_blocked=False,
                        requires_approval=False,
                        explanation=llm_explanation or "Sensitive data detected in response",
                        specific_risks=specific_risks,
                        sanitization_issues=sanitization_issues,
                    )

                # Add LLM insights
                if llm_explanation:
                    specific_risks.append(f"AI assessment: {llm_explanation}")

            except Exception as e:
                logger.error(f"LLM response assessment failed: {e}")

        # Step 3: Final assessment
        if specific_risks or has_injection:
            risk_level = RiskLevel.HIGH_RISK if has_injection else RiskLevel.REQUIRES_APPROVAL
            explanation = "Security issues detected in response"
        elif sanitization_issues:
            risk_level = RiskLevel.LOW_RISK
            explanation = f"Response sanitized ({len(sanitization_issues)} issues)"
        else:
            risk_level = RiskLevel.SAFE
            explanation = "Response assessed as safe"

        return sanitized_response, SecurityAssessment(
            risk_level=risk_level,
            is_blocked=False,
            requires_approval=False,
            explanation=explanation,
            specific_risks=specific_risks,
            sanitization_issues=sanitization_issues,
        )

    def _redact_sensitive_response(self, response: Any) -> Any:
        """Heavily redact sensitive response data in strict mode."""
        if isinstance(response, str):
            # Look for common sensitive patterns
            import re
            patterns = [
                (r'[A-Za-z0-9+/]{20,}={0,2}', '[REDACTED_KEY]'),  # Base64-like
                (r'(?:password|pwd|pass)["\']?\s*[:=]\s*["\']?[^\s"\']+', '[REDACTED_PASSWORD]'),
                (r'(?:api_key|apikey|key)["\']?\s*[:=]\s*["\']?[^\s"\']+', '[REDACTED_API_KEY]'),
                (r'(?:token)["\']?\s*[:=]\s*["\']?[^\s"\']+', '[REDACTED_TOKEN]'),
            ]

            result = response
            for pattern, replacement in patterns:
                result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
            return result

        elif isinstance(response, dict):
            return {k: self._redact_sensitive_response(v) for k, v in response.items()}
        elif isinstance(response, list):
            return [self._redact_sensitive_response(item) for item in response]
        else:
            return response

    def update_trust_store(self, server_name: str, config: dict[str, Any]) -> None:
        """
        Update trust store with server configuration.

        Args:
            server_name: Server name
            config: Server configuration
        """
        self.trust_store.add_trusted_server(
            server_name,
            config,
            description="Added via integrated security layer"
        )
        self.trust_store.verify_and_update(server_name)


# Global instance
_integrated_security: IntegratedSecurity | None = None


def get_integrated_security(strict_mode: bool = False) -> IntegratedSecurity:
    """Get or create the global integrated security instance."""
    global _integrated_security
    if _integrated_security is None or _integrated_security.strict_mode != strict_mode:
        _integrated_security = IntegratedSecurity(strict_mode)
    return _integrated_security
