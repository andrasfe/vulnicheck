"""
LLM-based risk assessment for MCP passthrough operations.

This module provides AI-powered security assessment of MCP requests and responses,
adding an intelligent layer of protection against malicious operations.
"""

import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class LLMRiskAssessor:
    """Assesses security risks in MCP operations using LLM analysis."""

    def __init__(self) -> None:
        """Initialize the LLM risk assessor."""
        self.api_key = os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        self.api_type = "openai" if os.getenv("OPENAI_API_KEY") else "anthropic"
        self.enabled = bool(self.api_key)

        if self.enabled:
            logger.info(f"LLM risk assessor enabled using {self.api_type} API")
        else:
            logger.info("LLM risk assessor disabled - no API key found")

    async def assess_request(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        security_context: str | None = None,
    ) -> tuple[bool, str | None, str | None]:
        """
        Assess if an MCP request poses security risks before execution.

        Args:
            server_name: Target MCP server
            tool_name: Tool to be called
            parameters: Parameters for the tool
            security_context: Additional security context

        Returns:
            Tuple of (is_safe, risk_level, explanation)
        """
        if not self.enabled:
            return True, None, None

        try:
            prompt = self._build_request_assessment_prompt(
                server_name, tool_name, parameters, security_context
            )

            response = await self._query_llm(prompt)
            return self._parse_assessment_response(response)

        except Exception as e:
            logger.error(f"Error in request assessment: {e}")
            # Fail closed - return UNKNOWN risk level with assessment_failed flag
            # For security tools, we should not allow operations when assessment fails
            return False, "UNKNOWN", f"Assessment failed: {str(e)} - manual review required"

    async def assess_response(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        response_data: Any,
        security_context: str | None = None,
    ) -> tuple[bool, str | None, str | None]:
        """
        Assess if an MCP response contains security risks.

        Args:
            server_name: MCP server that provided the response
            tool_name: Tool that was called
            parameters: Parameters that were sent
            response_data: The response received
            security_context: Additional security context

        Returns:
            Tuple of (is_safe, risk_level, explanation)
        """
        if not self.enabled:
            return True, None, None

        try:
            prompt = self._build_response_assessment_prompt(
                server_name, tool_name, parameters, response_data, security_context
            )

            response = await self._query_llm(prompt)
            return self._parse_assessment_response(response)

        except Exception as e:
            logger.error(f"Error in response assessment: {e}")
            # Fail closed - return UNKNOWN risk level with assessment_failed flag
            # For security tools, we should not allow operations when assessment fails
            return False, "UNKNOWN", f"Assessment failed: {str(e)} - manual review required"

    def _build_request_assessment_prompt(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        security_context: str | None,
    ) -> str:
        """Build prompt for request assessment."""
        param_str = json.dumps(parameters, indent=2) if parameters else "{}"

        prompt = f"""You are a security expert assessing MCP (Model Context Protocol) requests for potential risks.

Analyze this request that an LLM wants to make:

Server: {server_name}
Tool: {tool_name}
Parameters: {param_str}
Security Context: {security_context or "None provided"}

Assess if this request poses security risks such as:
1. Attempting to access sensitive files (passwords, keys, .env, etc.)
2. Trying to execute system commands that could harm the system
3. Attempting to modify critical system files
4. Trying to access network resources inappropriately
5. Attempting privilege escalation
6. Any other security concerns

Respond in JSON format:
{{
    "is_safe": true/false,
    "risk_level": "BLOCKED/HIGH_RISK/REQUIRES_APPROVAL/LOW_RISK",
    "explanation": "Clear explanation of the assessment",
    "specific_risks": ["risk1", "risk2"] or []
}}

Be strict but reasonable - legitimate development operations should be allowed."""

        return prompt

    def _build_response_assessment_prompt(
        self,
        server_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        response_data: Any,
        security_context: str | None,
    ) -> str:
        """Build prompt for response assessment."""
        param_str = json.dumps(parameters, indent=2) if parameters else "{}"

        # Truncate very large responses
        response_str = str(response_data)
        if len(response_str) > 10000:
            response_str = response_str[:10000] + "... (truncated)"

        prompt = f"""You are a security expert assessing MCP responses for potential security risks.

A request was made to an MCP server and this was the response. Assess if the response contains sensitive information that should not be exposed.

Original Request:
- Server: {server_name}
- Tool: {tool_name}
- Parameters: {param_str}

Response Received:
{response_str}

Security Context: {security_context or "None provided"}

Assess if this response contains security risks such as:
1. Exposed passwords, API keys, or secrets
2. Sensitive system information that could aid an attacker
3. Personal or confidential data
4. File contents from sensitive locations
5. Information that could be used for privilege escalation
6. Any other security concerns

Respond in JSON format:
{{
    "is_safe": true/false,
    "risk_level": "BLOCKED/HIGH_RISK/REQUIRES_APPROVAL/LOW_RISK",
    "explanation": "Clear explanation of the assessment",
    "specific_risks": ["risk1", "risk2"] or [],
    "sensitive_content_found": true/false
}}

Be strict about sensitive data but allow normal development information."""

        return prompt

    async def _query_llm(self, prompt: str) -> dict[str, Any]:
        """Query the LLM for risk assessment."""
        if self.api_type == "openai":
            return await self._query_openai(prompt)
        else:
            return await self._query_anthropic(prompt)

    async def _query_openai(self, prompt: str) -> dict[str, Any]:
        """Query OpenAI API."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-4o-mini",
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a security expert. Always respond with valid JSON.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                },
                timeout=30.0,
            )
            response.raise_for_status()
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            return json.loads(content)  # type: ignore[no-any-return]

    async def _query_anthropic(self, prompt: str) -> dict[str, Any]:
        """Query Anthropic API."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key or "",
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-3-haiku-20240307",
                    "messages": [
                        {
                            "role": "user",
                            "content": f"{prompt}\n\nRemember to respond with valid JSON only.",
                        }
                    ],
                    "temperature": 0.1,
                    "max_tokens": 1000,
                },
                timeout=30.0,
            )
            response.raise_for_status()
            result = response.json()
            content = result["content"][0]["text"]
            # Extract JSON from the response
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())  # type: ignore[no-any-return]
            else:
                raise ValueError("No JSON found in response")

    def _parse_assessment_response(
        self, response: dict[str, Any]
    ) -> tuple[bool, str | None, str | None]:
        """Parse the LLM assessment response."""
        is_safe = response.get("is_safe", True)
        risk_level = response.get("risk_level", "LOW_RISK")
        explanation = response.get("explanation", "")

        # Add specific risks to explanation if present
        specific_risks = response.get("specific_risks", [])
        if specific_risks:
            explanation += f"\nSpecific risks: {', '.join(specific_risks)}"

        # Add sensitive content warning for responses
        if response.get("sensitive_content_found"):
            explanation += "\nSensitive content detected in response."

        return is_safe, risk_level, explanation


# Global instance
_risk_assessor: LLMRiskAssessor | None = None


def get_risk_assessor() -> LLMRiskAssessor:
    """Get or create the global risk assessor instance."""
    global _risk_assessor
    if _risk_assessor is None:
        _risk_assessor = LLMRiskAssessor()
    return _risk_assessor
