"""
Response sanitizer for MCP responses.

This module provides sanitization of MCP responses to prevent prompt injection
and other security issues.
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class ResponseSanitizer:
    """Sanitizes MCP responses to prevent security issues."""

    # ANSI escape sequence pattern - handles codes with or without numbers
    ANSI_PATTERN = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

    # Common prompt injection patterns
    INJECTION_PATTERNS = [
        # Direct instruction patterns
        re.compile(r'(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions?|commands?|rules?)', re.MULTILINE),
        re.compile(r'(?i)(new|updated?)\s+(instructions?|rules?|commands?).*?:', re.MULTILINE),
        re.compile(r'(?i)^(###|system:|assistant:|human:|user:)', re.MULTILINE),

        # Boundary-breaking attempts
        re.compile(r'(?i)<\|?(system|endoftext|startoftext)\|?>', re.MULTILINE),
        re.compile(r'(?i)\[(?:INST|/INST|SYS|/SYS)\]', re.MULTILINE),

        # Role-switching attempts
        re.compile(r'(?i)(you\s+are|act\s+as|pretend\s+to\s+be|behave\s+as)\s+(now\s+)?a', re.MULTILINE),
        re.compile(r'(?i)(i\s+am|as\s+an?)\s+(a\s+)?(helpful\s+)?(assistant|ai|model)', re.MULTILINE),

        # Command injection attempts
        re.compile(r'(?i)(execute|run|eval)\s*\(', re.MULTILINE),
        re.compile(r'(?i)(os\.|subprocess\.|exec\s*\(|eval\s*\()', re.MULTILINE),
    ]

    # Suspicious content patterns that warrant a warning
    WARNING_PATTERNS = [
        re.compile(r'(?i)(password|secret|api[_\s]?key|token|credential)', re.MULTILINE),
        re.compile(r'(?i)(sudo|admin|root)\s+', re.MULTILINE),
        re.compile(r'(?i)base64\s*[:=]', re.MULTILINE),
    ]

    def __init__(self, strict_mode: bool = False):
        """
        Initialize the response sanitizer.

        Args:
            strict_mode: If True, apply more aggressive sanitization
        """
        self.strict_mode = strict_mode
        self.detection_count = 0

    def sanitize(self, response: Any) -> tuple[Any, list[str]]:
        """
        Sanitize an MCP response.

        Args:
            response: The response to sanitize

        Returns:
            Tuple of (sanitized_response, list_of_issues_found)
        """
        issues: list[str] = []

        if isinstance(response, str):
            sanitized, str_issues = self._sanitize_string(response)
            issues.extend(str_issues)
            return sanitized, issues

        elif isinstance(response, dict):
            sanitized_dict: dict[Any, Any] = {}
            for key, value in response.items():
                sanitized_value, value_issues = self.sanitize(value)
                sanitized_dict[key] = sanitized_value
                issues.extend(value_issues)
            return sanitized_dict, issues

        elif isinstance(response, list):
            sanitized_list: list[Any] = []
            for item in response:
                sanitized_item, item_issues = self.sanitize(item)
                sanitized_list.append(sanitized_item)
                issues.extend(item_issues)
            return sanitized_list, issues

        else:
            # For other types, return as-is
            return response, issues

    def _sanitize_string(self, text: str) -> tuple[str, list[str]]:
        """
        Sanitize a string value.

        Args:
            text: The string to sanitize

        Returns:
            Tuple of (sanitized_string, list_of_issues_found)
        """
        issues: list[str] = []
        sanitized = text

        # Remove ANSI escape sequences
        if self.ANSI_PATTERN.search(sanitized):
            sanitized = self.ANSI_PATTERN.sub('', sanitized)
            issues.append("ANSI escape sequences removed")

        # Check for prompt injection attempts
        for pattern in self.INJECTION_PATTERNS:
            match = pattern.search(sanitized)
            if match:
                self.detection_count += 1
                issues.append(f"Potential prompt injection detected: '{match.group()[:50]}...'")

                if self.strict_mode:
                    # In strict mode, redact the suspicious content
                    sanitized = pattern.sub('[REDACTED]', sanitized)
                else:
                    # In normal mode, just add warning markers
                    sanitized = pattern.sub(lambda m: f"[WARNING: SUSPICIOUS CONTENT] {m.group()}", sanitized)

        # Check for warning patterns
        for pattern in self.WARNING_PATTERNS:
            if pattern.search(sanitized):
                issues.append("Sensitive content pattern detected")

        return sanitized, issues

    def check_for_injection(self, response: Any) -> tuple[bool, list[str]]:
        """
        Check if a response contains potential prompt injection.

        Args:
            response: The response to check

        Returns:
            Tuple of (has_injection, list_of_detections)
        """
        _, issues = self.sanitize(response)

        # Filter for actual injection issues
        injection_issues = [
            issue for issue in issues
            if "prompt injection" in issue.lower()
        ]

        return len(injection_issues) > 0, injection_issues

    def get_stats(self) -> dict[str, Any]:
        """
        Get sanitization statistics.

        Returns:
            Dictionary of statistics
        """
        return {
            "detection_count": self.detection_count,
            "strict_mode": self.strict_mode
        }


# Global instance
_sanitizer: ResponseSanitizer | None = None


def get_sanitizer(strict_mode: bool = False) -> ResponseSanitizer:
    """Get the global sanitizer instance."""
    global _sanitizer
    if _sanitizer is None or _sanitizer.strict_mode != strict_mode:
        _sanitizer = ResponseSanitizer(strict_mode)
    return _sanitizer
