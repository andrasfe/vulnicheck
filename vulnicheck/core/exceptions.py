"""Custom exception hierarchy for VulniCheck.

This module provides a structured exception hierarchy to replace
broad `except Exception` catches with specific error types.
"""


class VulniCheckError(Exception):
    """Base exception for all VulniCheck errors.

    All custom exceptions should inherit from this class to allow
    callers to catch all VulniCheck-specific errors with a single
    except clause when appropriate.
    """
    pass


# =============================================================================
# Scanner Errors
# =============================================================================

class ScannerError(VulniCheckError):
    """Base exception for scanner-related errors."""
    pass


class DependencyParseError(ScannerError):
    """Error parsing dependency files (requirements.txt, pyproject.toml, etc.)."""
    pass


class FileNotFoundError(ScannerError):
    """File or directory not found during scanning."""
    pass


class FileTooLargeError(ScannerError):
    """File exceeds maximum allowed size for scanning."""
    pass


class UnsupportedFileTypeError(ScannerError):
    """File type is not supported for scanning."""
    pass


# =============================================================================
# Client Errors (API/Network)
# =============================================================================

class ClientError(VulniCheckError):
    """Base exception for API client errors."""
    pass


class NetworkError(ClientError):
    """Network connectivity or request error."""
    pass


class APIError(ClientError):
    """Error returned by an external API."""

    def __init__(self, message: str, status_code: int | None = None, response_body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class RateLimitError(ClientError):
    """API rate limit exceeded."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class AuthenticationError(ClientError):
    """API authentication failed (invalid/missing credentials)."""
    pass


class TimeoutError(ClientError):
    """API request timed out."""
    pass


# =============================================================================
# Security Errors
# =============================================================================

class SecurityError(VulniCheckError):
    """Base exception for security-related errors."""
    pass


class ZipBombError(SecurityError):
    """Potential zip bomb detected (high compression ratio, excessive nesting)."""
    pass


class PathTraversalError(SecurityError):
    """Attempted path traversal attack detected."""
    pass


class MaliciousContentError(SecurityError):
    """Malicious content detected in file or response."""
    pass


class TrustStoreError(SecurityError):
    """Error with MCP server trust store validation."""
    pass


class RiskAssessmentError(SecurityError):
    """Error during risk assessment of MCP operations."""
    pass


# =============================================================================
# Configuration Errors
# =============================================================================

class ConfigurationError(VulniCheckError):
    """Base exception for configuration errors."""
    pass


class InvalidConfigError(ConfigurationError):
    """Configuration file is invalid or malformed."""
    pass


class MissingConfigError(ConfigurationError):
    """Required configuration is missing."""
    pass


# =============================================================================
# Validation Errors
# =============================================================================

class ValidationError(VulniCheckError):
    """Base exception for input validation errors."""
    pass


class InvalidInputError(ValidationError):
    """Invalid input provided to a function or tool."""
    pass


class InvalidVersionError(ValidationError):
    """Invalid package version format."""
    pass


class InvalidURLError(ValidationError):
    """Invalid URL format."""
    pass


# =============================================================================
# MCP/Provider Errors
# =============================================================================

class MCPError(VulniCheckError):
    """Base exception for MCP-related errors."""
    pass


class MCPConnectionError(MCPError):
    """Error connecting to MCP server."""
    pass


class MCPToolError(MCPError):
    """Error executing MCP tool."""
    pass


class ProviderError(VulniCheckError):
    """Base exception for file provider errors."""
    pass


class UnsupportedOperationError(ProviderError):
    """Operation not supported by the file provider."""
    pass


class PermissionDeniedError(ProviderError):
    """Permission denied for file operation."""
    pass


# =============================================================================
# Convenience Aliases for Common Cases
# =============================================================================

# These provide shorter names for frequently used exceptions
ParseError = DependencyParseError
NotFoundError = FileNotFoundError
