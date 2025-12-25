"""Core utilities for caching, rate limiting, logging, and agent detection."""

from .agent_detector import AgentDetector, detect_agent
from .cache import VulnerabilityCache
from .exceptions import (
    APIError,
    AuthenticationError,
    ClientError,
    ConfigurationError,
    DependencyParseError,
    FileTooLargeError,
    InvalidConfigError,
    InvalidInputError,
    MCPConnectionError,
    MCPError,
    MCPToolError,
    NetworkError,
    PathTraversalError,
    PermissionDeniedError,
    ProviderError,
    RateLimitError,
    RiskAssessmentError,
    ScannerError,
    SecurityError,
    TrustStoreError,
    UnsupportedFileTypeError,
    UnsupportedOperationError,
    ValidationError,
    VulniCheckError,
    ZipBombError,
)
from .logging_config import configure_mcp_logging
from .mcp_paths import (
    MCP_CONFIG_PATHS,
    check_mcp_exists_anywhere,
    find_existing_mcp_configs,
    get_mcp_paths_for_agent,
)
from .rate_limiter import APIRateLimiters, RateLimiter, get_nvd_rate_limiter
from .service_container import (
    ServiceContainer,
    get_service_container,
    reset_service_container,
)
from .url_detector import compare_urls, detect_public_url_from_headers

__all__ = [
    # Cache
    "VulnerabilityCache",
    # Rate limiting
    "get_nvd_rate_limiter",
    "RateLimiter",
    "APIRateLimiters",
    # Logging
    "configure_mcp_logging",
    # Agent detection
    "detect_agent",
    "AgentDetector",
    # MCP paths
    "get_mcp_paths_for_agent",
    "MCP_CONFIG_PATHS",
    "find_existing_mcp_configs",
    "check_mcp_exists_anywhere",
    # URL detection
    "detect_public_url_from_headers",
    "compare_urls",
    # Service container
    "ServiceContainer",
    "get_service_container",
    "reset_service_container",
    # Exceptions
    "VulniCheckError",
    "ScannerError",
    "DependencyParseError",
    "FileTooLargeError",
    "UnsupportedFileTypeError",
    "ClientError",
    "NetworkError",
    "APIError",
    "RateLimitError",
    "AuthenticationError",
    "SecurityError",
    "ZipBombError",
    "PathTraversalError",
    "TrustStoreError",
    "RiskAssessmentError",
    "ConfigurationError",
    "InvalidConfigError",
    "ValidationError",
    "InvalidInputError",
    "MCPError",
    "MCPConnectionError",
    "MCPToolError",
    "ProviderError",
    "UnsupportedOperationError",
    "PermissionDeniedError",
]
