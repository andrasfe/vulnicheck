"""Authentication module for VulniCheck MCP server.

This module provides optional authentication support for the VulniCheck MCP server.
Authentication is disabled by default and only loaded when explicitly enabled.
"""

from .config import AuthConfig, GoogleAuthConfig
from .manager import AuthenticationManager


def GoogleOAuthProvider(*args, **kwargs):
    """Lazy loader for GoogleOAuthProvider to avoid importing FastMCP auth at startup."""
    from .google_oauth import GoogleOAuthProvider as _GoogleOAuthProvider

    return _GoogleOAuthProvider(*args, **kwargs)


__all__ = [
    "AuthConfig",
    "GoogleAuthConfig",
    "GoogleOAuthProvider",
    "AuthenticationManager",
]
