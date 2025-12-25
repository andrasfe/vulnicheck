"""Google OAuth 2.0 provider for FastMCP authentication."""

import os

from fastmcp.server.auth.providers.google import GoogleProvider


def GoogleOAuthProvider(
    client_id: str | None = None,
    client_secret: str | None = None,
    base_url: str | None = None,
    required_scopes: list[str] | None = None,
) -> GoogleProvider:
    """
    Create a Google OAuth provider for FastMCP.

    This is a convenience wrapper around FastMCP's GoogleProvider that reads
    credentials from environment variables if not provided.

    Args:
        client_id: Google OAuth client ID (or from env FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID)
        client_secret: Google OAuth client secret (or from env FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET)
        base_url: Base URL for the server (or from env FASTMCP_SERVER_BASE_URL)
        required_scopes: List of required OAuth scopes (defaults to ['openid', 'email', 'profile'])

    Returns:
        Configured GoogleProvider instance

    Raises:
        ValueError: If required credentials are missing
    """
    # Get credentials from environment if not provided
    client_id = client_id or os.environ.get("FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID")
    client_secret = client_secret or os.environ.get("FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET")
    resolved_base_url = base_url or os.environ.get("FASTMCP_SERVER_BASE_URL", "http://localhost:3000")

    if not client_id:
        raise ValueError(
            "Google OAuth client ID is required. "
            "Set FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID environment variable."
        )

    if not client_secret:
        raise ValueError(
            "Google OAuth client secret is required. "
            "Set FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET environment variable."
        )

    # Default scopes for Google OAuth
    if required_scopes is None:
        required_scopes = ["openid", "email", "profile"]

    # Create and return FastMCP's GoogleProvider
    return GoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        base_url=resolved_base_url,
        required_scopes=required_scopes,
    )
