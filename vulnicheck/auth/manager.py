"""Authentication manager for VulniCheck MCP server."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from .config import AuthConfig, GoogleAuthConfig

if TYPE_CHECKING:
    from fastmcp.server.auth.providers.google import GoogleProvider

logger = logging.getLogger(__name__)


class AuthenticationManager:
    """Manages authentication providers for VulniCheck server."""

    def __init__(self, auth_mode: str = "none", config: AuthConfig | None = None):
        """
        Initialize authentication manager.

        Args:
            auth_mode: Authentication mode ('none' or 'google')
            config: Optional authentication configuration
        """
        self.auth_mode = auth_mode
        self.config = config or self._load_config_from_env()
        self.provider = None

    def _load_config_from_env(self) -> AuthConfig:
        """Load authentication configuration from environment variables."""
        if self.auth_mode == "google":
            return GoogleAuthConfig(
                client_id=os.environ.get("FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID", ""),
                client_secret=os.environ.get(
                    "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET", ""
                ),
                base_url=os.environ.get(
                    "FASTMCP_SERVER_BASE_URL", "http://localhost:3000"
                ),
                redirect_uri=os.environ.get("FASTMCP_SERVER_AUTH_REDIRECT_URI"),
                required_scopes=os.environ.get(
                    "FASTMCP_SERVER_AUTH_SCOPES", "openid,email,profile"
                ).split(","),
                token_storage_path=os.environ.get(
                    "FASTMCP_SERVER_AUTH_TOKEN_STORAGE",
                    "/home/vulnicheck/.vulnicheck/tokens",
                ),
            )
        return AuthConfig()

    def get_provider(self) -> GoogleProvider | None:
        """
        Get the configured authentication provider.

        Returns:
            GoogleProvider instance or None if auth is disabled

        Raises:
            ValueError: If auth is enabled but configuration is invalid
        """
        if self.auth_mode == "none":
            logger.info("Authentication disabled - running in open mode")
            return None

        if self.auth_mode == "google":
            if not isinstance(self.config, GoogleAuthConfig):
                raise ValueError(
                    "Google OAuth mode requires GoogleAuthConfig configuration"
                )

            if not self.config.client_id or not self.config.client_secret:
                raise ValueError(
                    "Google OAuth requires FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID and "
                    "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET environment variables"
                )

            logger.info(f"Initializing Google OAuth with base URL: {self.config.base_url}")

            # Lazy import to avoid loading auth modules when not needed
            from .google_oauth import GoogleOAuthProvider

            return GoogleOAuthProvider(
                client_id=self.config.client_id,
                client_secret=self.config.client_secret,
                base_url=self.config.base_url,
                required_scopes=list(self.config.required_scopes) if self.config.required_scopes else None,
            )

        raise ValueError(f"Unknown authentication mode: {self.auth_mode}")

    def validate_config(self) -> bool:
        """
        Validate the authentication configuration.

        Returns:
            True if configuration is valid, False otherwise
        """
        if self.auth_mode == "none":
            return True

        if self.auth_mode == "google":
            required = ["client_id", "client_secret", "base_url"]
            for field in required:
                if not getattr(self.config, field, None):
                    logger.error(f"Missing required Google OAuth field: {field}")
                    return False
            return True

        return False
