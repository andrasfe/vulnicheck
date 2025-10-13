"""Google OAuth 2.0 provider for FastMCP authentication."""

import os
from urllib.parse import urlencode

from fastmcp.server.auth.auth import OAuthProvider


class GoogleOAuthProvider(OAuthProvider):
    """
    Google OAuth 2.0 authentication provider for FastMCP.

    This provider implements Google OAuth 2.0 authentication flow for securing
    MCP server endpoints. It requires the following environment variables:
    - FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID
    - FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET
    - FASTMCP_SERVER_BASE_URL (for redirect URI)
    """

    GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        base_url: str | None = None,
        required_scopes: list[str] | None = None,
    ):
        """
        Initialize Google OAuth provider.

        Args:
            client_id: Google OAuth client ID (or from env FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID)
            client_secret: Google OAuth client secret (or from env FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET)
            base_url: Base URL for the server (or from env FASTMCP_SERVER_BASE_URL)
            required_scopes: List of required OAuth scopes (defaults to ['openid', 'email', 'profile'])
        """
        # Get credentials from environment if not provided
        self.client_id = client_id or os.environ.get("FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID")
        self.client_secret = client_secret or os.environ.get("FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET")
        self.base_url = base_url if base_url else os.environ.get("FASTMCP_SERVER_BASE_URL", "http://localhost:3000")

        if not self.client_id:
            raise ValueError(
                "Google OAuth client ID is required. "
                "Set FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID environment variable."
            )

        if not self.client_secret:
            raise ValueError(
                "Google OAuth client secret is required. "
                "Set FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET environment variable."
            )

        # Default scopes for Google OAuth
        if required_scopes is None:
            required_scopes = ["openid", "email", "profile"]

        # Initialize the base OAuthProvider
        super().__init__(
            issuer_url="https://accounts.google.com",
            service_documentation_url="https://developers.google.com/identity/protocols/oauth2",
            required_scopes=required_scopes,
        )

        # Set OAuth URLs
        self.authorization_endpoint = self.GOOGLE_AUTH_URL
        self.token_endpoint = self.GOOGLE_TOKEN_URL
        self.userinfo_endpoint = self.GOOGLE_USERINFO_URL

    @property
    def redirect_uri(self) -> str:
        """Get the OAuth redirect URI."""
        return f"{self.base_url.rstrip('/')}/oauth/callback"

    def get_authorization_url(self, state: str, scopes: list[str] | None = None) -> str:
        """
        Generate the Google OAuth authorization URL.

        Args:
            state: CSRF protection state token
            scopes: OAuth scopes to request (uses required_scopes if not provided)

        Returns:
            The authorization URL to redirect the user to
        """
        scopes = scopes or self.required_scopes or ["openid", "email", "profile"]

        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "state": state,
            "access_type": "online",  # Don't request refresh tokens by default
            "prompt": "select_account",  # Allow user to select account
        }

        return f"{self.GOOGLE_AUTH_URL}?{urlencode(params)}"

    async def exchange_code_for_token(self, code: str) -> dict[str, str]:
        """
        Exchange an authorization code for an access token.

        Args:
            code: The authorization code from Google

        Returns:
            Token response containing access_token and other fields
        """
        import aiohttp

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
        }

        async with aiohttp.ClientSession() as session, session.post(
            self.GOOGLE_TOKEN_URL, data=data
        ) as response:
            if response.status != 200:
                error_text = await response.text()
                raise ValueError(f"Failed to exchange code for token: {error_text}")

            result: dict[str, str] = await response.json()
            return result

    async def get_user_info(self, access_token: str) -> dict[str, str]:
        """
        Get user information from Google using an access token.

        Args:
            access_token: The OAuth access token

        Returns:
            User information from Google
        """
        import aiohttp

        headers = {"Authorization": f"Bearer {access_token}"}

        async with aiohttp.ClientSession() as session, session.get(
            self.GOOGLE_USERINFO_URL, headers=headers
        ) as response:
            if response.status != 200:
                error_text = await response.text()
                raise ValueError(f"Failed to get user info: {error_text}")

            result: dict[str, str] = await response.json()
            return result

    async def validate_token(self, access_token: str) -> bool:
        """
        Validate an access token by attempting to fetch user info.

        Args:
            access_token: The OAuth access token to validate

        Returns:
            True if the token is valid, False otherwise
        """
        try:
            await self.get_user_info(access_token)
            return True
        except Exception:
            return False
