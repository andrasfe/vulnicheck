"""Tests for Google OAuth authentication."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnicheck.auth import GoogleOAuthProvider


class TestGoogleOAuthProvider:
    """Test suite for GoogleOAuthProvider."""

    def test_provider_initialization_with_explicit_params(self):
        """Test provider initialization with explicit parameters."""
        provider = GoogleOAuthProvider(
            client_id="test-client-id",
            client_secret="test-secret",
            base_url="https://example.com",
        )

        assert provider.client_id == "test-client-id"
        assert provider.client_secret == "test-secret"
        assert provider.base_url == "https://example.com"
        assert provider.redirect_uri == "https://example.com/oauth/callback"

    def test_provider_initialization_from_env(self):
        """Test provider initialization from environment variables."""
        with patch.dict(
            os.environ,
            {
                "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID": "env-client-id",
                "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET": "env-secret",
                "FASTMCP_SERVER_BASE_URL": "https://env.example.com",
            },
        ):
            provider = GoogleOAuthProvider()

            assert provider.client_id == "env-client-id"
            assert provider.client_secret == "env-secret"
            assert provider.base_url == "https://env.example.com"

    def test_provider_missing_client_id(self):
        """Test provider raises error when client_id is missing."""
        with patch.dict(os.environ, {}, clear=True), pytest.raises(
            ValueError, match="Google OAuth client ID is required"
        ):
            GoogleOAuthProvider()

    def test_provider_missing_client_secret(self):
        """Test provider raises error when client_secret is missing."""
        with patch.dict(
            os.environ,
            {"FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID": "test-id"},
            clear=True,
        ), pytest.raises(ValueError, match="Google OAuth client secret is required"):
            GoogleOAuthProvider()

    def test_default_base_url(self):
        """Test provider uses default base URL when not specified."""
        provider = GoogleOAuthProvider(
            client_id="test-id",
            client_secret="test-secret",
        )

        assert provider.base_url == "http://localhost:3000"
        assert provider.redirect_uri == "http://localhost:3000/oauth/callback"

    def test_get_authorization_url(self):
        """Test authorization URL generation."""
        provider = GoogleOAuthProvider(
            client_id="test-client-id",
            client_secret="test-secret",
            base_url="https://example.com",
        )

        auth_url = provider.get_authorization_url(state="test-state")

        assert "https://accounts.google.com/o/oauth2/v2/auth" in auth_url
        assert "client_id=test-client-id" in auth_url
        assert "redirect_uri=https%3A%2F%2Fexample.com%2Foauth%2Fcallback" in auth_url
        assert "state=test-state" in auth_url
        assert "response_type=code" in auth_url
        assert "scope=openid+email+profile" in auth_url

    def test_custom_scopes(self):
        """Test provider with custom scopes."""
        provider = GoogleOAuthProvider(
            client_id="test-id",
            client_secret="test-secret",
            required_scopes=["openid", "custom.scope"],
        )

        auth_url = provider.get_authorization_url(state="test")
        assert "scope=openid+custom.scope" in auth_url

    @pytest.mark.asyncio
    async def test_exchange_code_for_token_success(self):
        """Test successful token exchange."""
        provider = GoogleOAuthProvider(
            client_id="test-id",
            client_secret="test-secret",
        )

        # Create mock response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "access_token": "test-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        })

        # Create mock session
        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))

        # Mock the ClientSession context manager
        with patch("aiohttp.ClientSession", return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_session))):
            result = await provider.exchange_code_for_token("test-code")

            assert result["access_token"] == "test-access-token"

    @pytest.mark.asyncio
    async def test_exchange_code_for_token_failure(self):
        """Test failed token exchange."""
        provider = GoogleOAuthProvider(
            client_id="test-id",
            client_secret="test-secret",
        )

        # Create mock response
        mock_response = MagicMock()
        mock_response.status = 400
        mock_response.text = AsyncMock(return_value="Invalid authorization code")

        # Create mock session
        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))

        # Mock the ClientSession context manager
        with patch(
            "aiohttp.ClientSession",
            return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_session)),
        ), pytest.raises(ValueError, match="Failed to exchange code for token"):
            await provider.exchange_code_for_token("invalid-code")

    @pytest.mark.asyncio
    async def test_get_user_info_success(self):
        """Test successful user info retrieval."""
        provider = GoogleOAuthProvider(
            client_id="test-id",
            client_secret="test-secret",
        )

        # Create mock response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "id": "123456",
            "email": "user@example.com",
            "name": "Test User",
        })

        # Create mock session
        mock_session = MagicMock()
        mock_session.get = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response)))

        # Mock the ClientSession context manager
        with patch("aiohttp.ClientSession", return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_session))):
            result = await provider.get_user_info("test-token")

            assert result["email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_validate_token_valid(self):
        """Test token validation with valid token."""
        provider = GoogleOAuthProvider(
            client_id="test-id",
            client_secret="test-secret",
        )

        with patch.object(provider, "get_user_info") as mock_get_user:
            mock_get_user.return_value = {"email": "user@example.com"}

            is_valid = await provider.validate_token("valid-token")

            assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_token_invalid(self):
        """Test token validation with invalid token."""
        provider = GoogleOAuthProvider(
            client_id="test-id",
            client_secret="test-secret",
        )

        with patch.object(provider, "get_user_info") as mock_get_user:
            mock_get_user.side_effect = ValueError("Invalid token")

            is_valid = await provider.validate_token("invalid-token")

            assert is_valid is False
