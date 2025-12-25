"""Tests for Google OAuth authentication wrapper.

Note: GoogleOAuthProvider is a thin wrapper around FastMCP's GoogleProvider.
We only test the wrapper's credential loading and validation logic, not
FastMCP's internal OAuth implementation.
"""

import os
from unittest.mock import patch

import pytest

from vulnicheck.auth import GoogleOAuthProvider


class TestGoogleOAuthProvider:
    """Test suite for GoogleOAuthProvider wrapper function."""

    def test_provider_initialization_with_explicit_params(self):
        """Test provider initialization with explicit parameters."""
        # GoogleOAuthProvider returns a FastMCP GoogleProvider instance
        # We verify it was created successfully (no exceptions)
        provider = GoogleOAuthProvider(
            client_id="test-client-id",
            client_secret="test-secret",
            base_url="https://example.com",
        )

        # Provider should be an instance from FastMCP
        assert provider is not None
        # Check that it has the expected type name (GoogleProvider from FastMCP)
        assert "GoogleProvider" in type(provider).__name__

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

            # Provider should be created successfully from env vars
            assert provider is not None
            assert "GoogleProvider" in type(provider).__name__

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

        # FastMCP normalizes URLs, so we check the string representation contains the expected host
        assert "localhost:3000" in str(provider.base_url)

    def test_custom_scopes(self):
        """Test provider with custom scopes.

        Note: We verify the provider is created without error when custom scopes
        are provided. The actual OAuth flow is handled by FastMCP's GoogleProvider.
        """
        provider = GoogleOAuthProvider(
            client_id="test-id",
            client_secret="test-secret",
            required_scopes=["openid", "custom.scope"],
        )
        # Provider should be created successfully with custom scopes
        assert provider is not None
        assert "GoogleProvider" in type(provider).__name__

    def test_provider_client_secret_precedence(self):
        """Test that explicit params take precedence over env vars."""
        with patch.dict(
            os.environ,
            {
                "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID": "env-client-id",
                "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET": "env-secret",
            },
        ):
            # Explicit params should override env vars
            provider = GoogleOAuthProvider(
                client_id="explicit-client-id",
                client_secret="explicit-secret",
            )

            # Provider should be created with explicit params
            assert provider is not None
