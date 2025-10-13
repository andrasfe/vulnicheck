"""Configuration models for VulniCheck authentication."""


from pydantic import BaseModel, Field


class AuthConfig(BaseModel):
    """Base authentication configuration."""

    enabled: bool = False


class GoogleAuthConfig(AuthConfig):
    """Google OAuth 2.0 configuration."""

    enabled: bool = True
    client_id: str = Field(..., description="Google OAuth Client ID")
    client_secret: str = Field(..., description="Google OAuth Client Secret")
    base_url: str = Field(
        default="http://localhost:3000", description="Base URL for OAuth callbacks"
    )
    redirect_uri: str | None = Field(
        default=None,
        description="Custom redirect URI (optional, auto-generated if not provided)",
    )
    required_scopes: list[str] = Field(
        default_factory=lambda: ["openid", "email", "profile"],
        description="Required OAuth scopes",
    )
    token_storage_path: str = Field(
        default="/home/vulnicheck/.vulnicheck/tokens",
        description="Path for token storage",
    )
    allowed_domains: list[str] | None = Field(
        default=None, description="Restrict access to specific email domains"
    )
