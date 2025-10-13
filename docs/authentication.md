# VulniCheck Authentication Guide

VulniCheck MCP Server now supports Google OAuth 2.0 authentication to secure your vulnerability checking endpoints.

## Overview

The authentication feature is optional and disabled by default to maintain backward compatibility. When enabled, it requires users to authenticate with their Google account before accessing the MCP tools.

## Quick Start

### 1. Default Mode (No Authentication)

By default, VulniCheck runs without authentication:

```bash
vulnicheck
# or
python -m vulnicheck.server
```

### 2. Google OAuth Mode

To enable Google OAuth authentication:

```bash
# Set required environment variables
export FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID="your-client-id"
export FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET="your-client-secret"
export FASTMCP_SERVER_BASE_URL="https://your-server.com"  # Optional, defaults to http://localhost:3000

# Run with authentication
vulnicheck --auth-mode google
# or
python -m vulnicheck.server --auth-mode google
```

## Setting Up Google OAuth

### 1. Create Google OAuth Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth client ID"
5. Choose "Web application" as the application type
6. Add authorized redirect URIs:
   - For development: `http://localhost:3000/oauth/callback`
   - For production: `https://your-server.com/oauth/callback`
7. Save your Client ID and Client Secret

### 2. Configure Environment Variables

Set the following environment variables:

```bash
# Required for Google OAuth
export FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
export FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET="your-client-secret"

# Optional - defaults to http://localhost:3000
export FASTMCP_SERVER_BASE_URL="https://vulnicheck.example.com"

# Optional - change default port (default: 3000)
export MCP_PORT="8080"
```

### 3. Run the Server

```bash
vulnicheck --auth-mode google
```

The server will display:
- Authentication mode status
- OAuth configuration details
- Redirect URI for Google OAuth
- OAuth endpoint URLs

## Command Line Options

```bash
vulnicheck --help
```

Options:
- `--auth-mode {google,disabled}`: Authentication mode (default: disabled)
  - `disabled`: No authentication required (default)
  - `google`: Google OAuth 2.0 authentication

## OAuth Flow

When Google OAuth is enabled:

1. Users access the MCP endpoint at `http://localhost:3000/mcp`
2. Unauthenticated requests are redirected to Google's OAuth authorization page
3. After Google authentication, users are redirected to `/oauth/callback`
4. The server validates the OAuth token and grants access to MCP tools
5. Subsequent requests include the OAuth token for authorization

## Security Considerations

1. **HTTPS in Production**: Always use HTTPS in production environments
   ```bash
   export FASTMCP_SERVER_BASE_URL="https://your-secure-server.com"
   ```

2. **Client Secret Security**: Never commit client secrets to version control
   - Use environment variables or secret management systems
   - Rotate secrets regularly

3. **Redirect URI Validation**: Ensure redirect URIs match exactly in Google Console

4. **Token Validation**: The server validates tokens on each request by checking with Google's userinfo endpoint

## Troubleshooting

### Missing Credentials Error

```
ERROR: FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID environment variable is required for Google OAuth
```

**Solution**: Set the required environment variables before running the server.

### Invalid Redirect URI

If Google OAuth shows a redirect URI mismatch error:
1. Check that `FASTMCP_SERVER_BASE_URL` matches your Google OAuth configuration
2. Ensure the redirect URI in Google Console includes `/oauth/callback`

### Port Conflicts

If port 3000 is already in use:
```bash
export MCP_PORT=8080
vulnicheck --auth-mode google
```

## Integration with MCP Clients

MCP clients connecting to an authenticated server need to:
1. Support OAuth authentication flow
2. Handle OAuth redirects
3. Include OAuth tokens in subsequent requests

Example client configuration:
```json
{
  "mcpServers": {
    "vulnicheck": {
      "command": "vulnicheck",
      "args": ["--auth-mode", "google"],
      "env": {
        "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID": "your-client-id",
        "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET": "your-secret",
        "FASTMCP_SERVER_BASE_URL": "https://your-server.com"
      }
    }
  }
}
```

## Backward Compatibility

The authentication feature is fully backward compatible:

- Default behavior (no `--auth-mode` flag) works exactly as before
- Existing integrations continue to work without changes
- Authentication is opt-in via command line flag
- All existing environment variables for API keys (NVD, GitHub) still work

## Docker Support

When using Docker, pass environment variables and auth mode:

```dockerfile
# Dockerfile
FROM vulnicheck:latest
ENV FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
ENV FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
ENV FASTMCP_SERVER_BASE_URL=${BASE_URL}
CMD ["vulnicheck", "--auth-mode", "google"]
```

```bash
# Docker run
docker run -p 3000:3000 \
  -e FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID="your-client-id" \
  -e FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET="your-secret" \
  -e FASTMCP_SERVER_BASE_URL="https://your-server.com" \
  vulnicheck --auth-mode google
```

## API Reference

### GoogleOAuthProvider Class

The `GoogleOAuthProvider` class implements Google OAuth 2.0 authentication for FastMCP:

```python
from vulnicheck.auth import GoogleOAuthProvider

# Initialize with explicit credentials
provider = GoogleOAuthProvider(
    client_id="your-client-id",
    client_secret="your-secret",
    base_url="https://your-server.com",
    required_scopes=["openid", "email", "profile"]  # Optional
)

# Or use environment variables
provider = GoogleOAuthProvider()  # Reads from env vars
```

Methods:
- `get_authorization_url(state, scopes)`: Generate OAuth authorization URL
- `exchange_code_for_token(code)`: Exchange auth code for access token
- `get_user_info(access_token)`: Get user info from Google
- `validate_token(access_token)`: Validate an access token

## Support

For issues or questions about authentication:
1. Check the [GitHub Issues](https://github.com/andrasfe/vulnicheck/issues)
2. Review the [FastMCP documentation](https://github.com/jlowin/fastmcp)
3. Ensure all environment variables are correctly set