"""URL detection from HTTP request headers."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def detect_public_url_from_headers(headers: dict[str, Any]) -> str | None:
    """
    Detect the public URL from HTTP request headers.

    When behind a reverse proxy like ngrok, the original Host header
    is preserved in X-Forwarded-Host and the protocol in X-Forwarded-Proto.

    Args:
        headers: HTTP request headers (case-insensitive dict)

    Returns:
        The detected public URL (e.g., "https://abc123.ngrok-free.dev")
        or None if detection fails
    """
    # Convert headers to lowercase for case-insensitive access
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Try X-Forwarded headers first (set by ngrok and other proxies)
    forwarded_proto = headers_lower.get("x-forwarded-proto")
    forwarded_host = headers_lower.get("x-forwarded-host")

    if forwarded_proto and forwarded_host:
        url = f"{forwarded_proto}://{forwarded_host}"
        logger.debug(f"Detected public URL from X-Forwarded headers: {url}")
        return url

    # Fallback to Host header (direct access)
    host = headers_lower.get("host")
    if host:
        # Determine protocol - default to http for localhost, https otherwise
        proto = "http" if "localhost" in host or "127.0.0.1" in host else "https"

        # Check X-Forwarded-Proto even if X-Forwarded-Host wasn't set
        if forwarded_proto:
            proto = forwarded_proto

        url = f"{proto}://{host}"
        logger.debug(f"Detected public URL from Host header: {url}")
        return url

    logger.warning("Could not detect public URL from request headers")
    return None


def compare_urls(detected_url: str | None, configured_url: str | None) -> dict[str, Any]:
    """
    Compare detected URL with configured URL and provide recommendations.

    Args:
        detected_url: URL detected from request headers
        configured_url: URL from FASTMCP_SERVER_BASE_URL env var

    Returns:
        Dict with status, match result, and recommendations
    """
    result = {
        "detected_url": detected_url,
        "configured_url": configured_url,
        "match": False,
        "warning": None,
        "recommendation": None,
    }

    if not detected_url:
        result["warning"] = "Could not detect public URL from request headers"
        return result

    if not configured_url:
        result["warning"] = "FASTMCP_SERVER_BASE_URL not configured"
        result["recommendation"] = (
            f"Set FASTMCP_SERVER_BASE_URL={detected_url} "
            "or add to .env: NGROK_URL={detected_url}"
        )
        return result

    # Normalize URLs for comparison (remove trailing slashes)
    detected_normalized = detected_url.rstrip("/")
    configured_normalized = configured_url.rstrip("/")

    if detected_normalized == configured_normalized:
        result["match"] = True
        result["recommendation"] = "URLs match - configuration is correct"
    else:
        result["match"] = False
        result["warning"] = "Detected URL does not match configured URL"
        result["recommendation"] = (
            f"Update .env with: NGROK_URL={detected_url}\n"
            f"Then run: ./restart-vulnicheck-ngrok.sh\n"
            f"Also update Google Cloud Console redirect URI to: {detected_url}/oauth/callback"
        )

    return result
