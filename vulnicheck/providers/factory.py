"""
File provider factory and manager.

This module provides factory functions and provider management for creating
appropriate FileProvider instances based on deployment context.
"""

import logging
import os

from ..mcp.mcp_client import MCPConnection
from .base import FileProvider
from .local import LocalFileProvider
from .mcp_client import MCPClientFileProvider

logger = logging.getLogger(__name__)


class FileProviderManager:
    """
    Manager for FileProvider instances.

    Provides factory methods and caching for FileProvider instances,
    enabling easy switching between local and MCP client providers
    based on deployment context.
    """

    def __init__(self) -> None:
        """Initialize the file provider manager."""
        self._local_provider: LocalFileProvider | None = None
        self._mcp_providers: dict[str, MCPClientFileProvider] = {}

    def get_local_provider(self, base_path: str | None = None) -> LocalFileProvider:
        """
        Get a local file provider instance.

        Args:
            base_path: Optional base path to restrict operations to

        Returns:
            LocalFileProvider instance
        """
        if self._local_provider is None or (base_path and self._local_provider.base_path != base_path):
            self._local_provider = LocalFileProvider(base_path=base_path)
            logger.debug(f"Created LocalFileProvider with base_path={base_path}")

        return self._local_provider

    def get_mcp_provider(
        self,
        server_name: str,
        client: MCPConnection | None = None,
        timeout: int = 30
    ) -> MCPClientFileProvider:
        """
        Get an MCP client file provider instance.

        Args:
            server_name: Name of the MCP server
            client: Optional existing MCPConnection instance
            timeout: Timeout for MCP operations

        Returns:
            MCPClientFileProvider instance
        """
        cache_key = f"{server_name}:{timeout}"

        if cache_key not in self._mcp_providers:
            self._mcp_providers[cache_key] = MCPClientFileProvider(
                server_name=server_name,
                client=client,
                timeout=timeout
            )
            logger.debug(f"Created MCPClientFileProvider for server={server_name}")

        return self._mcp_providers[cache_key]

    def get_provider(
        self,
        prefer_local: bool = True,
        server_name: str | None = None,
        base_path: str | None = None,
        client: MCPConnection | None = None,
        timeout: int = 30
    ) -> FileProvider:
        """
        Get the appropriate file provider based on context.

        Args:
            prefer_local: Whether to prefer local provider over MCP
            server_name: MCP server name (required for MCP provider)
            base_path: Base path for local provider
            client: Optional MCPClient instance
            timeout: Timeout for MCP operations

        Returns:
            Appropriate FileProvider instance

        Raises:
            ValueError: If MCP provider requested but server_name not provided
        """
        if prefer_local:
            return self.get_local_provider(base_path=base_path)
        else:
            if not server_name:
                raise ValueError("server_name is required for MCP provider")
            return self.get_mcp_provider(
                server_name=server_name,
                client=client,
                timeout=timeout
            )

    def clear_cache(self) -> None:
        """Clear cached provider instances."""
        self._local_provider = None
        self._mcp_providers.clear()
        logger.debug("Cleared file provider cache")


# Global provider manager instance
_provider_manager = FileProviderManager()


def get_provider_manager() -> FileProviderManager:
    """Get the global file provider manager."""
    return _provider_manager


def create_local_provider(base_path: str | None = None) -> LocalFileProvider:
    """
    Create a local file provider.

    Args:
        base_path: Optional base path to restrict operations to

    Returns:
        LocalFileProvider instance
    """
    return LocalFileProvider(base_path=base_path)


def create_mcp_provider(
    server_name: str,
    client: MCPConnection | None = None,
    timeout: int = 30
) -> MCPClientFileProvider:
    """
    Create an MCP client file provider.

    Args:
        server_name: Name of the MCP server
        client: Optional existing MCPClient instance
        timeout: Timeout for MCP operations

    Returns:
        MCPClientFileProvider instance
    """
    return MCPClientFileProvider(
        server_name=server_name,
        client=client,
        timeout=timeout
    )


def get_default_provider(
    deployment_mode: str | None = None,
    server_name: str | None = None,
    base_path: str | None = None
) -> FileProvider:
    """
    Get the default file provider based on deployment mode.

    Args:
        deployment_mode: Deployment mode ("local", "http", or None for auto-detect)
        server_name: MCP server name for HTTP mode
        base_path: Base path for local mode

    Returns:
        Appropriate FileProvider instance
    """
    # Auto-detect deployment mode if not specified
    if deployment_mode is None:
        # Check environment variables or server context
        if os.environ.get("VULNICHECK_HTTP_ONLY", "").lower() in ("true", "1", "yes"):
            deployment_mode = "http"
        else:
            deployment_mode = "local"

    manager = get_provider_manager()

    if deployment_mode == "http":
        if not server_name:
            # Try to detect from context or use default
            server_name = os.environ.get("VULNICHECK_MCP_SERVER", "files")

        return manager.get_mcp_provider(server_name=server_name)
    else:
        return manager.get_local_provider(base_path=base_path)


def configure_provider_for_scanner(scanner_type: str = "dependency") -> FileProvider:
    """
    Configure appropriate file provider for different scanner types.

    Args:
        scanner_type: Type of scanner ("dependency", "secrets", "docker", "github")

    Returns:
        Configured FileProvider instance
    """
    # GitHub scanner always uses local provider for cloned repos
    if scanner_type == "github":
        return create_local_provider()

    # Other scanners use default provider
    return get_default_provider()


# Convenience functions for backward compatibility
def get_local_file_provider(base_path: str | None = None) -> LocalFileProvider:
    """Get local file provider (backward compatibility)."""
    return get_provider_manager().get_local_provider(base_path=base_path)


def get_mcp_file_provider(
    server_name: str,
    client: MCPConnection | None = None,
    timeout: int = 30
) -> MCPClientFileProvider:
    """Get MCP file provider (backward compatibility)."""
    return get_provider_manager().get_mcp_provider(
        server_name=server_name,
        client=client,
        timeout=timeout
    )
