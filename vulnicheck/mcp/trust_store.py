"""
Trust store for MCP server configurations.

This module manages trusted server configurations to prevent unauthorized
modifications and ensure only approved servers can be accessed.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class TrustStore:
    """Manages trusted MCP server configurations."""

    def __init__(self, trust_file: str | None = None):
        """
        Initialize the trust store.

        Args:
            trust_file: Path to the trust store file.
                       Defaults to ~/.vulnicheck/trusted_servers.json
        """
        if trust_file is None:
            trust_dir = Path.home() / ".vulnicheck"
            trust_dir.mkdir(exist_ok=True)
            self.trust_file = trust_dir / "trusted_servers.json"
        else:
            self.trust_file = Path(trust_file)

        self._load_trusted_servers()

    def _load_trusted_servers(self) -> None:
        """Load trusted servers from file."""
        self.trusted_servers: dict[str, dict[str, Any]] = {}

        if self.trust_file.exists():
            try:
                with open(self.trust_file) as f:
                    data = json.load(f)
                    self.trusted_servers = data.get("servers", {})
                logger.info(f"Loaded {len(self.trusted_servers)} trusted servers")
            except Exception as e:
                logger.error(f"Failed to load trust store: {e}")
                self.trusted_servers = {}

    def _save_trusted_servers(self) -> None:
        """Save trusted servers to file with secure permissions."""
        try:
            data = {
                "version": "1.0",
                "updated_at": datetime.now().isoformat(),
                "servers": self.trusted_servers
            }

            # Ensure directory exists
            self.trust_file.parent.mkdir(exist_ok=True)

            # Write atomically with secure permissions
            temp_file = self.trust_file.with_suffix(".tmp")

            # Create file with restricted permissions (owner read/write only)
            with open(temp_file, "w", opener=lambda path, flags: os.open(path, flags, 0o600)) as f:
                json.dump(data, f, indent=2)

            # Ensure the temp file has correct permissions before replacing
            os.chmod(temp_file, 0o600)

            # Atomic replace
            temp_file.replace(self.trust_file)

            # Ensure final file has correct permissions
            os.chmod(self.trust_file, 0o600)

            logger.info(f"Saved {len(self.trusted_servers)} trusted servers")
        except Exception as e:
            logger.error(f"Failed to save trust store: {e}")
            # Re-raise the exception instead of silently failing
            raise

    def add_trusted_server(
        self,
        server_name: str,
        config: dict[str, Any],
        description: str | None = None
    ) -> None:
        """
        Add or update a trusted server configuration.

        Args:
            server_name: Name of the server
            config: Server configuration
            description: Optional description of the server
        """
        self.trusted_servers[server_name] = {
            "config": config,
            "description": description,
            "added_at": datetime.now().isoformat(),
            "last_verified": datetime.now().isoformat()
        }
        self._save_trusted_servers()
        logger.info(f"Added trusted server: {server_name}")

    def remove_trusted_server(self, server_name: str) -> bool:
        """
        Remove a trusted server.

        Args:
            server_name: Name of the server to remove

        Returns:
            True if removed, False if not found
        """
        if server_name in self.trusted_servers:
            del self.trusted_servers[server_name]
            self._save_trusted_servers()
            logger.info(f"Removed trusted server: {server_name}")
            return True
        return False

    def is_trusted(self, server_name: str, config: dict[str, Any]) -> bool:
        """
        Check if a server configuration is trusted.

        Args:
            server_name: Name of the server
            config: Configuration to verify

        Returns:
            True if the configuration matches the trusted one
        """
        if server_name not in self.trusted_servers:
            return False

        trusted_config = self.trusted_servers[server_name]["config"]

        # Compare key configuration elements
        # For stdio transport
        if "command" in config and "command" in trusted_config:
            return bool(config["command"] == trusted_config["command"])

        # For HTTP transport
        if "url" in config and "url" in trusted_config:
            return bool(config["url"] == trusted_config["url"])

        # If transport types don't match
        return False

    def get_trusted_config(self, server_name: str) -> dict[str, Any] | None:
        """
        Get the trusted configuration for a server.

        Args:
            server_name: Name of the server

        Returns:
            Trusted configuration or None if not found
        """
        if server_name in self.trusted_servers:
            config = self.trusted_servers[server_name]["config"]
            return dict(config)  # Return a copy
        return None

    def list_trusted_servers(self) -> dict[str, dict[str, Any]]:
        """
        List all trusted servers.

        Returns:
            Dictionary of server names to their metadata
        """
        return {
            name: {
                "description": info.get("description", ""),
                "added_at": info.get("added_at", ""),
                "last_verified": info.get("last_verified", "")
            }
            for name, info in self.trusted_servers.items()
        }

    def verify_and_update(self, server_name: str) -> None:
        """
        Update the last verified timestamp for a server.

        Args:
            server_name: Name of the server
        """
        if server_name in self.trusted_servers:
            self.trusted_servers[server_name]["last_verified"] = datetime.now().isoformat()
            self._save_trusted_servers()


# Global instance
_trust_store: TrustStore | None = None


def get_trust_store() -> TrustStore:
    """Get the global trust store instance."""
    global _trust_store
    if _trust_store is None:
        _trust_store = TrustStore()
    return _trust_store
