"""
MCP Configuration Cache Manager.

This module handles discovery, parsing, and caching of MCP server configurations
from various assistant/IDE configuration files.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..core.agent_detector import AgentDetector

logger = logging.getLogger(__name__)


class MCPServerConfig(BaseModel):
    """Configuration for a single MCP server."""

    command: str | None = Field(default=None, description="Command to execute")
    args: list[str] = Field(default_factory=list, description="Command arguments")
    env: dict[str, str] = Field(
        default_factory=dict, description="Environment variables"
    )
    cwd: str | None = Field(default=None, description="Working directory")
    transport: str = Field(default="stdio", description="Transport type (stdio, http)")
    type: str | None = Field(default=None, description="Alias for transport (used in .claude.json)")
    url: str | None = Field(default=None, description="URL for HTTP transport")

    def model_post_init(self, __context: Any) -> None:
        """Handle type -> transport mapping."""
        if self.type and not self.transport:
            self.transport = self.type
        elif self.type and self.transport == "stdio":
            # If type is specified, it takes precedence
            self.transport = self.type


class MCPConfigCache:
    """Manages MCP configuration discovery and caching."""

    def __init__(self, cache_ttl: int = 300):
        """
        Initialize the config cache.

        Args:
            cache_ttl: Cache time-to-live in seconds (default: 5 minutes)
        """
        self.cache_ttl = cache_ttl
        self._cache: dict[str, dict[str, MCPServerConfig]] = {}
        self._config_paths: dict[str, list[Path]] = {}
        self._last_checked: dict[str, datetime] = {}
        self._last_modified: dict[str, dict[Path, float]] = {}
        self._agent_detector = AgentDetector()

        # Use config patterns from agent detector
        self.agent_config_patterns = {}
        for agent_name, agent_info in self._agent_detector.AGENT_PATTERNS.items():
            patterns = []
            for pattern in agent_info["config_patterns"]:
                # Convert string patterns to Path objects
                patterns.append(Path(pattern.replace("~", str(Path.home()))))
            self.agent_config_patterns[agent_name] = patterns

    def _find_config_files(self, agent_name: str) -> list[Path]:
        """Find configuration files for a specific agent."""
        config_files = []
        patterns = self.agent_config_patterns.get(agent_name.lower(), [])

        for pattern in patterns:
            if "*" in str(pattern):
                # Handle glob patterns
                base_path = pattern.parent
                while "*" in str(base_path):
                    base_path = base_path.parent

                if base_path.exists():
                    glob_pattern = str(pattern).replace(str(base_path) + "/", "")
                    for match in base_path.rglob(glob_pattern):
                        if match.exists():
                            config_files.append(match)
            elif pattern.exists():
                config_files.append(pattern)

        # Special handling for Cline - recursive search
        if agent_name.lower() == "cline":
            config_base = Path.home() / ".config"
            if config_base.exists():
                for cline_config in config_base.rglob("cline_mcp_settings.json"):
                    config_files.append(cline_config)

        return config_files

    def _parse_config_file(self, config_path: Path) -> dict[str, MCPServerConfig]:
        """Parse an MCP configuration file."""
        try:
            content = config_path.read_text()
            data = json.loads(content)

            # Special handling for .claude.json format
            if config_path.name == ".claude.json":
                servers = {}

                # Check if this is a project-based config (Claude Code)
                if "projects" in data and isinstance(data["projects"], dict):
                    # Claude Code format with projects
                    for _, project_config in data["projects"].items():
                        if (
                            isinstance(project_config, dict)
                            and "mcpServers" in project_config
                        ):
                            for server_name, server_config in project_config[
                                "mcpServers"
                            ].items():
                                if server_name not in servers:  # First one wins
                                    servers[server_name] = MCPServerConfig(
                                        **server_config
                                    )
                else:
                    # Legacy format - check all top-level keys
                    for _, project_config in data.items():
                        if (
                            isinstance(project_config, dict)
                            and "mcpServers" in project_config
                        ):
                            for server_name, server_config in project_config[
                                "mcpServers"
                            ].items():
                                if server_name not in servers:  # First one wins
                                    servers[server_name] = MCPServerConfig(
                                        **server_config
                                    )
                return servers

            # Standard format - look for mcpServers key
            if "mcpServers" in data:
                return {
                    name: MCPServerConfig(**config)
                    for name, config in data["mcpServers"].items()
                }

            # Some configs might have servers at root level
            if all(isinstance(v, dict) and "command" in v for v in data.values()):
                return {
                    name: MCPServerConfig(**config) for name, config in data.items()
                }

            logger.warning(f"No MCP servers found in {config_path}")
            return {}

        except Exception as e:
            logger.error(f"Error parsing config file {config_path}: {e}")
            return {}

    def _is_cache_valid(self, agent_name: str) -> bool:
        """Check if the cache for an agent is still valid."""
        if agent_name not in self._cache:
            return False

        # Check TTL
        last_checked = self._last_checked.get(agent_name)
        if not last_checked:
            return False

        if datetime.now() - last_checked > timedelta(seconds=self.cache_ttl):
            return False

        # Check if any config files have been modified
        for path, mtime in self._last_modified.get(agent_name, {}).items():
            if path.exists():
                current_mtime = path.stat().st_mtime
                if current_mtime > mtime:
                    logger.info(f"Config file {path} has been modified")
                    return False

        return True

    async def get_server_configs(self, agent_name: str) -> dict[str, MCPServerConfig]:
        """
        Get MCP server configurations for a specific agent.

        Args:
            agent_name: Name of the agent (claude, cursor, vscode, etc.)

        Returns:
            Dictionary mapping server names to their configurations
        """
        # Check cache validity
        if self._is_cache_valid(agent_name):
            logger.debug(f"Using cached config for {agent_name}")
            return self._cache[agent_name]

        logger.info(f"Loading MCP configurations for {agent_name}")

        # Find config files
        config_files = self._find_config_files(agent_name)
        if not config_files:
            logger.warning(f"No configuration files found for {agent_name}")
            return {}

        # Parse and merge configurations
        all_servers = {}
        modified_times = {}

        for config_file in config_files:
            logger.debug(f"Parsing {config_file}")
            servers = self._parse_config_file(config_file)

            # Track modification time
            modified_times[config_file] = config_file.stat().st_mtime

            # Merge servers (first one wins for duplicates)
            for name, config in servers.items():
                if name not in all_servers:
                    all_servers[name] = config
                    logger.debug(f"Found server '{name}' in {config_file}")

        # For Claude, also check CLI servers
        if agent_name.lower() == "claude":
            try:
                import subprocess

                result = subprocess.run(
                    ["claude", "mcp", "list"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0:
                    # Parse CLI output
                    for line in result.stdout.strip().split("\n"):
                        if ": " in line:
                            name, command = line.split(": ", 1)
                            name = name.strip()
                            if name not in all_servers:
                                # Parse command and args
                                parts = command.strip().split()
                                all_servers[name] = MCPServerConfig(
                                    command=parts[0],
                                    args=parts[1:] if len(parts) > 1 else [],
                                )
                                logger.debug(f"Found CLI server '{name}'")
            except Exception as e:
                logger.warning(f"Could not get Claude CLI servers: {e}")

        # Update cache
        self._cache[agent_name] = all_servers
        self._config_paths[agent_name] = config_files
        self._last_checked[agent_name] = datetime.now()
        self._last_modified[agent_name] = modified_times

        logger.info(f"Loaded {len(all_servers)} MCP servers for {agent_name}")
        return all_servers

    async def get_server_config(
        self, agent_name: str, server_name: str
    ) -> MCPServerConfig | None:
        """
        Get configuration for a specific MCP server.

        Args:
            agent_name: Name of the agent
            server_name: Name of the MCP server

        Returns:
            Server configuration or None if not found
        """
        configs = await self.get_server_configs(agent_name)
        return configs.get(server_name)

    def clear_cache(self, agent_name: str | None = None) -> None:
        """Clear the cache for a specific agent or all agents."""
        if agent_name:
            self._cache.pop(agent_name, None)
            self._config_paths.pop(agent_name, None)
            self._last_checked.pop(agent_name, None)
            self._last_modified.pop(agent_name, None)
            logger.info(f"Cleared cache for {agent_name}")
        else:
            self._cache.clear()
            self._config_paths.clear()
            self._last_checked.clear()
            self._last_modified.clear()
            logger.info("Cleared all caches")

    def get_available_servers(self, agent_name: str) -> list[str]:
        """Get list of available server names from cache (sync method for quick access)."""
        if agent_name in self._cache:
            return list(self._cache[agent_name].keys())
        return []
