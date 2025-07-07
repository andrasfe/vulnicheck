"""
Shared agent detection module with caching.

This module provides a centralized way to detect which agent/assistant is calling
the MCP server and caches the result for the session.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Cache file location
CACHE_DIR = Path.home() / ".cache" / "vulnicheck"
AGENT_CACHE_FILE = CACHE_DIR / "detected_agent.json"
CACHE_TTL_HOURS = 24  # Cache for 24 hours


class AgentDetector:
    """Detects and caches the calling agent/assistant type."""

    # Known agent types and their config patterns
    AGENT_PATTERNS = {
        "claude": {
            "display_name": "Claude",
            "config_patterns": [
                "~/.claude.json",  # Claude Code primary config
                "~/.claude/claude_desktop_config.json",
                "~/.claude/settings.local.json",
                "~/Library/Application Support/Claude/claude_desktop_config.json",
            ],
        },
        "cline": {
            "display_name": "Cline",
            "config_patterns": [
                "~/.cursor/mcp.json",
                "~/.vscode/mcp.json",
            ],
        },
        "cursor": {
            "display_name": "Cursor",
            "config_patterns": [
                "~/.cursor/config.json",
                "~/Library/Application Support/Cursor/User/globalStorage/saoud.mcp-manager/config.json",
            ],
        },
        "vscode": {
            "display_name": "VS Code",
            "config_patterns": [
                "~/.vscode/extensions/saoud.mcp-manager-*/config.json",
                "~/Library/Application Support/Code/User/globalStorage/saoud.mcp-manager/config.json",
            ],
        },
        "copilot": {
            "display_name": "GitHub Copilot",
            "config_patterns": [
                "~/.vscode/extensions/github.copilot-*/config.json",
                "~/Library/Application Support/Code/User/globalStorage/github.copilot/config.json",
            ],
        },
        "windsurf": {
            "display_name": "Windsurf",
            "config_patterns": [
                "~/.windsurf/config.json",
                "~/Library/Application Support/Windsurf/config.json",
            ],
        },
        "continue": {
            "display_name": "Continue",
            "config_patterns": [
                "~/.continue/config.json",
                "~/.continue/.continuerc.json",
            ],
        },
    }

    def __init__(self) -> None:
        """Initialize the agent detector."""
        self._cached_agent: str | None = None
        self._cache_loaded = False

    def _ensure_cache_dir(self) -> None:
        """Ensure the cache directory exists."""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _load_cache(self) -> dict[str, Any] | None:
        """Load cached agent detection result."""
        if not AGENT_CACHE_FILE.exists():
            return None

        try:
            with open(AGENT_CACHE_FILE) as f:
                cache_data = json.load(f)

            # Check if cache is still valid
            cached_time = datetime.fromisoformat(cache_data.get("timestamp", ""))
            if datetime.now() - cached_time > timedelta(hours=CACHE_TTL_HOURS):
                logger.debug("Agent cache expired")
                return None

            return cache_data  # type: ignore[no-any-return]
        except Exception as e:
            logger.debug(f"Failed to load agent cache: {e}")
            return None

    def _save_cache(self, agent_name: str, detection_method: str) -> None:
        """Save agent detection result to cache."""
        try:
            self._ensure_cache_dir()
            cache_data = {
                "agent": agent_name,
                "detection_method": detection_method,
                "timestamp": datetime.now().isoformat(),
            }
            with open(AGENT_CACHE_FILE, "w") as f:
                json.dump(cache_data, f, indent=2)
            logger.debug(f"Cached agent detection: {agent_name}")
        except Exception as e:
            logger.warning(f"Failed to save agent cache: {e}")

    def _detect_from_environment(self) -> str | None:
        """Detect agent from environment variables."""
        # Check for specific environment markers
        env_markers = {
            "CLAUDECODE": "claude",  # Claude Code sets CLAUDECODE=1
            "CLAUDE_CODE": "claude",
            "CURSOR_IDE": "cursor",
            "VSCODE_PID": "vscode",
            "GITHUB_COPILOT": "copilot",
            "WINDSURF_IDE": "windsurf",
            "CONTINUE_DEV": "continue",
        }

        for env_var, agent_name in env_markers.items():
            if os.environ.get(env_var):
                logger.info(
                    f"Detected {agent_name} from environment variable {env_var}"
                )
                return agent_name

        return None

    def _detect_from_config_files(self) -> str | None:
        """Detect agent from presence of config files."""
        for agent_name, agent_info in self.AGENT_PATTERNS.items():
            for pattern in agent_info["config_patterns"]:
                # Expand user home directory
                config_path = Path(pattern.replace("~", str(Path.home())))

                # Handle glob patterns
                if "*" in str(config_path):
                    parent = config_path.parent
                    if parent.exists():
                        glob_pattern = config_path.name
                        matches = list(parent.glob(glob_pattern))
                        if matches:
                            logger.info(
                                f"Detected {agent_name} from config file: {matches[0]}"
                            )
                            return agent_name
                elif config_path.exists():
                    logger.info(
                        f"Detected {agent_name} from config file: {config_path}"
                    )
                    return agent_name

        return None

    def detect_agent(self, agent_name: str | None = None) -> str:
        """
        Detect the calling agent/assistant.

        Args:
            agent_name: Optional explicit agent name. If provided, this overrides detection.

        Returns:
            The detected or provided agent name (lowercase).
        """
        # If explicitly provided, use that and cache it
        if agent_name:
            normalized = agent_name.lower()
            if normalized in self.AGENT_PATTERNS:
                self._save_cache(normalized, "explicit")
                return normalized
            else:
                logger.warning(f"Unknown agent name: {agent_name}, using 'custom'")
                return "custom"

        # Check in-memory cache
        if self._cached_agent:
            return self._cached_agent

        # Try to load from file cache
        if not self._cache_loaded:
            cache_data = self._load_cache()
            if cache_data:
                self._cached_agent = cache_data["agent"]
                self._cache_loaded = True
                logger.info(
                    f"Using cached agent detection: {self._cached_agent} "
                    f"(method: {cache_data['detection_method']})"
                )
                return self._cached_agent

        # Try environment detection
        detected = self._detect_from_environment()
        if detected:
            self._cached_agent = detected
            self._save_cache(detected, "environment")
            return detected

        # Try config file detection
        detected = self._detect_from_config_files()
        if detected:
            self._cached_agent = detected
            self._save_cache(detected, "config_file")
            return detected

        # Default to claude
        logger.warning("Could not detect agent type, defaulting to 'claude'")
        self._cached_agent = "claude"
        self._save_cache("claude", "default")
        return "claude"

    def get_display_name(self, agent_name: str) -> str:
        """Get the display name for an agent."""
        agent_info = self.AGENT_PATTERNS.get(agent_name, {})
        display_name = agent_info.get("display_name", agent_name.title())
        return str(display_name)  # Ensure we return a string

    def clear_cache(self) -> None:
        """Clear the cached agent detection."""
        self._cached_agent = None
        self._cache_loaded = False
        if AGENT_CACHE_FILE.exists():
            try:
                AGENT_CACHE_FILE.unlink()
                logger.info("Cleared agent detection cache")
            except Exception as e:
                logger.warning(f"Failed to clear agent cache: {e}")


# Global detector instance
_detector = AgentDetector()


def detect_agent(agent_name: str | None = None) -> str:
    """
    Detect the calling agent/assistant.

    Args:
        agent_name: Optional explicit agent name. If provided, this overrides detection.

    Returns:
        The detected or provided agent name (lowercase).
    """
    return _detector.detect_agent(agent_name)


def get_agent_display_name(agent_name: str) -> str:
    """Get the display name for an agent."""
    return _detector.get_display_name(agent_name)


def clear_agent_cache() -> None:
    """Clear the cached agent detection."""
    _detector.clear_cache()
