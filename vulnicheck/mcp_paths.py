"""
Central configuration for MCP (Model Context Protocol) paths.

This module consolidates all MCP-related paths to avoid duplication
across the codebase.
"""

from pathlib import Path

# MCP configuration paths by agent
MCP_CONFIG_PATHS: dict[str, list[Path]] = {
    "claude": [
        Path.home() / ".claude.json",  # Claude Code primary config
        Path.home() / ".claude" / "claude_desktop_config.json",
        Path.home() / ".claude" / "settings.local.json",  # Claude Code
        Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",  # macOS
    ],
    "cline": [
        Path.home() / ".cursor" / "mcp.json",  # Cline uses Cursor/VS Code directories
        Path.home() / ".vscode" / "mcp.json",
    ],
    "cursor": [
        Path.home() / ".cursor" / "mcp.json",
        Path.home() / ".cursor" / "config.json",
        Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "settings.json",  # macOS
        Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "saoud.mcp-manager" / "config.json",  # macOS
    ],
    "vscode": [
        Path.home() / ".vscode" / "mcp.json",
        Path.home() / ".vscode" / "settings.json",
        Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json",  # macOS
        Path.home() / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "saoud.mcp-manager" / "config.json",  # macOS
    ],
    "windsurf": [
        Path.home() / ".windsurf" / "mcp.json",
        Path.home() / ".windsurf" / "config.json",
        Path.home() / "Library" / "Application Support" / "Windsurf" / "config.json",  # macOS
        Path.home() / "Library" / "Application Support" / "Windsurf" / "User" / "settings.json",  # macOS
    ],
    "continue": [
        Path.home() / ".continue" / "config.json",
        Path.home() / ".continue" / ".continuerc.json",
    ],
    "copilot": [
        Path.home() / ".vscode" / "extensions" / "github.copilot-*" / "config.json",
        Path.home() / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "github.copilot" / "config.json",  # macOS
    ],
}

# All MCP paths for quick checks
ALL_MCP_PATHS: list[Path] = []
for paths in MCP_CONFIG_PATHS.values():
    ALL_MCP_PATHS.extend(paths)

# Common MCP paths for basic detection
COMMON_MCP_PATHS: list[Path] = [
    Path.home() / ".claude" / "claude_desktop_config.json",
    Path.home() / ".cursor" / "mcp.json",
    Path.home() / ".vscode" / "mcp.json",
]


def get_mcp_paths_for_agent(agent_name: str) -> list[Path]:
    """
    Get MCP configuration paths for a specific agent.

    Args:
        agent_name: Name of the agent (claude, cline, cursor, vscode, etc.)

    Returns:
        List of paths where MCP config might be found for this agent
    """
    return MCP_CONFIG_PATHS.get(agent_name.lower(), [])


def get_all_mcp_paths() -> list[Path]:
    """Get all known MCP configuration paths."""
    return ALL_MCP_PATHS.copy()


def get_common_mcp_paths() -> list[Path]:
    """Get the most common MCP configuration paths for quick checks."""
    return COMMON_MCP_PATHS.copy()


def check_mcp_exists_anywhere() -> bool:
    """Quick check if any MCP configuration exists."""
    return any(path.exists() for path in COMMON_MCP_PATHS)


def find_existing_mcp_configs() -> dict[str, list[Path]]:
    """
    Find all existing MCP configurations on the system.

    Returns:
        Dictionary mapping agent names to lists of existing config paths
    """
    existing_configs: dict[str, list[Path]] = {}

    for agent, paths in MCP_CONFIG_PATHS.items():
        existing = [p for p in paths if p.exists()]
        if existing:
            existing_configs[agent] = existing

    return existing_configs
