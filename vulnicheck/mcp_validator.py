"""MCP security validation using mcp-scan."""

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from mcp_scan import MCPScanner  # type: ignore[import-untyped]

logger = logging.getLogger("vulnicheck.mcp_validator")


class MCPValidator:
    """Wrapper for mcp-scan validation functionality."""

    def __init__(self, local_only: bool = True):
        """Initialize MCP validator.

        Args:
            local_only: Whether to use only local validation (no external API calls)
        """
        self.local_only = local_only
        self.base_url = "https://mcp.invariantlabs.ai/"

    async def validate_config(
        self, config_json: str | None = None, mode: str = "scan"
    ) -> dict[str, Any]:
        """Validate MCP configuration for security issues.

        Args:
            config_json: JSON string containing MCP configuration
            mode: Either "scan" for full analysis or "inspect" for quick check

        Returns:
            Dictionary containing validation results
        """
        # Handle JSON input or auto-detect config paths
        temp_file = None
        config_paths = []

        if config_json:
            # Validate JSON
            try:
                json.loads(config_json)
            except json.JSONDecodeError as e:
                return {
                    "error": f"Invalid JSON configuration: {str(e)}",
                    "server_count": 0,
                    "issue_count": 0,
                    "issues": []
                }

            # Create temporary file with JSON content
            try:
                temp_file = tempfile.NamedTemporaryFile(  # noqa: SIM115
                    mode='w',
                    suffix='.json',
                    delete=False
                )
                temp_file.write(config_json)
                temp_file.close()
                config_paths = [temp_file.name]
            except Exception as e:
                return {
                    "error": f"Failed to create temporary config file: {str(e)}",
                    "server_count": 0,
                    "issue_count": 0,
                    "issues": []
                }
        else:
            # Auto-detect config paths if no JSON provided
            config_paths = self._detect_config_paths()
            if not config_paths:
                return {
                    "error": "No MCP configuration provided or found",
                    "server_count": 0,
                    "issue_count": 0,
                    "issues": []
                }

        try:
            scanner = MCPScanner(
                files=config_paths,
                base_url=self.base_url,
                local_only=self.local_only,
                server_timeout=10,
                checks_per_server=1
            )

            async with scanner:
                if mode == "scan":
                    results = await scanner.scan()
                elif mode == "inspect":
                    results = await scanner.inspect()
                else:
                    raise ValueError(f"Invalid mode: {mode}")

            return self._format_results(results)

        except Exception as e:
            logger.error(f"Error during MCP validation: {e}")
            return {
                "error": str(e),
                "server_count": 0,
                "issue_count": 0,
                "issues": []
            }
        finally:
            # Clean up temporary file if created
            if temp_file and os.path.exists(temp_file.name):
                with contextlib.suppress(Exception):
                    os.unlink(temp_file.name)

    def _detect_config_paths(self) -> list[str]:
        """Auto-detect MCP configuration paths.

        Returns:
            List of detected configuration file paths
        """
        config_paths = []

        # Common MCP configuration locations
        home = Path.home()

        # Claude Desktop
        claude_configs = [
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            home / ".config" / "claude" / "claude_desktop_config.json",
            home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
        ]

        # Cursor
        cursor_configs = [
            home / ".cursor" / "mcp" / "config.json",
            home / "Library" / "Application Support" / "Cursor" / "mcp" / "config.json",
        ]

        # Windsurf
        windsurf_configs = [
            home / ".windsurf" / "mcp" / "config.json",
            home / "Library" / "Application Support" / "Windsurf" / "mcp" / "config.json",
        ]

        # Check all possible locations
        for config_path in claude_configs + cursor_configs + windsurf_configs:
            if config_path.exists():
                config_paths.append(str(config_path))
                logger.info(f"Found MCP config: {config_path}")

        # Also check environment variable
        if custom_path := os.environ.get("MCP_CONFIG_PATH"):
            custom_path_obj = Path(custom_path)
            if custom_path_obj.exists():
                config_paths.append(str(custom_path_obj))

        return config_paths

    def _format_results(self, raw_results: Any) -> dict[str, Any]:
        """Format scan results for vulnicheck tool output.

        Args:
            raw_results: Raw results from mcp-scan

        Returns:
            Formatted results dictionary
        """
        # Handle different result formats
        if isinstance(raw_results, str):
            try:
                results_data = json.loads(raw_results)
            except json.JSONDecodeError:
                # If not JSON, treat as error message
                return {
                    "error": raw_results,
                    "server_count": 0,
                    "issue_count": 0,
                    "issues": []
                }
        else:
            results_data = raw_results

        # Extract and format issues
        issues = []
        server_count = 0

        if isinstance(results_data, dict):
            # Count servers
            if "servers" in results_data:
                server_count = len(results_data.get("servers", []))

            # Extract issues from scan results
            for server_name, server_data in results_data.items():
                if isinstance(server_data, dict):
                    server_count += 1

                    # Check for various issue indicators
                    if server_data.get("malicious"):
                        issues.append({
                            "severity": "CRITICAL",
                            "title": "Malicious server detected",
                            "server": server_name,
                            "description": "This server has been flagged as malicious",
                            "recommendation": "Remove this server immediately from your configuration"
                        })

                    if server_data.get("prompt_injection_risk"):
                        issues.append({
                            "severity": "HIGH",
                            "title": "Prompt injection risk",
                            "server": server_name,
                            "description": "Tool descriptions may contain prompt injection attempts",
                            "recommendation": "Review and sanitize tool descriptions"
                        })

                    if server_data.get("suspicious_tools"):
                        for tool in server_data["suspicious_tools"]:
                            issues.append({
                                "severity": "MEDIUM",
                                "title": f"Suspicious tool: {tool.get('name', 'unknown')}",
                                "server": server_name,
                                "description": tool.get("reason", "Tool flagged as suspicious"),
                                "recommendation": "Review tool permissions and behavior"
                            })

        return {
            "server_count": server_count,
            "issue_count": len(issues),
            "issues": issues
        }
