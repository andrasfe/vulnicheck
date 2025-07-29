"""
Logging configuration for MCP passthrough interactions.

This module provides configuration for structured logging of all MCP server
interactions, including requests, responses, risk assessments, and security decisions.
"""

import json
import logging
from logging.handlers import TimedRotatingFileHandler
from typing import Any


class MCPInteractionFormatter(logging.Formatter):
    """Custom formatter for MCP interaction logs."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log records with structured data."""
        # Base log entry
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, "event"):
            log_entry["event"] = record.event

        # Common fields for all MCP interactions
        for field in ["agent", "server", "tool", "status"]:
            if hasattr(record, field):
                log_entry[field] = getattr(record, field)

        # Risk-related fields
        for field in ["risk_level", "decision", "category", "pattern"]:
            if hasattr(record, field):
                log_entry[field] = getattr(record, field)

        # Request/Response specific fields
        if hasattr(record, "parameters"):
            # Log full parameters for requests
            log_entry["parameters"] = record.parameters

        # Log response payload if present
        if hasattr(record, "result"):
            log_entry["result"] = record.result

        # Log has_result flag
        if hasattr(record, "has_result"):
            log_entry["has_result"] = record.has_result

        # Log security prompt if present
        if hasattr(record, "security_prompt"):
            log_entry["security_prompt"] = record.security_prompt

        # Error fields
        if hasattr(record, "error"):
            log_entry["error"] = record.error

        # Additional context fields
        for field in ["security_context", "matched_text", "reason", "alternative", "request_id"]:
            if hasattr(record, field):
                log_entry[field] = getattr(record, field)

        return json.dumps(log_entry)


def configure_mcp_logging(
    log_file: str | None = None,
    log_level: str = "INFO",
    enable_console: bool = True,
) -> None:
    """
    Configure logging for MCP interactions.

    Args:
        log_file: Path to log file for MCP interactions (optional)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        enable_console: Whether to also log to console
    """
    # Get the MCP interactions logger
    logger = logging.getLogger("vulnicheck.mcp_interactions")
    logger.setLevel(getattr(logging, log_level.upper()))
    logger.propagate = False  # Don't propagate to root logger

    # Clear existing handlers
    logger.handlers.clear()

    # Create formatter
    formatter = MCPInteractionFormatter()

    # Add file handler if specified
    if log_file:
        # Use TimedRotatingFileHandler for hourly rotation
        file_handler = TimedRotatingFileHandler(
            log_file,
            when='H',  # Rotate every hour
            interval=1,  # Every 1 hour
            backupCount=168,  # Keep 168 hours (7 days) of logs
            encoding='utf-8',
            utc=False
        )
        # Add timestamp to rotated file names
        file_handler.suffix = "%Y%m%d_%H%M%S.log"
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Add console handler if enabled
    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)


def get_mcp_logger() -> logging.Logger:
    """Get the configured MCP interactions logger."""
    return logging.getLogger("vulnicheck.mcp_interactions")


# Example usage and log analysis functions
def analyze_mcp_logs(log_file: str) -> dict[str, Any]:
    """
    Analyze MCP interaction logs for patterns and statistics.

    Args:
        log_file: Path to the log file

    Returns:
        Dictionary with analysis results
    """
    stats: dict[str, Any] = {
        "total_requests": 0,
        "blocked_requests": 0,
        "approved_requests": 0,
        "denied_requests": 0,
        "auto_approved_requests": 0,
        "errors": 0,
        "risk_levels": {},
        "servers": {},
        "tools": {},
        "decisions": {},
    }

    try:
        with open(log_file) as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())

                    if entry.get("event") == "mcp_request":
                        stats["total_requests"] += 1

                        # Track servers and tools
                        server = entry.get("server", "unknown")
                        tool = entry.get("tool", "unknown")
                        stats["servers"][server] = stats["servers"].get(server, 0) + 1
                        stats["tools"][f"{server}.{tool}"] = stats["tools"].get(f"{server}.{tool}", 0) + 1

                    elif entry.get("event") == "mcp_security_decision":
                        decision = entry.get("decision", "unknown")
                        stats["decisions"][decision] = stats["decisions"].get(decision, 0) + 1

                        if decision == "blocked":
                            stats["blocked_requests"] += 1
                        elif decision == "approved":
                            stats["approved_requests"] += 1
                        elif decision == "denied":
                            stats["denied_requests"] += 1
                        elif decision == "auto_approved":
                            stats["auto_approved_requests"] += 1

                        # Track risk levels
                        risk_level = entry.get("risk_level", "unknown")
                        stats["risk_levels"][risk_level] = stats["risk_levels"].get(risk_level, 0) + 1

                    elif entry.get("event") == "mcp_response" and entry.get("status") == "error":
                        stats["errors"] += 1

                except json.JSONDecodeError:
                    continue

    except FileNotFoundError:
        pass

    return stats


def print_mcp_summary(stats: dict[str, Any]) -> None:
    """Print a summary of MCP interaction statistics."""
    print("\n=== MCP Interaction Summary ===")
    print(f"Total Requests: {stats['total_requests']}")
    print(f"Blocked: {stats['blocked_requests']}")
    print(f"Approved: {stats['approved_requests']}")
    print(f"Auto-Approved: {stats['auto_approved_requests']}")
    print(f"Denied: {stats['denied_requests']}")
    print(f"Errors: {stats['errors']}")

    print("\n=== Risk Levels ===")
    for level, count in sorted(stats["risk_levels"].items()):
        print(f"{level}: {count}")

    print("\n=== Top Servers ===")
    for server, count in sorted(stats["servers"].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{server}: {count}")

    print("\n=== Top Tools ===")
    for tool, count in sorted(stats["tools"].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{tool}: {count}")
