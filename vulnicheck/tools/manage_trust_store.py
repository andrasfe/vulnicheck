"""
Tool implementation for managing the MCP server trust store.
"""

import json
from typing import Any

from ..mcp.trust_store import get_trust_store


async def manage_trust_store(
    action: str = "list",
    server_name: str | None = None,
    config: dict[str, Any] | None = None,
    description: str | None = None,
) -> str:
    """
    Manage the MCP server trust store.

    Args:
        action: The action to perform - 'list', 'add', 'remove', or 'verify'
        server_name: Name of the server (required for add/remove/verify)
        config: Server configuration (required for add)
        description: Optional description for the server (for add)

    Returns:
        A formatted report of the action performed
    """
    trust_store = get_trust_store()

    if action == "list":
        servers = trust_store.list_trusted_servers()
        if not servers:
            return "No trusted servers configured."

        lines = ["# Trusted MCP Servers\n"]
        for name, info in servers.items():
            lines.append(f"## {name}")
            if info.get("description"):
                lines.append(f"Description: {info['description']}")
            lines.append(f"Added: {info.get('added_at', 'Unknown')}")
            lines.append(f"Last verified: {info.get('last_verified', 'Never')}")
            lines.append("")

        return "\n".join(lines)

    elif action == "add":
        if not server_name:
            return "ERROR: server_name is required for 'add' action"
        if not config:
            return "ERROR: config is required for 'add' action"

        try:
            trust_store.add_trusted_server(server_name, config, description)
            return f"✅ Successfully added '{server_name}' to trust store"
        except Exception as e:
            return f"❌ Failed to add server: {e}"

    elif action == "remove":
        if not server_name:
            return "ERROR: server_name is required for 'remove' action"

        if trust_store.remove_trusted_server(server_name):
            return f"✅ Successfully removed '{server_name}' from trust store"
        else:
            return f"⚠️ Server '{server_name}' not found in trust store"

    elif action == "verify":
        if not server_name:
            return "ERROR: server_name is required for 'verify' action"

        trusted_config = trust_store.get_trusted_config(server_name)
        if trusted_config:
            trust_store.verify_and_update(server_name)
            return f"✅ Server '{server_name}' is trusted\n\nConfiguration:\n```json\n{json.dumps(trusted_config, indent=2)}\n```"
        else:
            return f"❌ Server '{server_name}' is NOT in the trust store"

    else:
        return f"ERROR: Unknown action '{action}'. Valid actions are: list, add, remove, verify"
