"""Conversation storage for MCP passthrough interactions.

This module manages the storage and retrieval of conversations between
clients (e.g., Claude) and MCP servers that VulniCheck intermediates with.
Conversations are stored in a local .vulnicheck directory within the
current working directory.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ConversationMessage(BaseModel):
    """A single message in a conversation."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    direction: str  # "request" or "response"
    client: str  # e.g., "claude", "cursor", etc.
    server: str  # e.g., "github", "zen", etc.
    tool: str  # The tool being called
    parameters: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    risk_assessment: dict[str, Any] | None = None


class Conversation(BaseModel):
    """A conversation session between a client and MCP server."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    client: str
    server: str
    messages: list[ConversationMessage] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConversationStorage:
    """Manages storage and retrieval of MCP conversations."""

    def __init__(self, base_path: Path | None = None):
        """Initialize conversation storage.

        Args:
            base_path: Base directory for storage. If None, uses current directory.
        """
        if base_path is None:
            base_path = Path.cwd()

        self.storage_dir = base_path / ".vulnicheck" / "conversations"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Index file to track all conversations
        self.index_file = self.storage_dir / "index.json"
        self._ensure_index()

    def _ensure_index(self) -> None:
        """Ensure the index file exists."""
        if not self.index_file.exists():
            self._save_index([])

    def _load_index(self) -> list[dict[str, Any]]:
        """Load the conversation index."""
        try:
            with open(self.index_file) as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save_index(self, index: list[dict[str, Any]]) -> None:
        """Save the conversation index."""
        with open(self.index_file, "w") as f:
            json.dump(index, f, indent=2, default=str)

    def start_conversation(self, client: str, server: str, metadata: dict[str, Any] | None = None) -> Conversation:
        """Start a new conversation session.

        Args:
            client: The client identifier (e.g., "claude")
            server: The MCP server name
            metadata: Optional metadata for the conversation

        Returns:
            A new Conversation instance
        """
        conversation = Conversation(
            client=client,
            server=server,
            metadata=metadata or {}
        )

        # Update index
        index = self._load_index()
        index.append({
            "id": conversation.id,
            "client": client,
            "server": server,
            "started_at": conversation.started_at.isoformat(),
            "updated_at": conversation.updated_at.isoformat()
        })
        self._save_index(index)

        # Save initial conversation
        self._save_conversation(conversation)

        return conversation

    def add_request(
        self,
        conversation_id: str,
        client: str,
        server: str,
        tool: str,
        parameters: dict[str, Any] | None = None
    ) -> ConversationMessage:
        """Add a request message to a conversation.

        Args:
            conversation_id: The conversation ID
            client: The client identifier
            server: The MCP server name
            tool: The tool being called
            parameters: The request parameters

        Returns:
            The created message
        """
        conversation = self.get_conversation(conversation_id)
        if not conversation:
            # Auto-create conversation if it doesn't exist
            conversation = self.start_conversation(client, server)
            conversation.id = conversation_id

        message = ConversationMessage(
            direction="request",
            client=client,
            server=server,
            tool=tool,
            parameters=parameters
        )

        conversation.messages.append(message)
        conversation.updated_at = datetime.now()

        self._save_conversation(conversation)
        self._update_index_timestamp(conversation_id)

        return message

    def add_response(
        self,
        conversation_id: str,
        client: str,
        server: str,
        tool: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        risk_assessment: dict[str, Any] | None = None
    ) -> ConversationMessage:
        """Add a response message to a conversation.

        Args:
            conversation_id: The conversation ID
            client: The client identifier
            server: The MCP server name
            tool: The tool that was called
            result: The response result
            error: Any error message
            risk_assessment: Risk assessment data

        Returns:
            The created message
        """
        conversation = self.get_conversation(conversation_id)
        if not conversation:
            raise ValueError(f"Conversation {conversation_id} not found")

        message = ConversationMessage(
            direction="response",
            client=client,
            server=server,
            tool=tool,
            result=result,
            error=error,
            risk_assessment=risk_assessment
        )

        conversation.messages.append(message)
        conversation.updated_at = datetime.now()

        self._save_conversation(conversation)
        self._update_index_timestamp(conversation_id)

        return message

    def get_conversation(self, conversation_id: str) -> Conversation | None:
        """Get a conversation by ID.

        Args:
            conversation_id: The conversation ID

        Returns:
            The conversation or None if not found
        """
        conversation_file = self.storage_dir / f"{conversation_id}.json"
        if not conversation_file.exists():
            return None

        try:
            with open(conversation_file) as f:
                data = json.load(f)
                return Conversation(**data)
        except (json.JSONDecodeError, ValueError):
            return None

    def list_conversations(
        self,
        client: str | None = None,
        server: str | None = None,
        limit: int = 100,
        offset: int = 0
    ) -> list[dict[str, Any]]:
        """List conversations with optional filtering.

        Args:
            client: Filter by client name
            server: Filter by server name
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of conversation summaries
        """
        index = self._load_index()

        # Filter
        if client:
            index = [c for c in index if c.get("client") == client]
        if server:
            index = [c for c in index if c.get("server") == server]

        # Sort by updated_at descending
        index.sort(key=lambda x: x.get("updated_at", ""), reverse=True)

        # Paginate
        return index[offset:offset + limit]

    def search_conversations(
        self,
        query: str,
        limit: int = 100
    ) -> list[dict[str, Any]]:
        """Search conversations by tool name or parameters.

        Args:
            query: Search query
            limit: Maximum number of results

        Returns:
            List of matching conversations with relevant messages
        """
        results = []
        index = self._load_index()

        for conv_summary in index:
            conversation = self.get_conversation(conv_summary["id"])
            if not conversation:
                continue

            # Search in messages
            matching_messages = []
            for message in conversation.messages:
                # Search in tool name
                if query.lower() in message.tool.lower():
                    matching_messages.append(message)
                    continue

                # Search in parameters
                if message.parameters:
                    params_str = json.dumps(message.parameters, default=str).lower()
                    if query.lower() in params_str:
                        matching_messages.append(message)
                        continue

                # Search in results
                if message.result:
                    result_str = json.dumps(message.result, default=str).lower()
                    if query.lower() in result_str:
                        matching_messages.append(message)

            if matching_messages:
                results.append({
                    "conversation": conv_summary,
                    "matching_messages": [msg.model_dump() for msg in matching_messages[:5]],
                    "total_matches": len(matching_messages)
                })

            if len(results) >= limit:
                break

        return results

    def delete_conversation(self, conversation_id: str) -> bool:
        """Delete a conversation.

        Args:
            conversation_id: The conversation ID

        Returns:
            True if deleted, False if not found
        """
        conversation_file = self.storage_dir / f"{conversation_id}.json"
        if not conversation_file.exists():
            return False

        # Remove from index
        index = self._load_index()
        index = [c for c in index if c["id"] != conversation_id]
        self._save_index(index)

        # Delete file
        conversation_file.unlink()

        return True

    def cleanup_old_conversations(self, days: int = 30) -> int:
        """Delete conversations older than specified days.

        Args:
            days: Number of days to keep

        Returns:
            Number of conversations deleted
        """
        cutoff = datetime.now().timestamp() - (days * 24 * 60 * 60)
        index = self._load_index()
        deleted = 0

        for conv_summary in index[:]:  # Copy to iterate safely
            updated_at = datetime.fromisoformat(conv_summary["updated_at"]).timestamp()
            if updated_at < cutoff and self.delete_conversation(conv_summary["id"]):
                deleted += 1

        return deleted

    def _save_conversation(self, conversation: Conversation) -> None:
        """Save a conversation to disk."""
        conversation_file = self.storage_dir / f"{conversation.id}.json"
        with open(conversation_file, "w") as f:
            json.dump(conversation.model_dump(), f, indent=2, default=str)

    def _update_index_timestamp(self, conversation_id: str) -> None:
        """Update the timestamp in the index for a conversation."""
        index = self._load_index()
        for conv in index:
            if conv["id"] == conversation_id:
                conv["updated_at"] = datetime.now().isoformat()
                break
        self._save_index(index)

    def get_active_conversation(self, client: str, server: str) -> Conversation | None:
        """Get the most recent active conversation for a client-server pair.

        Args:
            client: The client identifier
            server: The MCP server name

        Returns:
            The most recent conversation or None
        """
        conversations = self.list_conversations(client=client, server=server, limit=1)
        if not conversations:
            return None

        # Check if the conversation is recent (within last hour)
        conv_summary = conversations[0]
        updated_at = datetime.fromisoformat(conv_summary["updated_at"])
        if (datetime.now() - updated_at).seconds < 3600:
            return self.get_conversation(conv_summary["id"])

        return None
