"""Tests for conversation storage functionality."""

from datetime import datetime, timedelta

import pytest

from vulnicheck.conversation_storage import (
    Conversation,
    ConversationMessage,
    ConversationStorage,
)


@pytest.fixture
def temp_storage_dir(tmp_path):
    """Create a temporary storage directory."""
    return tmp_path


@pytest.fixture
def storage(temp_storage_dir):
    """Create a ConversationStorage instance with temp directory."""
    return ConversationStorage(base_path=temp_storage_dir)


class TestConversationMessage:
    """Test ConversationMessage model."""

    def test_create_request_message(self):
        """Test creating a request message."""
        msg = ConversationMessage(
            direction="request",
            client="claude",
            server="github",
            tool="search_repositories",
            parameters={"query": "vulnicheck"}
        )

        assert msg.direction == "request"
        assert msg.client == "claude"
        assert msg.server == "github"
        assert msg.tool == "search_repositories"
        assert msg.parameters == {"query": "vulnicheck"}
        assert msg.result is None
        assert msg.error is None
        assert msg.id  # Should have auto-generated ID
        assert isinstance(msg.timestamp, datetime)

    def test_create_response_message(self):
        """Test creating a response message."""
        msg = ConversationMessage(
            direction="response",
            client="claude",
            server="github",
            tool="search_repositories",
            result={"status": "success", "count": 1},
            risk_assessment={"risk_level": "LOW_RISK"}
        )

        assert msg.direction == "response"
        assert msg.result == {"status": "success", "count": 1}
        assert msg.risk_assessment == {"risk_level": "LOW_RISK"}
        assert msg.error is None

    def test_create_error_message(self):
        """Test creating an error response message."""
        msg = ConversationMessage(
            direction="response",
            client="claude",
            server="github",
            tool="search_repositories",
            error="Connection timeout"
        )

        assert msg.direction == "response"
        assert msg.error == "Connection timeout"
        assert msg.result is None


class TestConversation:
    """Test Conversation model."""

    def test_create_conversation(self):
        """Test creating a conversation."""
        conv = Conversation(
            client="claude",
            server="github",
            metadata={"passthrough_mode": "with_approval"}
        )

        assert conv.client == "claude"
        assert conv.server == "github"
        assert conv.metadata == {"passthrough_mode": "with_approval"}
        assert conv.messages == []
        assert conv.id  # Should have auto-generated ID
        assert isinstance(conv.started_at, datetime)
        assert isinstance(conv.updated_at, datetime)


class TestConversationStorage:
    """Test ConversationStorage functionality."""

    def test_initialization(self, storage, temp_storage_dir):
        """Test storage initialization."""
        expected_dir = temp_storage_dir / ".vulnicheck" / "conversations"
        assert storage.storage_dir == expected_dir
        assert expected_dir.exists()
        assert storage.index_file.exists()

    def test_start_conversation(self, storage):
        """Test starting a new conversation."""
        conv = storage.start_conversation(
            client="claude",
            server="github",
            metadata={"test": True}
        )

        assert conv.client == "claude"
        assert conv.server == "github"
        assert conv.metadata == {"test": True}

        # Check index was updated
        index = storage._load_index()
        assert len(index) == 1
        assert index[0]["id"] == conv.id
        assert index[0]["client"] == "claude"
        assert index[0]["server"] == "github"

        # Check conversation file was created
        conv_file = storage.storage_dir / f"{conv.id}.json"
        assert conv_file.exists()

    def test_add_request(self, storage):
        """Test adding a request message."""
        conv = storage.start_conversation("claude", "github")

        msg = storage.add_request(
            conversation_id=conv.id,
            client="claude",
            server="github",
            tool="search_repositories",
            parameters={"query": "test"}
        )

        assert msg.direction == "request"
        assert msg.tool == "search_repositories"
        assert msg.parameters == {"query": "test"}

        # Reload conversation and check
        loaded_conv = storage.get_conversation(conv.id)
        assert len(loaded_conv.messages) == 1
        assert loaded_conv.messages[0].tool == "search_repositories"

    def test_add_response(self, storage):
        """Test adding a response message."""
        conv = storage.start_conversation("claude", "github")

        # Add request first
        storage.add_request(
            conversation_id=conv.id,
            client="claude",
            server="github",
            tool="search_repositories",
            parameters={"query": "test"}
        )

        # Add response
        msg = storage.add_response(
            conversation_id=conv.id,
            client="claude",
            server="github",
            tool="search_repositories",
            result={"status": "success", "count": 5},
            risk_assessment={"risk_level": "LOW_RISK"}
        )

        assert msg.direction == "response"
        assert msg.result == {"status": "success", "count": 5}
        assert msg.risk_assessment == {"risk_level": "LOW_RISK"}

        # Reload conversation and check
        loaded_conv = storage.get_conversation(conv.id)
        assert len(loaded_conv.messages) == 2
        assert loaded_conv.messages[1].direction == "response"

    def test_add_error_response(self, storage):
        """Test adding an error response message."""
        conv = storage.start_conversation("claude", "github")

        msg = storage.add_response(
            conversation_id=conv.id,
            client="claude",
            server="github",
            tool="search_repositories",
            error="Connection refused"
        )

        assert msg.error == "Connection refused"
        assert msg.result is None

    def test_get_conversation(self, storage):
        """Test retrieving a conversation."""
        conv = storage.start_conversation("claude", "github")
        storage.add_request(
            conversation_id=conv.id,
            client="claude",
            server="github",
            tool="test_tool",
            parameters={}
        )

        loaded = storage.get_conversation(conv.id)
        assert loaded is not None
        assert loaded.id == conv.id
        assert loaded.client == "claude"
        assert loaded.server == "github"
        assert len(loaded.messages) == 1

    def test_get_conversation_not_found(self, storage):
        """Test retrieving a non-existent conversation."""
        result = storage.get_conversation("non-existent-id")
        assert result is None

    def test_list_conversations(self, storage):
        """Test listing conversations."""
        # Create multiple conversations
        conv1 = storage.start_conversation("claude", "github")
        storage.start_conversation("claude", "zen")
        storage.start_conversation("cursor", "github")

        # List all
        all_convs = storage.list_conversations()
        assert len(all_convs) == 3

        # Filter by client
        claude_convs = storage.list_conversations(client="claude")
        assert len(claude_convs) == 2

        # Filter by server
        github_convs = storage.list_conversations(server="github")
        assert len(github_convs) == 2

        # Filter by both
        claude_github = storage.list_conversations(client="claude", server="github")
        assert len(claude_github) == 1
        assert claude_github[0]["id"] == conv1.id

    def test_list_conversations_pagination(self, storage):
        """Test pagination of conversation listing."""
        # Create 5 conversations
        for i in range(5):
            storage.start_conversation("claude", f"server{i}")

        # Test limit
        limited = storage.list_conversations(limit=3)
        assert len(limited) == 3

        # Test offset
        offset = storage.list_conversations(limit=3, offset=2)
        assert len(offset) == 3

        # Test offset beyond end
        beyond = storage.list_conversations(limit=10, offset=10)
        assert len(beyond) == 0

    def test_search_conversations(self, storage):
        """Test searching conversations."""
        # Create conversations with different content
        conv1 = storage.start_conversation("claude", "github")
        storage.add_request(
            conversation_id=conv1.id,
            client="claude",
            server="github",
            tool="search_repositories",
            parameters={"query": "vulnicheck"}
        )

        conv2 = storage.start_conversation("claude", "zen")
        storage.add_request(
            conversation_id=conv2.id,
            client="claude",
            server="zen",
            tool="chat",
            parameters={"prompt": "Hello world"}
        )
        storage.add_response(
            conversation_id=conv2.id,
            client="claude",
            server="zen",
            tool="chat",
            result={"response": "Hello! How can I help you today?"}
        )

        # Search by tool name
        results = storage.search_conversations("search_repositories")
        assert len(results) == 1
        assert results[0]["conversation"]["id"] == conv1.id

        # Search by parameter content
        results = storage.search_conversations("vulnicheck")
        assert len(results) == 1

        # Search in results
        results = storage.search_conversations("help you today")
        assert len(results) == 1
        assert results[0]["conversation"]["id"] == conv2.id

        # Search with no matches
        results = storage.search_conversations("nonexistent")
        assert len(results) == 0

    def test_delete_conversation(self, storage):
        """Test deleting a conversation."""
        conv = storage.start_conversation("claude", "github")
        conv_id = conv.id

        # Verify it exists
        assert storage.get_conversation(conv_id) is not None

        # Delete it
        result = storage.delete_conversation(conv_id)
        assert result is True

        # Verify it's gone
        assert storage.get_conversation(conv_id) is None

        # Verify it's removed from index
        index = storage._load_index()
        assert len(index) == 0

        # Verify file is deleted
        conv_file = storage.storage_dir / f"{conv_id}.json"
        assert not conv_file.exists()

    def test_delete_nonexistent_conversation(self, storage):
        """Test deleting a non-existent conversation."""
        result = storage.delete_conversation("non-existent-id")
        assert result is False

    def test_cleanup_old_conversations(self, storage):
        """Test cleaning up old conversations."""
        # Create old conversation
        old_conv = storage.start_conversation("claude", "github")
        old_id = old_conv.id

        # Manually set updated_at to 40 days ago
        old_conv.updated_at = datetime.now() - timedelta(days=40)
        storage._save_conversation(old_conv)

        # Update index with old timestamp
        index = storage._load_index()
        index[0]["updated_at"] = old_conv.updated_at.isoformat()
        storage._save_index(index)

        # Create recent conversation
        recent_conv = storage.start_conversation("claude", "zen")
        recent_id = recent_conv.id

        # Cleanup conversations older than 30 days
        deleted_count = storage.cleanup_old_conversations(days=30)
        assert deleted_count == 1

        # Verify old is gone, recent remains
        assert storage.get_conversation(old_id) is None
        assert storage.get_conversation(recent_id) is not None

    def test_get_active_conversation(self, storage):
        """Test getting active conversation."""
        # No conversations yet
        result = storage.get_active_conversation("claude", "github")
        assert result is None

        # Create a conversation
        conv = storage.start_conversation("claude", "github")

        # Should find it as active (within last hour)
        result = storage.get_active_conversation("claude", "github")
        assert result is not None
        assert result.id == conv.id

        # Create old conversation
        old_conv = storage.start_conversation("claude", "zen")
        old_conv.updated_at = datetime.now() - timedelta(hours=2)
        storage._save_conversation(old_conv)

        # Update index
        index = storage._load_index()
        for item in index:
            if item["id"] == old_conv.id:
                item["updated_at"] = old_conv.updated_at.isoformat()
        storage._save_index(index)

        # Should not find old conversation as active
        result = storage.get_active_conversation("claude", "zen")
        assert result is None

    def test_auto_create_conversation_on_add_request(self, storage):
        """Test that add_request auto-creates conversation if needed."""
        # Use a specific conversation ID that doesn't exist
        conv_id = "auto-created-conv"

        storage.add_request(
            conversation_id=conv_id,
            client="claude",
            server="github",
            tool="test_tool",
            parameters={}
        )

        # Should have created the conversation
        conv = storage.get_conversation(conv_id)
        assert conv is not None
        assert conv.id == conv_id
        assert conv.client == "claude"
        assert conv.server == "github"
        assert len(conv.messages) == 1

    def test_concurrent_message_handling(self, storage):
        """Test handling multiple messages in sequence."""
        conv = storage.start_conversation("claude", "github")

        # Add multiple request/response pairs
        for i in range(3):
            storage.add_request(
                conversation_id=conv.id,
                client="claude",
                server="github",
                tool=f"tool_{i}",
                parameters={"index": i}
            )

            storage.add_response(
                conversation_id=conv.id,
                client="claude",
                server="github",
                tool=f"tool_{i}",
                result={"status": "success", "index": i}
            )

        # Verify all messages are stored
        loaded = storage.get_conversation(conv.id)
        assert len(loaded.messages) == 6  # 3 requests + 3 responses

        # Verify order
        for i in range(3):
            req_idx = i * 2
            resp_idx = req_idx + 1
            assert loaded.messages[req_idx].direction == "request"
            assert loaded.messages[req_idx].tool == f"tool_{i}"
            assert loaded.messages[resp_idx].direction == "response"
            assert loaded.messages[resp_idx].result["index"] == i

    def test_conversation_metadata(self, storage):
        """Test conversation metadata handling."""
        metadata = {
            "passthrough_mode": "interactive",
            "session_id": "test-123",
            "custom_field": "value"
        }

        conv = storage.start_conversation(
            client="claude",
            server="github",
            metadata=metadata
        )

        # Verify metadata is stored
        loaded = storage.get_conversation(conv.id)
        assert loaded.metadata == metadata

    def test_risk_assessment_storage(self, storage):
        """Test storing risk assessment in messages."""
        conv = storage.start_conversation("claude", "github")

        risk_assessment = {
            "risk_level": "HIGH_RISK",
            "category": "file_access",
            "pattern_name": "sensitive_file",
            "description": "Accessing sensitive file"
        }

        msg = storage.add_response(
            conversation_id=conv.id,
            client="claude",
            server="github",
            tool="read_file",
            result={"status": "blocked"},
            risk_assessment=risk_assessment
        )

        assert msg.risk_assessment == risk_assessment

        # Verify it's persisted
        loaded = storage.get_conversation(conv.id)
        assert loaded.messages[0].risk_assessment == risk_assessment
