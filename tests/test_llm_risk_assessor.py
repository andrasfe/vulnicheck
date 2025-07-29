"""Tests for LLM risk assessor."""

from unittest.mock import MagicMock, patch

import pytest
from httpx import Response

from vulnicheck.security.llm_risk_assessor import LLMRiskAssessor, get_risk_assessor


@pytest.fixture
def mock_env_no_api_keys(monkeypatch):
    """Mock environment without API keys."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture
def mock_env_openai_key(monkeypatch):
    """Mock environment with OpenAI API key."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


@pytest.fixture
def mock_env_anthropic_key(monkeypatch):
    """Mock environment with Anthropic API key."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")


class TestLLMRiskAssessor:
    """Tests for LLMRiskAssessor class."""

    def test_init_no_api_keys(self, mock_env_no_api_keys):
        """Test initialization without API keys."""
        assessor = LLMRiskAssessor()
        assert not assessor.enabled
        assert assessor.api_key is None

    def test_init_openai_key(self, mock_env_openai_key):
        """Test initialization with OpenAI API key."""
        assessor = LLMRiskAssessor()
        assert assessor.enabled
        assert assessor.api_key == "test-openai-key"
        assert assessor.api_type == "openai"

    def test_init_anthropic_key(self, mock_env_anthropic_key):
        """Test initialization with Anthropic API key."""
        assessor = LLMRiskAssessor()
        assert assessor.enabled
        assert assessor.api_key == "test-anthropic-key"
        assert assessor.api_type == "anthropic"

    @pytest.mark.asyncio
    async def test_assess_request_disabled(self, mock_env_no_api_keys):
        """Test request assessment when disabled."""
        assessor = LLMRiskAssessor()
        is_safe, risk_level, explanation = await assessor.assess_request(
            "test_server", "test_tool", {"param": "value"}
        )
        assert is_safe is True
        assert risk_level is None
        assert explanation is None

    @pytest.mark.asyncio
    async def test_assess_response_disabled(self, mock_env_no_api_keys):
        """Test response assessment when disabled."""
        assessor = LLMRiskAssessor()
        is_safe, risk_level, explanation = await assessor.assess_response(
            "test_server", "test_tool", {"param": "value"}, {"result": "data"}
        )
        assert is_safe is True
        assert risk_level is None
        assert explanation is None

    @pytest.mark.asyncio
    async def test_assess_request_openai_blocked(self, mock_env_openai_key):
        """Test request assessment with OpenAI returning blocked."""
        assessor = LLMRiskAssessor()

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": '{"is_safe": false, "risk_level": "BLOCKED", "explanation": "Attempting to access password file", "specific_risks": ["password_file_access"]}'
                }
            }]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", return_value=mock_response):
            is_safe, risk_level, explanation = await assessor.assess_request(
                "system", "read_file", {"path": "/etc/passwd"}
            )

        assert is_safe is False
        assert risk_level == "BLOCKED"
        assert "Attempting to access password file" in explanation
        assert "password_file_access" in explanation

    @pytest.mark.asyncio
    async def test_assess_request_openai_safe(self, mock_env_openai_key):
        """Test request assessment with OpenAI returning safe."""
        assessor = LLMRiskAssessor()

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": '{"is_safe": true, "risk_level": "LOW_RISK", "explanation": "Normal development operation", "specific_risks": []}'
                }
            }]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", return_value=mock_response):
            is_safe, risk_level, explanation = await assessor.assess_request(
                "git", "status", {}
            )

        assert is_safe is True
        assert risk_level == "LOW_RISK"
        assert "Normal development operation" in explanation

    @pytest.mark.asyncio
    async def test_assess_response_anthropic_sensitive(self, mock_env_anthropic_key):
        """Test response assessment with Anthropic detecting sensitive content."""
        assessor = LLMRiskAssessor()

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {
            "content": [{
                "text": 'Some text before {"is_safe": false, "risk_level": "HIGH_RISK", "explanation": "Response contains API keys", "specific_risks": ["exposed_api_key"], "sensitive_content_found": true} and after'
            }]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", return_value=mock_response):
            is_safe, risk_level, explanation = await assessor.assess_response(
                "env_server", "get_env", {}, {"API_KEY": "secret-key-123"}
            )

        assert is_safe is False
        assert risk_level == "HIGH_RISK"
        assert "Response contains API keys" in explanation
        assert "exposed_api_key" in explanation
        assert "Sensitive content detected" in explanation

    @pytest.mark.asyncio
    async def test_assess_request_error_handling(self, mock_env_openai_key):
        """Test error handling in request assessment."""
        assessor = LLMRiskAssessor()

        with patch("httpx.AsyncClient.post", side_effect=Exception("API error")):
            is_safe, risk_level, explanation = await assessor.assess_request(
                "test_server", "test_tool", {}
            )

        assert is_safe is True  # Fails open
        assert risk_level is None
        assert "Assessment error: API error" in explanation

    @pytest.mark.asyncio
    async def test_parse_assessment_response(self):
        """Test parsing of assessment responses."""
        assessor = LLMRiskAssessor()

        # Test basic response
        response = {
            "is_safe": False,
            "risk_level": "REQUIRES_APPROVAL",
            "explanation": "Needs review"
        }
        is_safe, risk_level, explanation = assessor._parse_assessment_response(response)
        assert is_safe is False
        assert risk_level == "REQUIRES_APPROVAL"
        assert explanation == "Needs review"

        # Test with specific risks
        response = {
            "is_safe": True,
            "risk_level": "LOW_RISK",
            "explanation": "Safe operation",
            "specific_risks": ["minor_concern_1", "minor_concern_2"]
        }
        is_safe, risk_level, explanation = assessor._parse_assessment_response(response)
        assert is_safe is True
        assert risk_level == "LOW_RISK"
        assert "Safe operation" in explanation
        assert "minor_concern_1, minor_concern_2" in explanation

        # Test with sensitive content flag
        response = {
            "is_safe": False,
            "risk_level": "HIGH_RISK",
            "explanation": "Risky",
            "sensitive_content_found": True
        }
        is_safe, risk_level, explanation = assessor._parse_assessment_response(response)
        assert is_safe is False
        assert risk_level == "HIGH_RISK"
        assert "Sensitive content detected" in explanation


def test_get_risk_assessor():
    """Test the global risk assessor getter."""
    assessor1 = get_risk_assessor()
    assessor2 = get_risk_assessor()
    assert assessor1 is assessor2  # Should return same instance
