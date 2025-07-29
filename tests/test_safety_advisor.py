"""Tests for the safety advisor module."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnicheck.security.safety_advisor import SafetyAdvisor, assess_operation_safety


class TestSafetyAdvisor:
    """Test the SafetyAdvisor class."""

    @pytest.fixture
    def advisor(self):
        """Create a SafetyAdvisor instance."""
        return SafetyAdvisor()

    @pytest.mark.asyncio
    async def test_structured_assessment_file_write(self, advisor):
        """Test structured assessment for file write operations."""
        advisor.has_llm = False  # Force structured assessment

        result = await advisor.assess_operation(
            "file_write",
            {"path": "/etc/hosts", "content": "127.0.0.1 localhost"},
            "Updating system hosts file"
        )

        assert result["assessment"] == "Structured risk assessment (no LLM available)"
        assert any("system directory" in risk for risk in result["risks"])
        assert result["requires_human_approval"] is True
        assert len(result["recommendations"]) > 0
        assert any("risk aversion" in rec for rec in result["recommendations"])

    @pytest.mark.asyncio
    async def test_structured_assessment_file_delete(self, advisor):
        """Test structured assessment for file delete operations."""
        advisor.has_llm = False

        result = await advisor.assess_operation(
            "file_delete",
            {"path": "~/.ssh/id_rsa"},
            "Removing SSH key"
        )

        assert "Deleting security credentials" in result["risks"]
        assert result["requires_human_approval"] is True

    @pytest.mark.asyncio
    async def test_structured_assessment_command_execution(self, advisor):
        """Test structured assessment for command execution."""
        advisor.has_llm = False

        result = await advisor.assess_operation(
            "command_execution",
            {"command": "sudo rm -rf /"},
            None
        )

        assert any("Elevated privilege" in risk for risk in result["risks"])
        assert any("Destructive command" in risk for risk in result["risks"])
        assert result["requires_human_approval"] is True

    @pytest.mark.asyncio
    async def test_structured_assessment_safe_operation(self, advisor):
        """Test structured assessment for a relatively safe operation."""
        advisor.has_llm = False

        result = await advisor.assess_operation(
            "file_write",
            {"path": "/tmp/test.txt", "content": "test"},
            "Writing temporary test file"
        )

        # Should still have some recommendations but no specific risks
        assert len(result["risks"]) == 0 or result["risks"] == ["No specific risks identified"]
        assert result["requires_human_approval"] is False

    @pytest.mark.asyncio
    async def test_structured_assessment_unknown_operation(self, advisor):
        """Test structured assessment for unknown operation type."""
        advisor.has_llm = False

        result = await advisor.assess_operation(
            "unknown_operation",
            {"data": "some data"},
            None
        )

        assert "Unknown operation type" in result["risks"][0]
        assert result["requires_human_approval"] is True

    @pytest.mark.asyncio
    async def test_llm_assessment_success(self, advisor):
        """Test LLM assessment when API is available."""
        advisor.has_llm = True
        advisor.risk_assessor = MagicMock()
        advisor.risk_assessor.assess_request = AsyncMock(return_value=(
            False,  # is_safe
            "HIGH_RISK",  # risk_level
            "This operation modifies critical system files\nSpecific risks: Writing to system configuration"  # explanation
        ))

        result = await advisor.assess_operation(
            "file_write",
            {"path": "/etc/hosts"},
            None
        )

        assert "LLM Risk Assessment: HIGH_RISK" in result["assessment"]
        assert any("Writing to system configuration" in risk for risk in result["risks"])
        assert result["requires_human_approval"] is True

    @pytest.mark.asyncio
    async def test_llm_assessment_safe(self, advisor):
        """Test LLM assessment for safe operation."""
        advisor.has_llm = True
        advisor.risk_assessor = MagicMock()
        advisor.risk_assessor.assess_request = AsyncMock(return_value=(
            True,  # is_safe
            "SAFE",  # risk_level
            "No security concerns"  # explanation
        ))

        result = await advisor.assess_operation(
            "file_write",
            {"path": "/tmp/test.txt"},
            None
        )

        assert "Operation assessed as safe by LLM" in result["assessment"]
        assert result["risks"] == []
        assert result["requires_human_approval"] is False

    @pytest.mark.asyncio
    async def test_llm_assessment_fallback(self, advisor):
        """Test fallback to structured assessment when LLM fails."""
        advisor.has_llm = True
        advisor.risk_assessor = MagicMock()
        advisor.risk_assessor.assess_request = AsyncMock(side_effect=Exception("API error"))

        result = await advisor.assess_operation(
            "file_write",
            {"path": "/etc/hosts"},
            None
        )

        # Should fall back to structured assessment
        assert "Structured risk assessment" in result["assessment"]
        assert any("system directory" in risk for risk in result["risks"])

    @pytest.mark.asyncio
    async def test_format_operation(self, advisor):
        """Test operation formatting."""
        formatted = advisor._format_operation(
            "file_write",
            {"path": "/tmp/test.txt", "content": "hello", "mode": "w"},
            "Test context"
        )

        assert "path: /tmp/test.txt" in formatted
        assert "content: hello" in formatted
        assert "mode: w" in formatted

    @pytest.mark.asyncio
    async def test_assess_operation_safety_function(self):
        """Test the main entry point function."""
        with patch('vulnicheck.security.safety_advisor.SafetyAdvisor') as mock_advisor_class:
            mock_advisor = MagicMock()
            mock_advisor.assess_operation = AsyncMock(return_value={
                "assessment": "Test assessment",
                "risks": ["Test risk"],
                "recommendations": ["Test recommendation"],
                "requires_human_approval": False
            })
            mock_advisor_class.return_value = mock_advisor

            result = await assess_operation_safety(
                "file_write",
                {"path": "/tmp/test.txt"},
                "Test"
            )

            assert result["assessment"] == "Test assessment"
            assert result["risks"] == ["Test risk"]

    def test_initialization(self):
        """Test SafetyAdvisor initialization."""
        with patch('vulnicheck.security.safety_advisor.get_risk_assessor') as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = True
            mock_get_assessor.return_value = mock_assessor

            advisor = SafetyAdvisor()

            assert advisor.risk_assessor == mock_assessor
            assert advisor.has_llm is True

    def test_initialization_no_llm(self):
        """Test SafetyAdvisor initialization without LLM."""
        with patch('vulnicheck.security.safety_advisor.get_risk_assessor') as mock_get_assessor:
            mock_assessor = MagicMock()
            mock_assessor.enabled = False
            mock_get_assessor.return_value = mock_assessor

            advisor = SafetyAdvisor()

            assert advisor.risk_assessor == mock_assessor
            assert advisor.has_llm is False
