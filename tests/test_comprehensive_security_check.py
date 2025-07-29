"""
Tests for comprehensive security check tool.
"""

import os
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from vulnicheck.security.comprehensive_security_check import (
    ComprehensiveSecurityCheck,
    ConversationContext,
    ConversationState,
    RiskLevel,
    SecurityFinding,
)


@pytest.fixture
def security_checker():
    """Create a security checker instance."""
    return ComprehensiveSecurityCheck()


@pytest.fixture
def mock_project_path(tmp_path):
    """Create a mock project structure."""
    # Create some test files
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\nrequests==2.28.0\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test-project'\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.9\nRUN pip install flask\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / "main.py").write_text("import flask\nimport requests\n")
    (tmp_path / "utils.py").write_text("import os\nimport json\n")
    return tmp_path


class TestComprehensiveSecurityCheck:
    """Test the ComprehensiveSecurityCheck class."""

    def test_initialization(self, security_checker):
        """Test security checker initialization."""
        assert security_checker.safety_advisor is not None
        assert isinstance(security_checker.context, ConversationContext)
        assert security_checker.context.state == ConversationState.INITIAL_DISCOVERY

    def test_has_llm_configured(self, security_checker):
        """Test LLM configuration check."""
        # Test with no API keys
        with patch.dict(os.environ, {}, clear=True):
            assert not security_checker.has_llm_configured()

        # Test with OpenAI key
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            assert security_checker.has_llm_configured()

        # Test with Anthropic key
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            assert security_checker.has_llm_configured()

    @pytest.mark.asyncio
    async def test_start_conversation_no_llm(self, security_checker):
        """Test starting conversation without LLM configured."""
        with patch.dict(os.environ, {}, clear=True):
            result = await security_checker.start_conversation()
            assert result["status"] == "error"
            assert "No LLM configured" in result["error"]

    @pytest.mark.asyncio
    async def test_start_conversation_with_path(self, security_checker, mock_project_path):
        """Test starting conversation with initial path."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            result = await security_checker.start_conversation(str(mock_project_path))

            assert result["status"] == "question"
            assert str(mock_project_path) in result["question"]
            assert "Is this the correct project root?" in result["question"]
            assert result["conversation_id"] is not None
            assert security_checker.context.state == ConversationState.CONFIRM_PROJECT_PATH

    @pytest.mark.asyncio
    async def test_start_conversation_current_dir(self, security_checker):
        """Test starting conversation with current directory."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            result = await security_checker.start_conversation()

            assert result["status"] == "question"
            assert str(Path.cwd()) in result["question"]
            assert security_checker.context.project_path == Path.cwd()

    @pytest.mark.asyncio
    async def test_discover_resources(self, security_checker, mock_project_path):
        """Test resource discovery."""
        security_checker.context.project_path = mock_project_path

        with patch.object(security_checker, '_check_mcp_config_exists', return_value=True):
            discovery = await security_checker._discover_resources()

        assert len(discovery["dependency_files"]) == 2
        assert "requirements.txt" in discovery["dependency_files"]
        assert "pyproject.toml" in discovery["dependency_files"]
        assert len(discovery["dockerfiles"]) == 1
        assert "Dockerfile" in discovery["dockerfiles"][0]
        assert discovery["has_git"] is True
        assert discovery["python_files_count"] == 2
        assert discovery["has_mcp_config"] is True

    @pytest.mark.asyncio
    async def test_handle_project_path_confirmation_yes(self, security_checker, mock_project_path):
        """Test handling project path confirmation with yes."""
        security_checker.context.project_path = mock_project_path
        security_checker.context.dependency_files = [
            mock_project_path / "requirements.txt",
            mock_project_path / "pyproject.toml"
        ]

        result = await security_checker._handle_project_path_confirmation("yes")

        assert result["status"] == "question"
        assert "dependency files" in result["question"]
        assert security_checker.context.state == ConversationState.CONFIRM_DEPENDENCIES

    @pytest.mark.asyncio
    async def test_handle_project_path_confirmation_no(self, security_checker):
        """Test handling project path confirmation with no."""
        result = await security_checker._handle_project_path_confirmation("no")

        assert result["status"] == "question"
        assert "correct project root path" in result["question"]

    @pytest.mark.asyncio
    async def test_handle_dependencies_confirmation(self, security_checker):
        """Test handling dependencies scan confirmation."""
        # Mock _next_question to avoid state changes
        with patch.object(security_checker, '_next_question', return_value={"status": "question"}):
            await security_checker._handle_dependencies_confirmation("yes")

        assert security_checker.context.scan_results["scan_dependencies"] is True
        assert security_checker.context.state == ConversationState.CONFIRM_DOCKERFILE

    @pytest.mark.asyncio
    async def test_handle_dockerfile_confirmation(self, security_checker):
        """Test handling Dockerfile scan confirmation."""
        # Mock _next_question to avoid state changes
        with patch.object(security_checker, '_next_question', return_value={"status": "question"}):
            await security_checker._handle_dockerfile_confirmation("yes")

        assert security_checker.context.scan_results["scan_dockerfile"] is True
        assert security_checker.context.state == ConversationState.CONFIRM_MCP_CONFIG

    @pytest.mark.asyncio
    async def test_handle_mcp_confirmation_with_agent(self, security_checker):
        """Test handling MCP confirmation with agent name."""
        # Mock _next_question to avoid state changes
        with patch.object(security_checker, '_next_question', AsyncMock(return_value={"status": "question"})):
            # Note: the implementation checks if response starts with "yes" or "y"
            # but "yes claude" starts with "yes" so it should work
            await security_checker._handle_mcp_confirmation("yes claude")

        assert security_checker.context.scan_results.get("validate_mcp") is True
        assert security_checker.context.mcp_agent == "claude"
        assert security_checker.context.state == ConversationState.CONFIRM_SECRET_SCAN

    @pytest.mark.asyncio
    async def test_handle_secret_scan_confirmation(self, security_checker):
        """Test handling secret scan confirmation."""
        security_checker.context.scan_results = {
            "scan_dependencies": True,
            "scan_dockerfile": True
        }

        result = await security_checker._handle_secret_scan_confirmation("yes")

        assert security_checker.context.scan_results["scan_secrets"] is True
        assert result["status"] == "executing"
        assert "Starting comprehensive security scan" in result["message"]
        assert security_checker.context.state == ConversationState.EXECUTING_SCANS

    @pytest.mark.asyncio
    async def test_continue_conversation_flow(self, security_checker, mock_project_path):
        """Test the full conversation flow."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            # Start conversation
            await security_checker.start_conversation(str(mock_project_path))

            # Confirm project path
            result = await security_checker.continue_conversation("yes")
            assert "dependency files" in result["question"]

            # Confirm dependencies scan
            result = await security_checker.continue_conversation("yes")
            assert security_checker.context.state == ConversationState.CONFIRM_DOCKERFILE

    @pytest.mark.asyncio
    async def test_execute_scans_success(self, security_checker, mock_project_path):
        """Test successful scan execution."""
        security_checker.context.project_path = mock_project_path
        security_checker.context.dependency_files = [mock_project_path / "requirements.txt"]
        security_checker.context.dockerfiles = [mock_project_path / "Dockerfile"]
        security_checker.context.scan_results = {
            "scan_dependencies": True,
            "scan_dockerfile": True,
            "validate_mcp": True,
            "scan_secrets": True
        }
        security_checker.context.mcp_agent = "claude"

        # Mock scan tools
        mock_scan_deps = AsyncMock(return_value={"vulnerabilities": {"flask": [{"id": "CVE-2023-1234"}]}})
        mock_scan_docker = AsyncMock(return_value={"vulnerable_packages": []})
        mock_validate_mcp = AsyncMock(return_value={"findings": []})
        mock_scan_secrets = AsyncMock(return_value={"findings": []})

        scan_tools = {
            "scan_dependencies": mock_scan_deps,
            "scan_dockerfile": mock_scan_docker,
            "validate_mcp_security": mock_validate_mcp,
            "scan_for_secrets": mock_scan_secrets
        }

        with patch.object(security_checker, '_analyze_results_with_llm', return_value={
            "risk_level": "medium",
            "analysis": "Found some issues",
            "recommendations": ["Fix vulnerabilities"],
            "finding_count": 1
        }):
            result = await security_checker.execute_scans(scan_tools)

        assert result["status"] == "complete"
        assert result["executive_summary"]["overall_risk"] == "medium"
        assert result["executive_summary"]["total_findings"] == 1
        assert "detailed_findings" in result
        assert "recommendations" in result

    @pytest.mark.asyncio
    async def test_execute_scans_with_errors(self, security_checker, mock_project_path):
        """Test scan execution with errors."""
        security_checker.context.project_path = mock_project_path
        security_checker.context.dependency_files = [mock_project_path / "requirements.txt"]
        security_checker.context.scan_results = {"scan_dependencies": True}

        # Mock scan tool that raises exception
        mock_scan_deps = AsyncMock(side_effect=Exception("Scan failed"))
        scan_tools = {"scan_dependencies": mock_scan_deps}

        with patch.object(security_checker, '_analyze_results_with_llm', return_value={
            "risk_level": "low",
            "analysis": "Error in scanning",
            "recommendations": [],
            "finding_count": 0
        }):
            result = await security_checker.execute_scans(scan_tools)

        assert result["status"] == "complete"
        assert "error" in result["detailed_findings"]["dependencies_requirements.txt"]

    @pytest.mark.asyncio
    async def test_analyze_results_with_llm(self, security_checker):
        """Test LLM analysis of results."""
        results = {
            "dependencies_requirements.txt": {
                "vulnerabilities": {
                    "flask": [{
                        "id": "CVE-2023-1234",
                        "severity": "high",
                        "summary": "Security vulnerability in Flask"
                    }]
                }
            },
            "secrets": {
                "findings": [{
                    "file": "config.py",
                    "type": "API Key",
                    "severity": "high"
                }]
            }
        }

        mock_assessment = {
            "assessment": "Critical security issues found",
            "recommendations": ["Update Flask", "Remove API key"]
        }

        with patch.object(security_checker.safety_advisor, 'assess_operation',
                         return_value=mock_assessment):
            analysis = await security_checker._analyze_results_with_llm(results)

        assert analysis["risk_level"] == "critical"
        assert "Critical security issues" in analysis["analysis"]
        assert len(analysis["recommendations"]) == 2
        assert analysis["finding_count"] == 2

    def test_basic_analysis_fallback(self, security_checker):
        """Test basic analysis when LLM fails."""
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"}
        ]

        analysis = security_checker._basic_analysis(findings)

        assert analysis["risk_level"] == "critical"
        assert analysis["finding_count"] == 4
        assert analysis["severity_breakdown"]["critical"] == 1
        assert analysis["severity_breakdown"]["high"] == 2

    def test_generate_comprehensive_report(self, security_checker):
        """Test comprehensive report generation."""
        security_checker.context.project_path = Path("/test/project")
        security_checker.context.scan_results = {"scan_dependencies": True}
        security_checker.context.user_responses = {"confirm_project_path": "yes"}

        scan_results = {"test": "results"}
        analysis = {
            "risk_level": "high",
            "finding_count": 5,
            "recommendations": ["Fix issues"]
        }

        report = security_checker._generate_comprehensive_report(scan_results, analysis)

        assert report["status"] == "complete"
        assert report["executive_summary"]["overall_risk"] == "high"
        assert report["executive_summary"]["total_findings"] == 5
        assert report["detailed_findings"] == scan_results
        assert report["analysis"] == analysis
        assert "timestamp" in report

    @pytest.mark.asyncio
    async def test_next_question_dockerfile(self, security_checker, mock_project_path):
        """Test next question for Dockerfile confirmation."""
        security_checker.context.state = ConversationState.CONFIRM_DOCKERFILE
        security_checker.context.dockerfiles = [mock_project_path / "Dockerfile"]

        result = await security_checker._next_question()

        assert "Dockerfile" in result["question"]
        assert "scan these for Python package vulnerabilities" in result["question"]

    @pytest.mark.asyncio
    async def test_next_question_no_dockerfile(self, security_checker):
        """Test next question when no Dockerfile exists."""
        security_checker.context.state = ConversationState.CONFIRM_DOCKERFILE
        security_checker.context.dockerfiles = []
        security_checker.context.has_mcp_config = False  # This will skip MCP config too

        await security_checker._next_question()

        # Should skip to secret scan since no MCP config
        assert security_checker.context.state == ConversationState.CONFIRM_SECRET_SCAN

    @pytest.mark.asyncio
    async def test_next_question_mcp_config(self, security_checker):
        """Test next question for MCP configuration."""
        security_checker.context.state = ConversationState.CONFIRM_MCP_CONFIG
        security_checker.context.has_mcp_config = True

        result = await security_checker._next_question()

        assert "MCP configuration" in result["question"]
        assert "validate MCP security" in result["question"]

    @pytest.mark.asyncio
    async def test_next_question_secret_scan(self, security_checker, mock_project_path):
        """Test next question for secret scan."""
        security_checker.context.state = ConversationState.CONFIRM_SECRET_SCAN
        security_checker.context.project_path = mock_project_path

        result = await security_checker._next_question()

        assert "exposed secrets and credentials" in result["question"]
        assert mock_project_path.name in result["question"]


class TestConversationContext:
    """Test the ConversationContext dataclass."""

    def test_conversation_context_defaults(self):
        """Test default values for ConversationContext."""
        context = ConversationContext()

        assert context.state == ConversationState.INITIAL_DISCOVERY
        assert context.project_path is None
        assert context.dependency_files == []
        assert context.dockerfiles == []
        assert context.has_mcp_config is False
        assert context.mcp_agent is None
        assert context.scan_for_secrets is True
        assert context.findings == []
        assert context.scan_results == {}
        assert context.questions_asked == []
        assert context.user_responses == {}
        assert isinstance(context.start_time, datetime)


class TestSecurityFinding:
    """Test the SecurityFinding dataclass."""

    def test_security_finding_creation(self):
        """Test creating a SecurityFinding."""
        finding = SecurityFinding(
            tool="scan_dependencies",
            category="vulnerability",
            severity="high",
            description="Flask vulnerability",
            details={"cve": "CVE-2023-1234"},
            recommendations=["Update Flask to 2.1.0"]
        )

        assert finding.tool == "scan_dependencies"
        assert finding.category == "vulnerability"
        assert finding.severity == "high"
        assert finding.description == "Flask vulnerability"
        assert finding.details["cve"] == "CVE-2023-1234"
        assert finding.recommendations[0] == "Update Flask to 2.1.0"


class TestEnums:
    """Test enum definitions."""

    def test_conversation_state_enum(self):
        """Test ConversationState enum values."""
        assert ConversationState.INITIAL_DISCOVERY.value == "initial_discovery"
        assert ConversationState.CONFIRM_PROJECT_PATH.value == "confirm_project_path"
        assert ConversationState.EXECUTING_SCANS.value == "executing_scans"
        assert ConversationState.COMPLETE.value == "complete"

    def test_risk_level_enum(self):
        """Test RiskLevel enum values."""
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.INFO.value == "info"
