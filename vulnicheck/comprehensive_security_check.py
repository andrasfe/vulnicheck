"""
Comprehensive security check tool that orchestrates all VulniCheck security tools.

This module provides an interactive security assessment that:
1. Discovers available resources (dependencies, Dockerfiles, MCP configs)
2. Asks clarifying questions one at a time
3. Executes relevant security tools based on context
4. Uses LLM to analyze and synthesize results
5. Generates comprehensive security report with recommendations
"""

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from .mcp_paths import check_mcp_exists_anywhere
from .safety_advisor import SafetyAdvisor

logger = logging.getLogger(__name__)


class ConversationState(Enum):
    """States for the interactive conversation flow."""
    INITIAL_DISCOVERY = "initial_discovery"
    CONFIRM_PROJECT_PATH = "confirm_project_path"
    CONFIRM_DEPENDENCIES = "confirm_dependencies"
    CONFIRM_DOCKERFILE = "confirm_dockerfile"
    CONFIRM_MCP_CONFIG = "confirm_mcp_config"
    CONFIRM_SECRET_SCAN = "confirm_secret_scan"
    EXECUTING_SCANS = "executing_scans"
    ANALYZING_RESULTS = "analyzing_results"
    COMPLETE = "complete"


class RiskLevel(Enum):
    """Overall risk levels for the security assessment."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityFinding:
    """Represents a security finding from any tool."""
    tool: str
    category: str
    severity: str
    description: str
    details: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class ConversationContext:
    """Maintains context throughout the interactive conversation."""
    state: ConversationState = ConversationState.INITIAL_DISCOVERY
    project_path: Path | None = None
    dependency_files: list[Path] = field(default_factory=list)
    dockerfiles: list[Path] = field(default_factory=list)
    has_mcp_config: bool = False
    mcp_agent: str | None = None
    scan_for_secrets: bool = True
    findings: list[SecurityFinding] = field(default_factory=list)
    scan_results: dict[str, Any] = field(default_factory=dict)
    questions_asked: list[str] = field(default_factory=list)
    user_responses: dict[str, str] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)


class ComprehensiveSecurityCheck:
    """Orchestrates comprehensive security checks with interactive conversation."""

    def __init__(self) -> None:
        """Initialize the comprehensive security checker."""
        self.safety_advisor = SafetyAdvisor()
        self.context = ConversationContext()

    def has_llm_configured(self) -> bool:
        """Check if an LLM is configured for analysis."""
        return bool(os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"))

    async def start_conversation(self, initial_path: str | None = None) -> dict[str, Any]:
        """
        Start the interactive security check conversation.

        Args:
            initial_path: Optional starting path for the security check

        Returns:
            Initial question or discovery results
        """
        if not self.has_llm_configured():
            return {
                "error": "No LLM configured. Please set OPENAI_API_KEY or ANTHROPIC_API_KEY to use this tool.",
                "status": "error"
            }

        self.context = ConversationContext()

        if initial_path:
            self.context.project_path = Path(initial_path).resolve()
        else:
            self.context.project_path = Path.cwd()

        # Start discovery
        discovery = await self._discover_resources()

        # Move to first question
        self.context.state = ConversationState.CONFIRM_PROJECT_PATH

        return {
            "status": "question",
            "question": f"I'll perform a comprehensive security check. I found the project at: {self.context.project_path}\n\nIs this the correct project root? (yes/no) If not, please provide the correct path.",
            "discovery": discovery,
            "conversation_id": id(self.context)
        }

    async def continue_conversation(self, user_response: str, conversation_id: int | None = None) -> dict[str, Any]:
        """
        Continue the conversation based on user response.

        Args:
            user_response: The user's response to the previous question
            conversation_id: Optional conversation ID for tracking

        Returns:
            Next question, status update, or final results
        """
        # Store the response
        self.context.user_responses[self.context.state.value] = user_response

        # Process based on current state
        if self.context.state == ConversationState.CONFIRM_PROJECT_PATH:
            return await self._handle_project_path_confirmation(user_response)
        elif self.context.state == ConversationState.CONFIRM_DEPENDENCIES:
            return await self._handle_dependencies_confirmation(user_response)
        elif self.context.state == ConversationState.CONFIRM_DOCKERFILE:
            return await self._handle_dockerfile_confirmation(user_response)
        elif self.context.state == ConversationState.CONFIRM_MCP_CONFIG:
            return await self._handle_mcp_confirmation(user_response)
        elif self.context.state == ConversationState.CONFIRM_SECRET_SCAN:
            return await self._handle_secret_scan_confirmation(user_response)
        else:
            return {"status": "error", "error": "Invalid conversation state"}

    async def _discover_resources(self) -> dict[str, Any]:
        """Discover available resources in the project."""
        discovery = {
            "dependency_files": [],
            "dockerfiles": [],
            "has_git": False,
            "has_mcp_config": False,
            "python_files_count": 0
        }

        if not self.context.project_path or not self.context.project_path.exists():
            return discovery

        # Look for dependency files
        dep_patterns = ["requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "Pipfile.lock"]
        for pattern in dep_patterns:
            for file in self.context.project_path.rglob(pattern):
                self.context.dependency_files.append(file)
                dep_files = discovery["dependency_files"]
                assert isinstance(dep_files, list)
                dep_files.append(str(file.relative_to(self.context.project_path)))

        # Look for Dockerfiles
        for file in self.context.project_path.rglob("Dockerfile*"):
            self.context.dockerfiles.append(file)
            docker_files = discovery["dockerfiles"]
            assert isinstance(docker_files, list)
            docker_files.append(str(file.relative_to(self.context.project_path)))

        # Check for git
        discovery["has_git"] = (self.context.project_path / ".git").exists()

        # Count Python files
        discovery["python_files_count"] = len(list(self.context.project_path.rglob("*.py")))

        # Check for MCP configuration (will be done properly later)
        self.context.has_mcp_config = self._check_mcp_config_exists()
        discovery["has_mcp_config"] = self.context.has_mcp_config

        return discovery

    def _check_mcp_config_exists(self) -> bool:
        """Quick check if MCP configuration might exist."""
        # This is a simplified check - the actual validation will happen later
        return check_mcp_exists_anywhere()

    async def _handle_project_path_confirmation(self, response: str) -> dict[str, Any]:
        """Handle project path confirmation response."""
        response_lower = response.lower().strip()

        if response_lower in ["yes", "y"]:
            # Move to next question
            self.context.state = ConversationState.CONFIRM_DEPENDENCIES

            if self.context.dependency_files:
                files_list = "\n".join(f"  - {f.name}" for f in self.context.dependency_files[:5])
                if len(self.context.dependency_files) > 5:
                    files_list += f"\n  ... and {len(self.context.dependency_files) - 5} more"

                return {
                    "status": "question",
                    "question": f"I found the following dependency files:\n{files_list}\n\nShould I scan these for vulnerabilities? (yes/no)",
                    "state": self.context.state.value
                }
            else:
                # No dependency files, check for Python files
                if self.context.scan_results.get("python_files_count", 0) > 0:
                    return {
                        "status": "question",
                        "question": "No dependency files found, but I see Python files. Should I scan imported packages for vulnerabilities? (yes/no)",
                        "state": self.context.state.value
                    }
                else:
                    # Skip to Dockerfile check
                    self.context.state = ConversationState.CONFIRM_DOCKERFILE
                    return await self._next_question()
        else:
            # Ask for correct path
            return {
                "status": "question",
                "question": "Please provide the correct project root path:",
                "state": self.context.state.value
            }

    async def _handle_dependencies_confirmation(self, response: str) -> dict[str, Any]:
        """Handle dependencies scan confirmation."""
        response_lower = response.lower().strip()

        if response_lower in ["yes", "y"]:
            self.context.scan_results["scan_dependencies"] = True

        # Move to Dockerfile check
        self.context.state = ConversationState.CONFIRM_DOCKERFILE
        return await self._next_question()

    async def _handle_dockerfile_confirmation(self, response: str) -> dict[str, Any]:
        """Handle Dockerfile scan confirmation."""
        response_lower = response.lower().strip()

        if response_lower in ["yes", "y"]:
            self.context.scan_results["scan_dockerfile"] = True

        # Move to MCP config check
        self.context.state = ConversationState.CONFIRM_MCP_CONFIG
        return await self._next_question()

    async def _handle_mcp_confirmation(self, response: str) -> dict[str, Any]:
        """Handle MCP configuration check confirmation."""
        response_lower = response.lower().strip()

        if response_lower.startswith(("yes", "y")):
            self.context.scan_results["validate_mcp"] = True
            # Check if they provided an agent name
            words = response.split()
            if len(words) > 1:
                agent_name = " ".join(words[1:])
                self.context.mcp_agent = agent_name

        # Move to secret scan check
        self.context.state = ConversationState.CONFIRM_SECRET_SCAN
        return await self._next_question()

    async def _handle_secret_scan_confirmation(self, response: str) -> dict[str, Any]:
        """Handle secret scan confirmation."""
        response_lower = response.lower().strip()

        if response_lower in ["yes", "y"]:
            self.context.scan_results["scan_secrets"] = True

        # All questions asked, start executing
        self.context.state = ConversationState.EXECUTING_SCANS
        return {
            "status": "executing",
            "message": "Starting comprehensive security scan...",
            "scans_to_run": [k for k, v in self.context.scan_results.items() if v]
        }

    async def _next_question(self) -> dict[str, Any]:
        """Get the next question based on current state."""
        if self.context.state == ConversationState.CONFIRM_DOCKERFILE:
            if self.context.dockerfiles:
                files_list = "\n".join(f"  - {f.name}" for f in self.context.dockerfiles[:3])
                return {
                    "status": "question",
                    "question": f"I found Dockerfile(s):\n{files_list}\n\nShould I scan these for Python package vulnerabilities? (yes/no)",
                    "state": self.context.state.value
                }
            else:
                # Skip to MCP check
                self.context.state = ConversationState.CONFIRM_MCP_CONFIG
                return await self._next_question()

        elif self.context.state == ConversationState.CONFIRM_MCP_CONFIG:
            if self.context.has_mcp_config:
                return {
                    "status": "question",
                    "question": "I detected possible MCP configuration. Should I validate MCP security? (yes/no) You can also specify the agent name (e.g., 'yes claude')",
                    "state": self.context.state.value
                }
            else:
                # Skip to secret scan
                self.context.state = ConversationState.CONFIRM_SECRET_SCAN
                return await self._next_question()

        elif self.context.state == ConversationState.CONFIRM_SECRET_SCAN:
            return {
                "status": "question",
                "question": f"Should I scan {self.context.project_path.name if self.context.project_path else 'the project'} for exposed secrets and credentials? (yes/no)",
                "state": self.context.state.value
            }

        return {"status": "error", "error": "No more questions"}

    async def execute_scans(self, scan_tools: dict[str, Any]) -> dict[str, Any]:
        """
        Execute the confirmed scans using provided tool functions.

        Args:
            scan_tools: Dictionary mapping scan names to tool functions

        Returns:
            Comprehensive security report
        """
        self.context.state = ConversationState.EXECUTING_SCANS
        results = {}

        # Execute each confirmed scan
        if self.context.scan_results.get("scan_dependencies"):
            for dep_file in self.context.dependency_files:
                try:
                    if "scan_dependencies" in scan_tools:
                        result = await scan_tools["scan_dependencies"](
                            file_path=str(dep_file),
                            include_details=True
                        )
                        results[f"dependencies_{dep_file.name}"] = result
                except Exception as e:
                    logger.error(f"Error scanning {dep_file}: {e}")
                    results[f"dependencies_{dep_file.name}"] = {"error": str(e)}

        if self.context.scan_results.get("scan_dockerfile"):
            for dockerfile in self.context.dockerfiles:
                try:
                    if "scan_dockerfile" in scan_tools:
                        result = await scan_tools["scan_dockerfile"](
                            dockerfile_path=str(dockerfile)
                        )
                        results[f"dockerfile_{dockerfile.name}"] = result
                except Exception as e:
                    logger.error(f"Error scanning {dockerfile}: {e}")
                    results[f"dockerfile_{dockerfile.name}"] = {"error": str(e)}

        if self.context.scan_results.get("validate_mcp"):
            try:
                if "validate_mcp_security" in scan_tools:
                    result = await scan_tools["validate_mcp_security"](
                        agent_name=self.context.mcp_agent or "claude",
                        mode="scan"
                    )
                    results["mcp_security"] = result
            except Exception as e:
                logger.error(f"Error validating MCP: {e}")
                results["mcp_security"] = {"error": str(e)}

        if self.context.scan_results.get("scan_secrets"):
            try:
                if "scan_for_secrets" in scan_tools:
                    result = await scan_tools["scan_for_secrets"](
                        path=str(self.context.project_path)
                    )
                    results["secrets"] = result
            except Exception as e:
                logger.error(f"Error scanning secrets: {e}")
                results["secrets"] = {"error": str(e)}

        # Store raw results
        self.context.scan_results["raw_results"] = results

        # Analyze with LLM
        self.context.state = ConversationState.ANALYZING_RESULTS
        analysis = await self._analyze_results_with_llm(results)

        # Generate final report
        self.context.state = ConversationState.COMPLETE
        return self._generate_comprehensive_report(results, analysis)

    async def _analyze_results_with_llm(self, results: dict[str, Any]) -> dict[str, Any]:
        """Use LLM to analyze and synthesize security findings."""
        # Prepare findings for LLM analysis
        all_findings = []

        for scan_type, result in results.items():
            if isinstance(result, dict) and "error" not in result:
                # Extract findings based on scan type
                if "dependencies" in scan_type and "vulnerabilities" in result:
                    for pkg, vulns in result["vulnerabilities"].items():
                        for vuln in vulns:
                            all_findings.append({
                                "type": "dependency_vulnerability",
                                "package": pkg,
                                "severity": vuln.get("severity", "unknown"),
                                "cve": vuln.get("id", ""),
                                "description": vuln.get("summary", "")
                            })

                elif "dockerfile" in scan_type and "vulnerable_packages" in result:
                    for pkg in result["vulnerable_packages"]:
                        all_findings.append({
                            "type": "dockerfile_vulnerability",
                            "package": pkg["package"],
                            "severity": "high",
                            "vulnerabilities": pkg.get("vulnerabilities", [])
                        })

                elif scan_type == "secrets" and "findings" in result:
                    for finding in result["findings"]:
                        all_findings.append({
                            "type": "exposed_secret",
                            "file": finding.get("file", ""),
                            "secret_type": finding.get("type", ""),
                            "severity": finding.get("severity", "high")
                        })

                elif scan_type == "mcp_security" and "findings" in result:
                    for finding in result["findings"]:
                        all_findings.append({
                            "type": "mcp_security",
                            "severity": finding.get("severity", "medium"),
                            "issue": finding.get("issue", ""),
                            "details": finding.get("details", {})
                        })

        # Prepare LLM prompt
        prompt = f"""Analyze these security findings and provide:
1. Risk assessment summary (critical/high/medium/low)
2. Top 5 priority issues to address
3. Categorized findings by type
4. Specific remediation steps for each priority issue
5. Overall security posture assessment

Findings:
{json.dumps(all_findings, indent=2)}

Project context:
- Path: {self.context.project_path}
- Has dependencies: {bool(self.context.dependency_files)}
- Has Dockerfile: {bool(self.context.dockerfiles)}
- Has MCP config: {self.context.has_mcp_config}
"""

        try:
            # Use safety advisor for analysis
            # Convert findings to a string format for safety advisor
            findings_summary = json.dumps(all_findings, indent=2)
            safety_assessment = await self.safety_advisor.assess_operation(
                operation_type="security_analysis",
                operation_details={"findings": findings_summary},
                context=prompt
            )

            # Extract risk level from assessment
            risk_level = "high"  # Default
            assessment_text = safety_assessment.get("assessment", "")
            if isinstance(assessment_text, str):
                if "critical" in assessment_text.lower():
                    risk_level = "critical"
                elif "high" in assessment_text.lower():
                    risk_level = "high"
                elif "medium" in assessment_text.lower():
                    risk_level = "medium"
                elif "low" in assessment_text.lower():
                    risk_level = "low"

            return {
                "risk_level": risk_level,
                "analysis": str(safety_assessment.get("assessment", "")),
                "recommendations": safety_assessment.get("recommendations", []) if isinstance(safety_assessment.get("recommendations", []), list) else [],
                "finding_count": len(all_findings)
            }
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            # Fallback to basic analysis
            return self._basic_analysis(all_findings)

    def _basic_analysis(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Basic analysis without LLM."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Determine overall risk
        if severity_counts["critical"] > 0:
            risk_level = "critical"
        elif severity_counts["high"] > 2:
            risk_level = "high"
        elif severity_counts["medium"] > 5:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "risk_level": risk_level,
            "analysis": f"Found {len(findings)} security issues",
            "severity_breakdown": severity_counts,
            "recommendations": ["Address critical and high severity issues first"],
            "finding_count": len(findings)
        }

    def _generate_comprehensive_report(self, scan_results: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
        """Generate the final comprehensive security report."""
        duration = (datetime.now() - self.context.start_time).total_seconds()

        report = {
            "status": "complete",
            "executive_summary": {
                "overall_risk": analysis["risk_level"],
                "total_findings": analysis["finding_count"],
                "scan_duration_seconds": duration,
                "project_path": str(self.context.project_path),
                "scans_performed": list(self.context.scan_results.keys())
            },
            "detailed_findings": scan_results,
            "analysis": analysis,
            "recommendations": analysis.get("recommendations", []),
            "conversation_summary": {
                "questions_asked": len(self.context.questions_asked),
                "user_confirmations": self.context.user_responses
            },
            "timestamp": datetime.now().isoformat()
        }

        return report
