"""Pydantic models for Node.js/TypeScript static analysis results.

This module defines the data models used to represent security findings
and analysis results from the AST-based TS/JS scanner.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SecurityFinding(BaseModel):
    """A single security finding from static analysis.

    Represents a potential vulnerability or security issue detected
    in TypeScript/JavaScript source code through AST pattern matching.

    Attributes:
        rule_id: Unique identifier for the detection rule (e.g., "RCE-001").
        severity: Risk severity level -- one of "critical", "high",
            "medium", "low", or "info".
        category: Broad category of the finding such as "rce",
            "prompt_injection", "data_exfiltration", or "supply_chain".
        title: Short human-readable title for the finding.
        description: Detailed explanation of the security issue.
        file_path: Path to the file where the finding was detected.
        line: 1-based line number of the finding.
        column: 0-based column offset of the finding.
        code_snippet: The relevant source code fragment.
        recommendation: Actionable remediation advice.
        confidence: Confidence level of the detection -- "high", "medium",
            or "low".
        cwe_id: Optional CWE (Common Weakness Enumeration) reference
            such as "CWE-78".
    """

    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    file_path: str
    line: int
    column: int = 0
    code_snippet: str = ""
    recommendation: str = ""
    confidence: str = "medium"
    cwe_id: str | None = None


class AnalysisResult(BaseModel):
    """Aggregated results from analyzing a project or set of files.

    Attributes:
        project_path: Root path of the analyzed project.
        files_analyzed: Total number of files that were parsed.
        findings: List of all security findings across all files.
        summary: Mapping of category names to finding counts.
        analysis_time_seconds: Wall-clock time spent on analysis.
    """

    project_path: str
    files_analyzed: int = 0
    findings: list[SecurityFinding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
    analysis_time_seconds: float = 0.0
