# Node.js/TypeScript Static Analysis Architecture

## 1. Overview

This document describes the architecture for adding TypeScript and JavaScript static
analysis to VulniCheck. The primary goal of this first iteration is MCP skill
analysis: detecting security-relevant patterns in TS/JS source code that could
indicate remote code execution, prompt injection, data exfiltration, or supply chain
risks. All analysis runs in Python using tree-sitter bindings -- there is no
Node.js runtime dependency for core analysis.

The design follows the conventions established by the existing scanner modules
(`DependencyScanner`, `DockerScanner`, `SecretsScanner`, `GitHubRepoScanner`) and
integrates with the same `FileProvider` abstraction, `UnifiedScanner` zip handling,
and `@mcp.tool` registration patterns.

---

## 2. Module Structure

```
vulnicheck/
  scanners/
    __init__.py                    # Updated: export NodeJSScanner
    nodejs/
      __init__.py                  # Package exports
      scanner.py                   # NodeJSScanner -- top-level orchestrator
      ast_analyzer.py              # TreeSitterAnalyzer -- parse + query engine
      patterns.py                  # SecurityPatternRegistry -- pattern definitions
      models.py                    # Pydantic data models
      dependency_parser.py         # Parse package.json, package-lock.json, yarn.lock
      mcp_skill_analyzer.py        # MCPSkillAnalyzer -- MCP-specific analysis logic

tests/
  test_nodejs_scanner.py           # Unit tests for NodeJSScanner
  test_nodejs_ast_analyzer.py      # Unit tests for tree-sitter analysis
  test_nodejs_patterns.py          # Unit tests for pattern matching
  test_nodejs_models.py            # Unit tests for data models
  test_nodejs_dependency_parser.py # Unit tests for dependency parsing
  test_nodejs_mcp_skill_analyzer.py # Unit tests for MCP skill analysis
```

### File Responsibilities

**`vulnicheck/scanners/nodejs/__init__.py`**

Package-level exports. Follows the pattern in `vulnicheck/scanners/__init__.py` and
`vulnicheck/security/__init__.py`.

```python
"""Node.js and TypeScript static analysis for security pattern detection."""

from .models import (
    ASTMatch,
    DependencyInfo,
    MCPSkillAnalysisResult,
    NodeJSScanResult,
    SecurityFinding,
    SecurityPatternCategory,
    SeverityLevel,
)
from .scanner import NodeJSScanner

__all__ = [
    "NodeJSScanner",
    "NodeJSScanResult",
    "SecurityFinding",
    "ASTMatch",
    "DependencyInfo",
    "MCPSkillAnalysisResult",
    "SecurityPatternCategory",
    "SeverityLevel",
]
```

**`vulnicheck/scanners/nodejs/scanner.py`** -- `NodeJSScanner`

Top-level orchestrator. Analogous to `DockerScanner` and `GitHubRepoScanner`.
Accepts file paths or content via `FileProvider`, delegates to `TreeSitterAnalyzer`
for AST queries and `DependencyParser` for manifest parsing.

**`vulnicheck/scanners/nodejs/ast_analyzer.py`** -- `TreeSitterAnalyzer`

Encapsulates all tree-sitter operations: loading grammars, parsing source to syntax
trees, executing S-expression queries, and returning structured match results.
Single responsibility: turn source code + query into `ASTMatch` objects.

**`vulnicheck/scanners/nodejs/patterns.py`** -- `SecurityPatternRegistry`

Defines and organizes tree-sitter query patterns by security category (RCE, prompt
injection, data exfiltration, supply chain). Patterns are stored as data, not logic.
The registry provides lookup by category and severity.

**`vulnicheck/scanners/nodejs/models.py`** -- Pydantic data models

All data transfer objects. Follows the pattern established by
`vulnicheck/clients/osv_client.py` (which defines the `Vulnerability` Pydantic model)
and the dataclasses in `vulnicheck/scanners/github_scanner.py` (`ScanConfig`,
`GitHubRepoInfo`). Uses Pydantic `BaseModel` for serialization compatibility with
MCP tool responses.

**`vulnicheck/scanners/nodejs/dependency_parser.py`** -- `DependencyParser`

Parses `package.json`, `package-lock.json`, and `yarn.lock` to extract npm
dependencies with versions. Analogous to the `_parse_requirements`,
`_parse_pyproject`, and `_parse_lock_file` methods in
`vulnicheck/scanners/scanner.py`.

**`vulnicheck/scanners/nodejs/mcp_skill_analyzer.py`** -- `MCPSkillAnalyzer`

MCP-specific analysis that composes `TreeSitterAnalyzer` results with domain
knowledge about MCP tool patterns, permission models, and trust boundaries. This is
the high-value first-iteration target.

---

## 3. Data Models

All models live in `vulnicheck/scanners/nodejs/models.py`. They follow the Pydantic
`BaseModel` pattern used by `Vulnerability` in `osv_client.py` and use
`Field(default_factory=...)` for mutable defaults, matching existing convention.

```python
"""Data models for Node.js/TypeScript static analysis."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Severity levels for security findings.

    Matches the severity vocabulary used throughout VulniCheck:
    CRITICAL/HIGH/MEDIUM/LOW as seen in DockerScanner.severity_summary,
    SecretsScanner.get_secret_severity, and GitHubRepoScanner._generate_summary.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SecurityPatternCategory(str, Enum):
    """Categories of security patterns to detect."""
    RCE = "rce"
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    SUPPLY_CHAIN = "supply_chain"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    PATH_TRAVERSAL = "path_traversal"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    MCP_TRUST_BOUNDARY = "mcp_trust_boundary"


class ASTMatch(BaseModel):
    """A single match from a tree-sitter query against source code."""
    file_path: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    matched_text: str
    capture_name: str
    pattern_id: str
    context_lines: list[str] = Field(default_factory=list)


class SecurityPattern(BaseModel):
    """Definition of a security pattern to detect via tree-sitter."""
    id: str
    name: str
    description: str
    category: SecurityPatternCategory
    severity: SeverityLevel
    query: str  # tree-sitter S-expression query
    languages: list[str] = Field(default_factory=lambda: ["javascript", "typescript"])
    cwe_ids: list[str] = Field(default_factory=list)
    capture_name: str = "target"  # which capture in the query is the finding
    false_positive_hints: list[str] = Field(default_factory=list)


class SecurityFinding(BaseModel):
    """A security finding produced by pattern analysis."""
    pattern_id: str
    pattern_name: str
    category: SecurityPatternCategory
    severity: SeverityLevel
    description: str
    file_path: str
    start_line: int
    end_line: int
    matched_text: str
    cwe_ids: list[str] = Field(default_factory=list)
    recommendation: str = ""
    confidence: float = 1.0  # 0.0 to 1.0, reduced for heuristic matches
    context_lines: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Follows the pattern established by SecretsScanResult.to_dict() in
        vulnicheck/scanners/secrets_scanner.py.
        """
        return self.model_dump()


class DependencyInfo(BaseModel):
    """Parsed dependency information from package.json or lock files."""
    name: str
    version_spec: str
    resolved_version: str | None = None
    is_dev_dependency: bool = False
    source_file: str = ""


class FileAnalysisResult(BaseModel):
    """Analysis result for a single file."""
    file_path: str
    language: str  # "javascript" or "typescript"
    findings: list[SecurityFinding] = Field(default_factory=list)
    parse_errors: list[str] = Field(default_factory=list)
    lines_analyzed: int = 0


class MCPSkillAnalysisResult(BaseModel):
    """Result of analyzing an MCP skill/tool implementation.

    Captures both the structural analysis (what tools are exposed, what
    capabilities they claim) and the security analysis (what risks exist).
    """
    skill_name: str
    description: str = ""
    exposed_tools: list[str] = Field(default_factory=list)
    declared_permissions: list[str] = Field(default_factory=list)
    actual_capabilities: list[str] = Field(default_factory=list)
    permission_mismatches: list[str] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    trust_boundary_violations: list[str] = Field(default_factory=list)
    risk_summary: str = ""
    overall_risk_level: SeverityLevel = SeverityLevel.INFO

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return self.model_dump()


class NodeJSScanResult(BaseModel):
    """Top-level result from a Node.js/TypeScript scan.

    Structure mirrors the dict-based results used by DockerScanner and
    GitHubRepoScanner, but with Pydantic validation.
    """
    files_scanned: int = 0
    files_with_findings: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = Field(
        default_factory=lambda: {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
    )
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    file_results: list[FileAnalysisResult] = Field(default_factory=list)
    dependencies: list[DependencyInfo] = Field(default_factory=list)
    mcp_analysis: MCPSkillAnalysisResult | None = None
    scan_type: str = "nodejs_static_analysis"
    scanner_version: str = "0.1.0"
    parse_errors: list[str] = Field(default_factory=list)

    @property
    def severity_summary(self) -> dict[str, int]:
        """Alias for findings_by_severity.

        Named to match DockerScanner's severity_summary field.
        """
        return self.findings_by_severity

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return self.model_dump()
```

---

## 4. Class Hierarchy and Method Signatures

### 4.1 NodeJSScanner

Top-level scanner. Follows the same constructor signature pattern as `DockerScanner`:
accepts an optional vulnerability scanner for npm dependency checking and an optional
`FileProvider`.

```python
"""Node.js and TypeScript static analysis scanner."""

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ...providers import FileProvider, LocalFileProvider
from ...providers.base import FileNotFoundError as ProviderFileNotFoundError
from ...providers.base import FileProviderError
from .ast_analyzer import TreeSitterAnalyzer
from .dependency_parser import DependencyParser
from .mcp_skill_analyzer import MCPSkillAnalyzer
from .models import (
    FileAnalysisResult,
    MCPSkillAnalysisResult,
    NodeJSScanResult,
    SecurityFinding,
    SeverityLevel,
)
from .patterns import SecurityPatternRegistry

if TYPE_CHECKING:
    from ..scanner import DependencyScanner

logger = logging.getLogger(__name__)


class NodeJSScanner:
    """Scans TypeScript and JavaScript files for security patterns.

    Architecture:
    - Uses FileProvider for file I/O (matching DockerScanner, SecretsScanner)
    - Delegates AST parsing to TreeSitterAnalyzer
    - Delegates pattern definitions to SecurityPatternRegistry
    - Delegates MCP analysis to MCPSkillAnalyzer
    - Delegates dependency parsing to DependencyParser
    """

    # File extensions to analyze
    JS_EXTENSIONS: set[str] = {".js", ".mjs", ".cjs"}
    TS_EXTENSIONS: set[str] = {".ts", ".mts", ".cts", ".tsx", ".jsx"}
    ALL_EXTENSIONS: set[str] = JS_EXTENSIONS | TS_EXTENSIONS

    # Directories to skip during scanning
    EXCLUDED_DIRS: set[str] = {
        "node_modules", ".git", "dist", "build", ".next",
        "coverage", ".nyc_output", "__pycache__",
    }

    MAX_FILE_SIZE: int = 1024 * 1024  # 1MB per file
    MAX_FILES: int = 2000

    def __init__(
        self,
        scanner: "DependencyScanner | None" = None,
        file_provider: FileProvider | None = None,
    ) -> None:
        """Initialize Node.js scanner.

        Args:
            scanner: Optional DependencyScanner for npm vulnerability checks.
            file_provider: FileProvider instance for file operations.
                          Defaults to LocalFileProvider for backward compatibility.
        """
        self.scanner = scanner
        self.file_provider = file_provider or LocalFileProvider()
        self.ast_analyzer = TreeSitterAnalyzer()
        self.pattern_registry = SecurityPatternRegistry()
        self.dependency_parser = DependencyParser(self.file_provider)
        self.mcp_skill_analyzer = MCPSkillAnalyzer(self.ast_analyzer, self.pattern_registry)

    async def scan_file(self, file_path: str) -> FileAnalysisResult:
        """Scan a single JS/TS file for security patterns.

        Args:
            file_path: Path to the file to scan.

        Returns:
            FileAnalysisResult with any findings.

        Raises:
            FileNotFoundError: If file does not exist.
            ValueError: If file is too large or has unsupported extension.
        """
        ...

    async def scan_directory(
        self,
        directory_path: str,
        recursive: bool = True,
        include_dependencies: bool = True,
    ) -> NodeJSScanResult:
        """Scan a directory of JS/TS files for security patterns.

        Args:
            directory_path: Directory to scan.
            recursive: Whether to scan recursively.
            include_dependencies: Whether to parse and analyze package.json.

        Returns:
            Aggregated NodeJSScanResult.
        """
        ...

    async def scan_content(
        self,
        content: str,
        filename: str = "untitled.ts",
    ) -> FileAnalysisResult:
        """Scan source content directly without reading from disk.

        Args:
            content: Source code content.
            filename: Name used to determine language (JS vs TS).

        Returns:
            FileAnalysisResult with any findings.
        """
        ...

    async def analyze_mcp_skill(
        self,
        directory_path: str | None = None,
        content: str | None = None,
        filename: str | None = None,
    ) -> MCPSkillAnalysisResult:
        """Analyze a directory or file as an MCP skill implementation.

        This is the primary entry point for MCP tool analysis. It combines
        AST-based pattern detection with MCP-specific heuristics.

        Args:
            directory_path: Path to MCP skill directory.
            content: Source content (alternative to directory_path).
            filename: Filename when using content mode.

        Returns:
            MCPSkillAnalysisResult with tool inventory and risk assessment.
        """
        ...

    def _detect_language(self, file_path: str) -> str:
        """Determine language from file extension.

        Returns:
            "javascript" or "typescript"
        """
        ...

    async def _collect_files(
        self,
        directory_path: str,
        recursive: bool = True,
    ) -> list[str]:
        """Collect JS/TS files from directory using FileProvider.

        Follows the pattern in SecretsScanner._collect_files_async.
        Respects EXCLUDED_DIRS, MAX_FILE_SIZE, and MAX_FILES limits.
        """
        ...

    def _aggregate_results(
        self,
        file_results: list[FileAnalysisResult],
    ) -> NodeJSScanResult:
        """Aggregate per-file results into a scan-level result.

        Follows DockerScanner's pattern of building severity_summary dicts.
        """
        ...
```

### 4.2 TreeSitterAnalyzer

```python
"""Tree-sitter based AST analysis for JavaScript and TypeScript."""

import logging
from typing import Any

from .models import ASTMatch, SecurityPattern

logger = logging.getLogger(__name__)


class TreeSitterAnalyzer:
    """Parses JS/TS source code and executes tree-sitter queries.

    This class encapsulates all tree-sitter operations to keep the
    grammar-loading and query-compilation details out of the scanner.
    """

    def __init__(self) -> None:
        """Initialize analyzer and load language grammars lazily."""
        self._js_language: Any | None = None
        self._ts_language: Any | None = None
        self._parser: Any | None = None
        self._query_cache: dict[tuple[str, str], Any] = {}

    def _ensure_initialized(self, language: str) -> None:
        """Lazily initialize tree-sitter parser and language.

        Follows VulniCheck's lazy initialization pattern seen in
        server.py _ensure_clients_initialized().

        Args:
            language: "javascript" or "typescript"
        """
        ...

    def parse(self, source: str, language: str) -> Any:
        """Parse source code into a tree-sitter syntax tree.

        Args:
            source: Source code text.
            language: "javascript" or "typescript".

        Returns:
            tree-sitter Tree object.

        Raises:
            ValueError: If language is not supported.
        """
        ...

    def query(
        self,
        source: str,
        language: str,
        pattern: SecurityPattern,
    ) -> list[ASTMatch]:
        """Run a tree-sitter query against source code.

        Args:
            source: Source code text.
            language: "javascript" or "typescript".
            pattern: SecurityPattern containing the S-expression query.

        Returns:
            List of ASTMatch objects for each capture match.
        """
        ...

    def query_all(
        self,
        source: str,
        language: str,
        patterns: list[SecurityPattern],
    ) -> list[ASTMatch]:
        """Run multiple queries against the same source.

        Parses the source once and runs all queries against the resulting
        tree. More efficient than calling query() per pattern.

        Args:
            source: Source code text.
            language: "javascript" or "typescript".
            patterns: List of patterns to match.

        Returns:
            Combined list of ASTMatch objects across all patterns.
        """
        ...

    def extract_function_names(self, source: str, language: str) -> list[str]:
        """Extract all top-level function/method names from source.

        Useful for building a tool inventory in MCP skill analysis.

        Args:
            source: Source code text.
            language: "javascript" or "typescript".

        Returns:
            List of function names.
        """
        ...

    def extract_exports(self, source: str, language: str) -> list[str]:
        """Extract exported identifiers from source.

        Args:
            source: Source code text.
            language: "javascript" or "typescript".

        Returns:
            List of exported identifiers.
        """
        ...
```

### 4.3 SecurityPatternRegistry

```python
"""Security pattern definitions for JS/TS static analysis."""

from .models import SecurityPattern, SecurityPatternCategory, SeverityLevel


class SecurityPatternRegistry:
    """Registry of security patterns organized by category.

    Patterns are defined as tree-sitter S-expression queries. The registry
    provides lookup by category, severity, and language.
    """

    def __init__(self) -> None:
        """Initialize registry with all built-in patterns."""
        self._patterns: list[SecurityPattern] = []
        self._register_builtin_patterns()

    def get_all(self) -> list[SecurityPattern]:
        """Return all registered patterns."""
        ...

    def get_by_category(
        self,
        category: SecurityPatternCategory,
    ) -> list[SecurityPattern]:
        """Return patterns for a specific category."""
        ...

    def get_by_severity(
        self,
        min_severity: SeverityLevel,
    ) -> list[SecurityPattern]:
        """Return patterns at or above a severity threshold."""
        ...

    def get_for_language(self, language: str) -> list[SecurityPattern]:
        """Return patterns applicable to a specific language."""
        ...

    def _register_builtin_patterns(self) -> None:
        """Register all built-in security patterns.

        See Section 5 for the full pattern catalog.
        """
        ...
```

### 4.4 DependencyParser

```python
"""Parse Node.js dependency manifests."""

import json
import logging
from typing import Any

from ...providers.base import FileProvider, FileProviderError
from .models import DependencyInfo

logger = logging.getLogger(__name__)


class DependencyParser:
    """Parses package.json and lock files for dependency information.

    Follows the parsing pattern established by DependencyScanner._parse_requirements,
    _parse_pyproject, and _parse_lock_file in vulnicheck/scanners/scanner.py.
    Uses FileProvider for all file I/O.
    """

    def __init__(self, file_provider: FileProvider) -> None:
        self.file_provider = file_provider

    async def parse_package_json(self, file_path: str) -> list[DependencyInfo]:
        """Parse package.json for dependencies.

        Extracts from both 'dependencies' and 'devDependencies' fields.

        Args:
            file_path: Path to package.json.

        Returns:
            List of DependencyInfo objects.
        """
        ...

    async def parse_package_lock(self, file_path: str) -> list[DependencyInfo]:
        """Parse package-lock.json for resolved dependency versions.

        Args:
            file_path: Path to package-lock.json.

        Returns:
            List of DependencyInfo with resolved_version populated.
        """
        ...

    async def parse_yarn_lock(self, file_path: str) -> list[DependencyInfo]:
        """Parse yarn.lock for resolved dependency versions.

        Args:
            file_path: Path to yarn.lock.

        Returns:
            List of DependencyInfo with resolved_version populated.
        """
        ...

    async def find_and_parse(self, directory_path: str) -> list[DependencyInfo]:
        """Find and parse dependency files in a directory.

        Checks for package.json first, then augments with lock file data
        if available. Follows the pattern in DependencyScanner._find_lock_versions.

        Args:
            directory_path: Directory to search.

        Returns:
            List of DependencyInfo.
        """
        ...
```

### 4.5 MCPSkillAnalyzer

```python
"""MCP skill-specific analysis for Node.js/TypeScript implementations."""

import logging
from typing import Any

from .ast_analyzer import TreeSitterAnalyzer
from .models import (
    ASTMatch,
    FileAnalysisResult,
    MCPSkillAnalysisResult,
    SecurityFinding,
    SecurityPatternCategory,
    SeverityLevel,
)
from .patterns import SecurityPatternRegistry

logger = logging.getLogger(__name__)


class MCPSkillAnalyzer:
    """Analyzes MCP skill implementations for security risks.

    Combines tree-sitter AST analysis with MCP-domain heuristics:
    - Detects tool definitions (server.tool(), server.addTool())
    - Maps declared permissions to actual code capabilities
    - Identifies trust boundary violations
    - Checks for unsafe input handling in tool parameters
    """

    # Patterns indicating MCP SDK usage
    MCP_SDK_INDICATORS: list[str] = [
        "@modelcontextprotocol/sdk",
        "@anthropic-ai/sdk",
        "fastmcp",
        "mcp-framework",
    ]

    def __init__(
        self,
        ast_analyzer: TreeSitterAnalyzer,
        pattern_registry: SecurityPatternRegistry,
    ) -> None:
        self.ast_analyzer = ast_analyzer
        self.pattern_registry = pattern_registry

    def analyze(
        self,
        file_results: list[FileAnalysisResult],
        source_map: dict[str, str],
    ) -> MCPSkillAnalysisResult:
        """Analyze file results in the context of MCP skill semantics.

        Args:
            file_results: Per-file analysis results from TreeSitterAnalyzer.
            source_map: Mapping of file_path -> source content for further
                        inspection of MCP-specific structures.

        Returns:
            MCPSkillAnalysisResult with tool inventory and risk assessment.
        """
        ...

    def _detect_tool_definitions(
        self,
        source: str,
        language: str,
    ) -> list[dict[str, Any]]:
        """Find MCP tool/skill definitions in source.

        Detects patterns like:
        - server.tool("name", schema, handler)
        - server.setRequestHandler(ListToolsRequestSchema, ...)
        - export const tool = { name: ..., handler: ... }

        Returns:
            List of tool definition dicts with name, line, handler info.
        """
        ...

    def _detect_capabilities(
        self,
        source: str,
        language: str,
    ) -> list[str]:
        """Detect actual capabilities used in source code.

        Looks for filesystem access, network calls, subprocess execution,
        environment variable access, and other capability indicators.

        Returns:
            List of capability strings (e.g., "filesystem_read",
            "network_outbound", "subprocess_exec").
        """
        ...

    def _check_trust_boundaries(
        self,
        tool_definitions: list[dict[str, Any]],
        findings: list[SecurityFinding],
    ) -> list[str]:
        """Check for trust boundary violations in tool implementations.

        Identifies cases where user-controlled input flows into dangerous
        operations without sanitization.

        Returns:
            List of violation descriptions.
        """
        ...

    def _assess_overall_risk(
        self,
        findings: list[SecurityFinding],
        permission_mismatches: list[str],
        trust_violations: list[str],
    ) -> SeverityLevel:
        """Determine overall risk level for the MCP skill.

        Logic:
        - Any CRITICAL finding -> CRITICAL
        - Any HIGH finding or trust boundary violation -> HIGH
        - Permission mismatches alone -> MEDIUM
        - Only LOW/INFO findings -> LOW
        - No findings -> INFO
        """
        ...
```

---

## 5. Pattern Definitions

Patterns are organized by `SecurityPatternCategory`. Each pattern is a tree-sitter
S-expression query. The `@target` capture marks the node that constitutes the finding.

### 5.1 RCE Patterns

| Pattern ID | Name | Query Description | Severity | CWE |
|---|---|---|---|---|
| `rce-eval` | Dynamic eval | `eval()` call with non-literal argument | CRITICAL | CWE-95 |
| `rce-function-constructor` | Function constructor | `new Function(...)` | CRITICAL | CWE-95 |
| `rce-child-process` | Child process exec | `exec()`, `execSync()`, `spawn()` with string arg | HIGH | CWE-78 |
| `rce-vm-runin` | VM context exec | `vm.runInNewContext()`, `vm.runInThisContext()` | HIGH | CWE-94 |
| `rce-require-expression` | Dynamic require | `require()` with non-literal argument | MEDIUM | CWE-94 |
| `rce-dynamic-import` | Dynamic import | `import()` with non-literal argument | MEDIUM | CWE-94 |

Example tree-sitter query for `rce-eval`:

```scheme
(call_expression
  function: (identifier) @fn_name
  arguments: (arguments
    (identifier) @target)
  (#eq? @fn_name "eval"))
```

### 5.2 Prompt Injection Patterns

| Pattern ID | Name | Query Description | Severity | CWE |
|---|---|---|---|---|
| `pi-unsanitized-template` | Unsanitized template literal | Template literal using user input in prompt context | HIGH | CWE-74 |
| `pi-string-concat-prompt` | Prompt concatenation | String concatenation building prompts from external data | HIGH | CWE-74 |
| `pi-tool-description-dynamic` | Dynamic tool description | Tool descriptions built from runtime data | MEDIUM | CWE-74 |
| `pi-system-prompt-injection` | System prompt with user data | System prompt templates incorporating user-controlled values | CRITICAL | CWE-74 |

Example tree-sitter query for `pi-unsanitized-template`:

```scheme
(template_string
  (template_substitution
    (member_expression
      object: (identifier) @obj
      property: (property_identifier) @prop))
  (#match? @obj "req|request|params|query|body|input|args"))
```

### 5.3 Data Exfiltration Patterns

| Pattern ID | Name | Query Description | Severity | CWE |
|---|---|---|---|---|
| `exfil-fetch-dynamic` | Dynamic fetch URL | `fetch()` with variable/concatenated URL | HIGH | CWE-918 |
| `exfil-http-request` | Outbound HTTP | `http.request()`, `https.request()` | MEDIUM | CWE-918 |
| `exfil-axios-dynamic` | Dynamic axios call | axios with non-literal URL | HIGH | CWE-918 |
| `exfil-env-in-response` | Env vars in response | `process.env` values returned in tool response | HIGH | CWE-200 |
| `exfil-fs-read-response` | File content in response | File read results returned without sanitization | MEDIUM | CWE-200 |
| `exfil-dns-lookup` | DNS-based exfiltration | DNS lookups with dynamic subdomains | HIGH | CWE-918 |

### 5.4 Supply Chain Patterns

| Pattern ID | Name | Query Description | Severity | CWE |
|---|---|---|---|---|
| `sc-postinstall-script` | Postinstall script | package.json `postinstall` or `preinstall` scripts | MEDIUM | CWE-829 |
| `sc-install-script-exec` | Install script exec | Shell commands in install lifecycle scripts | HIGH | CWE-78 |
| `sc-dynamic-dependency` | Dynamic dependency loading | Runtime `require`/`import` of packages from external source | HIGH | CWE-829 |
| `sc-unpinned-dependency` | Unpinned dependency | Dependencies without locked versions | LOW | CWE-829 |

### 5.5 MCP Trust Boundary Patterns

| Pattern ID | Name | Query Description | Severity | CWE |
|---|---|---|---|---|
| `mcp-tool-no-validation` | No input validation | Tool handler without parameter validation | MEDIUM | CWE-20 |
| `mcp-tool-shell-passthrough` | Shell passthrough tool | Tool that passes input to shell commands | CRITICAL | CWE-78 |
| `mcp-tool-fs-traversal` | Path traversal in tool | Tool accepting file paths without normalization | HIGH | CWE-22 |
| `mcp-tool-unrestricted-network` | Unrestricted network tool | Tool making network requests to user-specified URLs | HIGH | CWE-918 |
| `mcp-tool-privilege-escalation` | Privilege escalation | Tool granting capabilities beyond declared permissions | CRITICAL | CWE-269 |
| `mcp-tool-response-injection` | Response injection | Tool response containing unsanitized external data | MEDIUM | CWE-74 |

---

## 6. Tree-sitter Usage

### 6.1 Python Bindings

The analysis uses the `tree-sitter` Python package (v0.23+) with pre-built language
bindings via `tree-sitter-javascript` and `tree-sitter-typescript`. These packages
provide compiled grammars that work directly with the tree-sitter Python API without
requiring a separate build step or Node.js.

### 6.2 Grammar Loading

```python
import tree_sitter_javascript as ts_js
import tree_sitter_typescript as ts_ts
from tree_sitter import Language, Parser

# Load languages from pre-built packages
JS_LANGUAGE = Language(ts_js.language())
TS_LANGUAGE = Language(ts_ts.language_typescript())
TSX_LANGUAGE = Language(ts_ts.language_tsx())

# Create parser and set language
parser = Parser()
parser.language = JS_LANGUAGE  # or TS_LANGUAGE for .ts files
```

### 6.3 Query Execution Pattern

```python
from tree_sitter import Parser, Language

def execute_query(
    source: str,
    language: Language,
    query_string: str,
) -> list[tuple]:
    """Execute a tree-sitter query and return matches."""
    parser = Parser()
    parser.language = language

    tree = parser.parse(source.encode("utf-8"))
    query = language.query(query_string)

    # captures() returns list of (node, capture_name) tuples
    captures = query.captures(tree.root_node)
    return captures
```

### 6.4 Query Caching

Compiled queries are cached by `(query_string, language_name)` tuple in the
`TreeSitterAnalyzer._query_cache` dict. This avoids recompiling the same query
for each file during a directory scan. This follows the same caching-for-performance
approach as `@lru_cache` decorators used elsewhere in VulniCheck.

### 6.5 Handling TypeScript-Specific Syntax

TypeScript requires the `tree-sitter-typescript` grammar, which handles type
annotations, interfaces, enums, generics, and other TS-specific constructs that
are absent from the JavaScript grammar. The `TreeSitterAnalyzer` selects the
appropriate grammar based on file extension:

- `.js`, `.mjs`, `.cjs` -> `ts_js.language()`
- `.jsx` -> `ts_js.language()` (JSX is supported by the JS grammar)
- `.ts`, `.mts`, `.cts` -> `ts_ts.language_typescript()`
- `.tsx` -> `ts_ts.language_tsx()`

### 6.6 Error Handling for Parse Failures

Tree-sitter is error-tolerant: it produces partial syntax trees even for
syntactically invalid files. The analyzer records parse errors (nodes with
`has_error` set) in `FileAnalysisResult.parse_errors` but still runs queries
against the partial tree. This avoids failing an entire scan because of one
malformed file.

---

## 7. Integration Points

### 7.1 Server Tool Registration

Two new tools are added to `vulnicheck/server.py`, following the existing
`@mcp.tool` decorator pattern with `Annotated[..., Field(...)]` parameters:

```python
@mcp.tool
async def scan_nodejs_security(
    directory_path: Annotated[
        str | None,
        Field(description="Path to directory containing JS/TS files to scan"),
    ] = None,
    file_content: Annotated[
        str | None,
        Field(description="Content of a JS/TS file to scan directly"),
    ] = None,
    file_name: Annotated[
        str | None,
        Field(description="Filename (e.g., 'index.ts') when using file_content"),
    ] = None,
    zip_content: Annotated[
        str | None,
        Field(description="Base64 encoded zip file containing JS/TS files to scan"),
    ] = None,
    include_mcp_analysis: Annotated[
        bool,
        Field(description="Run MCP skill-specific analysis in addition to general patterns"),
    ] = True,
) -> str:
    """Scan JavaScript/TypeScript code for security patterns.

    USE THIS TOOL WHEN:
    - You need to analyze JS/TS source code for security vulnerabilities
    - You want to audit an MCP skill implementation
    - The user asks about security of a Node.js project or MCP server

    DO NOT USE THIS TOOL FOR:
    - Checking npm package vulnerabilities by name (use check_package_vulnerabilities)
    - Scanning Python code (use scan_dependencies or scan_for_secrets)
    - Dockerfile analysis (use scan_dockerfile)

    INPUT OPTIONS (specify exactly one):
    - directory_path: Scan all JS/TS files in a directory
    - file_content + file_name: Scan a single file's content
    - zip_content: Scan files in a base64-encoded zip archive

    Detects: RCE, prompt injection, data exfiltration, supply chain risks,
    unsafe deserialization, path traversal, and MCP trust boundary violations.

    IMPORTANT: Analysis results are provided 'AS IS' without warranty."""
    ...


@mcp.tool
async def analyze_mcp_skill(
    directory_path: Annotated[
        str | None,
        Field(description="Path to MCP skill/server directory"),
    ] = None,
    file_content: Annotated[
        str | None,
        Field(description="Content of the MCP skill entry point file"),
    ] = None,
    file_name: Annotated[
        str | None,
        Field(description="Filename (e.g., 'index.ts') when using file_content"),
    ] = None,
    zip_content: Annotated[
        str | None,
        Field(description="Base64 encoded zip of the MCP skill project"),
    ] = None,
) -> str:
    """Analyze an MCP skill/server implementation for security risks.

    USE THIS TOOL WHEN:
    - You want to audit an MCP server before trusting it
    - You need to assess the security posture of an MCP tool
    - The user asks whether an MCP skill is safe to use

    Performs deep analysis of:
    - Tool definitions and their declared vs actual capabilities
    - Permission model compliance
    - Trust boundary integrity
    - Input validation coverage
    - Data flow from user input to dangerous operations

    IMPORTANT: Analysis results are provided 'AS IS' without warranty."""
    ...
```

### 7.2 Scanner Init in `__init__.py`

Update `vulnicheck/scanners/__init__.py`:

```python
"""Scanners for analyzing dependencies, secrets, Docker files, GitHub repositories, and Node.js."""

from .docker_scanner import DockerScanner
from .github_scanner import GitHubRepoScanner
from .nodejs import NodeJSScanner
from .scanner import DependencyScanner
from .secrets_scanner import SecretsScanner

__all__ = [
    "DependencyScanner",
    "SecretsScanner",
    "DockerScanner",
    "GitHubRepoScanner",
    "NodeJSScanner",
]
```

### 7.3 Client Initialization in `server.py`

Add to the global lazy-init block in `_ensure_clients_initialized()`:

```python
nodejs_scanner = None  # Added alongside docker_scanner, github_scanner

# Inside _ensure_clients_initialized():
from .scanners.nodejs import NodeJSScanner
nodejs_scanner = NodeJSScanner(
    scanner=scanner_with_provider,
    file_provider=client_file_provider,
)
```

This follows the same pattern as `docker_scanner` and `github_scanner` initialization:
- Lazy, only when first tool call arrives
- Uses the appropriate `FileProvider`
- Receives an optional `DependencyScanner` for vulnerability cross-referencing

### 7.4 UnifiedScanner (Zip Support)

The `UnifiedScanner` in `vulnicheck/core/unified_scanner.py` needs a new scan type.
Add to the `_prepare_zip_input` method's scan-type-specific context:

```python
elif scan_type == "nodejs":
    context["js_ts_files"] = await self.zip_handler.find_files_by_extension(
        extraction_path,
        extensions=[".js", ".ts", ".jsx", ".tsx", ".mjs", ".mts", ".cjs", ".cts"],
    )
    context["package_json_files"] = await self.zip_handler.find_files_by_name(
        extraction_path,
        names=["package.json"],
    )
```

This is a minor addition to an existing method, not a new abstraction, keeping the
change proportional.

### 7.5 GitHubRepoScanner Integration

`GitHubRepoScanner.scan_repository()` currently supports scan types `dependencies`,
`secrets`, and `dockerfile`. Add `nodejs` as a fourth scan type:

```python
if "nodejs" in scan_types:
    tasks.append(self._scan_nodejs(repo_path))
    scan_types_to_run.append("nodejs")
```

With a corresponding `_scan_nodejs` method following the same pattern as
`_scan_dependencies` and `_scan_dockerfiles`.

### 7.6 ComprehensiveSecurityCheck Integration

The comprehensive check's automatic discovery phase (in
`vulnicheck/security/comprehensive_security_check.py`) should detect JS/TS files
and offer Node.js scanning. This is a future integration after the core scanner
is stable.

### 7.7 FileProvider Usage

All file I/O goes through the `FileProvider` interface:
- `self.file_provider.read_file(path)` for reading source files
- `self.file_provider.find_files(dir, patterns=["*.ts", "*.js"], ...)` for discovery
- `self.file_provider.get_file_stats(path)` for size checks before parsing
- `self.file_provider.file_exists(path)` for checking package.json existence

This ensures the scanner works in both local and HTTP-only (MCP client-delegated)
deployment modes, matching the architecture described in the CLAUDE.md.

---

## 8. Dependencies

### 8.1 New Production Dependencies

Add to `pyproject.toml` `[project.dependencies]`:

```toml
dependencies = [
    # ... existing ...
    "tree-sitter>=0.23.0",
    "tree-sitter-javascript>=0.23.0",
    "tree-sitter-typescript>=0.23.0",
]
```

These packages provide:
- `tree-sitter`: Core parsing library with Python bindings (C extension, no runtime deps)
- `tree-sitter-javascript`: Pre-compiled JavaScript grammar (includes JSX support)
- `tree-sitter-typescript`: Pre-compiled TypeScript and TSX grammars

Total additional install size: approximately 5-8 MB. No Node.js runtime dependency.

### 8.2 mypy Override

Add to `pyproject.toml` `[[tool.mypy.overrides]]`:

```toml
[[tool.mypy.overrides]]
module = ["tree_sitter.*", "tree_sitter_javascript.*", "tree_sitter_typescript.*"]
ignore_missing_imports = true
```

This follows the existing override pattern for `mcp.*`, `fastmcp.*`, etc.

### 8.3 Docker Image

The `Dockerfile` needs no special changes beyond the pip install since tree-sitter
packages include pre-compiled wheels for Linux. No build tools or Node.js runtime
are required.

---

## 9. Testing Strategy

### 9.1 Test Organization

Tests follow the existing structure under `tests/`. Each test file mirrors a module:

| Test File | Module Under Test |
|---|---|
| `tests/test_nodejs_scanner.py` | `vulnicheck.scanners.nodejs.scanner` |
| `tests/test_nodejs_ast_analyzer.py` | `vulnicheck.scanners.nodejs.ast_analyzer` |
| `tests/test_nodejs_patterns.py` | `vulnicheck.scanners.nodejs.patterns` |
| `tests/test_nodejs_models.py` | `vulnicheck.scanners.nodejs.models` |
| `tests/test_nodejs_dependency_parser.py` | `vulnicheck.scanners.nodejs.dependency_parser` |
| `tests/test_nodejs_mcp_skill_analyzer.py` | `vulnicheck.scanners.nodejs.mcp_skill_analyzer` |

### 9.2 Test Patterns

Tests follow the conventions seen in `tests/test_docker_scanner.py`:

- Pytest fixtures for mock setup (`@pytest.fixture`)
- Class-based test grouping (`class TestNodeJSScanner:`)
- Mock `DependencyScanner` via `Mock(spec=DependencyScanner)`
- Inline test data (source code strings) rather than external fixture files
- Async tests use `pytest-asyncio` (`@pytest.mark.asyncio`)

Example test structure:

```python
"""Tests for Node.js static analysis scanner."""

from unittest.mock import AsyncMock, Mock

import pytest

from vulnicheck.scanners.nodejs import NodeJSScanner
from vulnicheck.scanners.nodejs.models import SeverityLevel


@pytest.fixture
def nodejs_scanner():
    """Create a NodeJSScanner instance without dependency scanner."""
    return NodeJSScanner()


class TestNodeJSScanner:
    """Test cases for NodeJSScanner."""

    @pytest.mark.asyncio
    async def test_scan_eval_detection(self, nodejs_scanner):
        """Test detection of eval() calls."""
        source = 'const result = eval(userInput);'
        result = await nodejs_scanner.scan_content(source, "test.js")
        assert len(result.findings) > 0
        assert result.findings[0].category.value == "rce"
        assert result.findings[0].severity == SeverityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_scan_safe_code(self, nodejs_scanner):
        """Test that safe code produces no findings."""
        source = 'const x = 1 + 2;\nconsole.log(x);'
        result = await nodejs_scanner.scan_content(source, "test.js")
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_scan_typescript_support(self, nodejs_scanner):
        """Test TypeScript-specific syntax is handled."""
        source = '''
        interface Config {
            command: string;
        }
        function run(config: Config): void {
            eval(config.command);
        }
        '''
        result = await nodejs_scanner.scan_content(source, "test.ts")
        assert len(result.findings) > 0
```

### 9.3 Makefile Target

Add to `Makefile`:

```makefile
.PHONY: test-nodejs
test-nodejs: ## Run Node.js scanner tests
	uv run pytest -v tests/test_nodejs*.py
```

---

## 10. Implementation Sequence

The recommended implementation order, from foundational to integrative:

1. **Models** (`models.py`) -- Define all data structures first. No external deps.
2. **Patterns** (`patterns.py`) -- Define pattern catalog. Depends only on models.
3. **AST Analyzer** (`ast_analyzer.py`) -- Implement tree-sitter integration. Depends on models. This is where the tree-sitter dependency is first exercised.
4. **Dependency Parser** (`dependency_parser.py`) -- Parse package.json/lock files. Depends on models and FileProvider.
5. **MCP Skill Analyzer** (`mcp_skill_analyzer.py`) -- MCP-specific logic. Depends on ast_analyzer, patterns, models.
6. **NodeJS Scanner** (`scanner.py`) -- Orchestrator. Composes all above components.
7. **Scanner `__init__.py`** -- Package exports and integration with `vulnicheck/scanners/__init__.py`.
8. **Server tools** -- Register `scan_nodejs_security` and `analyze_mcp_skill` in `server.py`.
9. **Tests** -- One test file per module, built alongside or immediately after each module.

---

## 11. Architectural Constraints and Decisions

### Why tree-sitter from Python, not a Node.js subprocess?

- Eliminates Node.js as a runtime dependency, keeping the Docker image smaller
- Avoids subprocess coordination, timeout management, and IPC serialization
- Tree-sitter Python bindings are mature and performant (C extension)
- Matches VulniCheck's pattern of doing all analysis in-process (contrast with
  `SecretsScanner` which shells out to `detect-secrets` -- that is an exception,
  not a pattern to replicate)

### Why a subpackage (`vulnicheck/scanners/nodejs/`) instead of a single file?

- The Node.js analysis has enough distinct concerns (AST parsing, pattern registry,
  dependency parsing, MCP skill analysis) to warrant separation
- Avoids a monolithic 1000+ line file
- Follows the precedent of `vulnicheck/mcp/` and `vulnicheck/security/` being
  subpackages with focused modules
- The `vulnicheck/scanners/` directory currently has flat files because each scanner
  is relatively self-contained; the Node.js scanner's complexity warrants a package

### Why Pydantic models instead of dataclasses?

- `osv_client.py` establishes Pydantic `BaseModel` as the pattern for structured data
  that gets serialized to JSON (which MCP tool responses require)
- `pydantic>=2.0.0` is already a project dependency
- Dataclasses are used in `github_scanner.py` (`ScanConfig`, `GitHubRepoInfo`) for
  configuration objects that are not serialized; the Node.js models are finding data
  that flows through MCP tool responses, so Pydantic is the right choice

### Async-first design

All public methods on `NodeJSScanner` are async, matching `DependencyScanner` and
the `@mcp.tool` async signatures. Tree-sitter operations themselves are synchronous
(CPU-bound C extension calls), but wrapping them in async methods keeps the interface
consistent and allows future parallelization (e.g., `asyncio.gather` across files).

### OSV ecosystem for npm

The existing `OSVClient.check_package` method accepts an `ecosystem` parameter
(defaulting to `"PyPI"`). For npm dependency vulnerability checking, pass
`ecosystem="npm"`:

```python
vulns = await self.osv_client.check_package(package_name, version, ecosystem="npm")
```

No new vulnerability client is needed -- OSV.dev already covers npm.
