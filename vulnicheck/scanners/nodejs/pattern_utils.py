"""Utility functions for building and executing security pattern queries.

This module provides helper functions for working with the security patterns
defined in ``patterns.py``, including tree-sitter query construction, simple
taint flow analysis, user-input heuristics, and MCP tool description extraction.

These utilities bridge the gap between the declarative pattern definitions
and the runtime AST analysis performed by the ``ASTEngine``.

Usage::

    from vulnicheck.scanners.nodejs.pattern_utils import (
        build_tree_sitter_query,
        check_taint_flow,
        extract_tool_description,
        is_user_controlled,
        run_pattern_against_ast,
    )

    engine = ASTEngine()
    ast = engine.parse(source_code, language="typescript")

    # Run a specific pattern category
    query = build_tree_sitter_query("RCE")
    matches = engine.query(ast, query)

    # Extract MCP tool descriptions
    tools = extract_tool_descriptions(ast, engine)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import tree_sitter as ts

from .ast_engine import ASTEngine, ParsedAST, QueryMatch
from .models import SecurityFinding
from .patterns import (
    ALL_PATTERNS,
    DATA_EXFILTRATION_PATTERNS,
    INSECURE_DESERIALIZATION_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    RCE_PATTERNS,
    SUPPLY_CHAIN_PATTERNS,
    UNAUTHORIZED_ACCESS_PATTERNS,
    PatternCategory,
    SecurityPattern,
    Severity,
    contains_suspicious_unicode,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum description length before flagging as suspicious (PI-004)
MAX_DESCRIPTION_LENGTH = 2000

# Patterns indicating user-controlled data sources
_USER_INPUT_PATTERNS: frozenset[str] = frozenset({
    "req.body", "req.query", "req.params", "req.headers",
    "request.body", "request.query", "request.params", "request.headers",
    "args", "input", "userInput", "user_input",
    "params", "payload", "data", "formData",
    "event.body", "event.data", "ctx.request.body",
})

# Sensitive function/method names that indicate dangerous operations
_SENSITIVE_OPERATIONS: frozenset[str] = frozenset({
    "exec", "execSync", "execFile", "execFileSync",
    "spawn", "spawnSync", "fork",
    "eval", "Function",
    "writeFile", "writeFileSync", "appendFile", "appendFileSync",
    "unlink", "unlinkSync", "rmdir", "rmdirSync",
    "fetch", "request", "post", "get", "put", "delete",
})

# Pattern category name to pattern list mapping
_CATEGORY_MAP: dict[str, list[SecurityPattern]] = {
    "RCE": RCE_PATTERNS,
    "PROMPT_INJECTION": PROMPT_INJECTION_PATTERNS,
    "DATA_EXFILTRATION": DATA_EXFILTRATION_PATTERNS,
    "SUPPLY_CHAIN": SUPPLY_CHAIN_PATTERNS,
    "UNAUTHORIZED_ACCESS": UNAUTHORIZED_ACCESS_PATTERNS,
    "INSECURE_DESERIALIZATION": INSECURE_DESERIALIZATION_PATTERNS,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class MCPToolDefinition:
    """Represents a parsed MCP server.tool() definition.

    Attributes:
        tool_name: The registered tool name (first string argument).
        description: The tool description (second string argument).
        schema_text: Source text of the Zod schema argument.
        handler_text: Source text of the handler function body.
        line: 1-based line number where the tool is defined.
        column: 0-based column offset.
        node: The underlying tree-sitter call_expression node.
    """

    tool_name: str
    description: str
    schema_text: str = ""
    handler_text: str = ""
    line: int = 0
    column: int = 0
    node: ts.Node | None = field(default=None, repr=False)


@dataclass
class TaintPath:
    """Represents a data flow path from source to sink.

    Attributes:
        source_node: The AST node where tainted data originates.
        sink_node: The AST node where tainted data is consumed.
        intermediate_nodes: Any nodes the data passes through.
        source_text: Source code text of the origin.
        sink_text: Source code text of the consumption point.
        confidence: How confident we are in this taint path.
    """

    source_node: ts.Node
    sink_node: ts.Node
    intermediate_nodes: list[ts.Node] = field(default_factory=list)
    source_text: str = ""
    sink_text: str = ""
    confidence: str = "medium"


# ---------------------------------------------------------------------------
# Query building
# ---------------------------------------------------------------------------


def build_tree_sitter_query(pattern_type: str) -> str:
    """Build a combined tree-sitter query from all patterns of a given type.

    Takes all patterns in the specified category and concatenates their
    tree-sitter queries into a single multi-pattern query string. Each
    individual pattern query is kept as a separate pattern within the
    combined query so that match results can be correlated back to the
    originating rule.

    Args:
        pattern_type: Category name to build queries for. One of:
            ``"RCE"``, ``"PROMPT_INJECTION"``, ``"DATA_EXFILTRATION"``,
            ``"SUPPLY_CHAIN"``, ``"UNAUTHORIZED_ACCESS"``,
            ``"INSECURE_DESERIALIZATION"``, or ``"ALL"`` for everything.

    Returns:
        A combined S-expression query string suitable for passing to
        ``ASTEngine.query()``. Individual patterns are separated by
        newline for readability.

    Raises:
        ValueError: If *pattern_type* is not a recognized category.

    Example::

        query = build_tree_sitter_query("RCE")
        matches = engine.query(ast, query)
    """
    pattern_type_upper = pattern_type.upper()

    if pattern_type_upper == "ALL":
        patterns = ALL_PATTERNS
    elif pattern_type_upper in _CATEGORY_MAP:
        patterns = _CATEGORY_MAP[pattern_type_upper]
    else:
        valid = ", ".join(sorted(_CATEGORY_MAP.keys()))
        raise ValueError(
            f"Unknown pattern type: {pattern_type!r}. "
            f"Valid types: {valid}, ALL"
        )

    # Combine all query strings, each on its own line block
    query_parts: list[str] = []
    for pattern in patterns:
        query_text = pattern.tree_sitter_query.strip()
        if query_text:
            # Add a comment with the rule_id for traceability
            query_parts.append(
                f"; {pattern.rule_id}: {pattern.name}\n{query_text}"
            )

    return "\n\n".join(query_parts)


def build_single_pattern_query(pattern: SecurityPattern) -> str:
    """Return the tree-sitter query string for a single pattern.

    This is a convenience wrapper that returns the pattern's query
    after minimal validation.

    Args:
        pattern: The SecurityPattern whose query to return.

    Returns:
        The tree-sitter S-expression query string.
    """
    return pattern.tree_sitter_query.strip()


# ---------------------------------------------------------------------------
# Taint flow analysis
# ---------------------------------------------------------------------------


def check_taint_flow(
    ast: ParsedAST,
    source_node: ts.Node,
    sink_node: ts.Node,
) -> bool:
    """Check if there is a data flow path from source_node to sink_node.

    This performs a simplified intra-procedural taint analysis by:
    1. Extracting the variable name(s) at the source
    2. Walking the AST between source and sink
    3. Tracking assignments and references to those variables
    4. Checking if any tracked variable reaches the sink

    This is a heuristic approach -- it does NOT perform full inter-procedural
    analysis, alias tracking, or handle complex control flow. It is designed
    to catch the most common patterns with acceptable false-positive rates.

    Args:
        ast: The parsed AST containing both nodes.
        source_node: The node where potentially tainted data originates
            (e.g., ``req.body``, ``process.env.SECRET``).
        sink_node: The node where data is consumed dangerously
            (e.g., ``eval()``, ``exec()``, ``fetch()``).

    Returns:
        ``True`` if a plausible data flow path exists between the
        source and sink, ``False`` otherwise.
    """
    # Quick spatial check: source must appear before sink in the file
    if source_node.start_byte >= sink_node.start_byte:
        return False

    # Extract variable names from the source
    source_vars = _extract_variable_names(ast, source_node)
    if not source_vars:
        # If we cannot determine variable names, assume possible flow
        # when they are in the same function scope
        return _in_same_function_scope(source_node, sink_node)

    # Walk from source to sink and track variable propagation
    tainted_vars: set[str] = set(source_vars)

    # Find the nearest common ancestor (function scope)
    scope_node = _find_common_scope(source_node, sink_node)
    if scope_node is None:
        return False

    # Scan all nodes between source and sink for assignments that
    # propagate taint
    found_flow = False

    def _visitor(node: ts.Node, _depth: int) -> bool | None:
        nonlocal found_flow

        if node.start_byte < source_node.start_byte:
            return None  # Skip nodes before source
        if node.start_byte >= sink_node.start_byte:
            return False  # Stop at sink

        # Track variable assignments: const x = tainted;
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node and value_node:
                value_text = ast.get_text(value_node)
                if any(var in value_text for var in tainted_vars):
                    new_name = ast.get_text(name_node)
                    tainted_vars.add(new_name)

        # Track assignment expressions: x = tainted;
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right:
                right_text = ast.get_text(right)
                if any(var in right_text for var in tainted_vars):
                    tainted_vars.add(ast.get_text(left))

        return None

    ast._walk_recursive(scope_node, _visitor, depth=0)

    # Check if any tainted variable appears in the sink
    sink_text = ast.get_text(sink_node)
    return any(var in sink_text for var in tainted_vars)


def find_taint_paths(
    ast: ParsedAST,
    engine: ASTEngine,
    source_patterns: list[str] | None = None,
    sink_patterns: list[str] | None = None,
) -> list[TaintPath]:
    """Find all taint flow paths from user-controlled sources to sinks.

    This is a higher-level function that identifies sources and sinks
    automatically, then checks each pair for data flow.

    Args:
        ast: The parsed AST to analyze.
        engine: The ASTEngine for query execution.
        source_patterns: Optional list of additional source identifiers
            to consider as user-controlled. Merged with defaults.
        sink_patterns: Optional list of additional sink function names
            to check. Merged with defaults.

    Returns:
        A list of ``TaintPath`` objects describing each detected flow.
    """
    paths: list[TaintPath] = []

    # Identify source nodes (user input)
    sources: list[ts.Node] = []
    _collect_user_input_nodes(ast, sources)

    # Identify sink nodes (dangerous functions)
    sinks: list[ts.Node] = []
    _collect_dangerous_sink_nodes(ast, engine, sinks)

    # Check each source-sink pair
    for source in sources:
        for sink in sinks:
            if check_taint_flow(ast, source, sink):
                paths.append(
                    TaintPath(
                        source_node=source,
                        sink_node=sink,
                        source_text=ast.get_text(source),
                        sink_text=ast.get_text(sink),
                        confidence="medium",
                    )
                )

    return paths


# ---------------------------------------------------------------------------
# User-controlled input detection
# ---------------------------------------------------------------------------


def is_user_controlled(node: ts.Node, ast: ParsedAST) -> bool:
    """Heuristic check whether an AST node represents user-controlled data.

    This function checks if the given node's text matches known patterns
    for user-controlled data sources. It uses both exact identifier matches
    and structural patterns (e.g., ``req.body.X``, ``args.X``).

    This is a conservative heuristic -- it may produce false positives
    for variables that happen to share names with common input patterns.
    The intent is to flag code for human review, not to provide a definitive
    taint analysis.

    Args:
        node: The AST node to check.
        ast: The ParsedAST the node belongs to.

    Returns:
        ``True`` if the node likely represents user-controlled input.

    Examples of user-controlled patterns:
        - ``req.body``, ``req.query``, ``req.params``
        - ``args`` (common in MCP tool handlers)
        - ``process.argv``
        - ``event.body`` (Lambda/serverless)
        - Any variable whose assignment can be traced to the above
    """
    node_text = ast.get_text(node)

    # Direct match against known patterns
    if node_text in _USER_INPUT_PATTERNS:
        return True

    # Check for pattern prefixes (e.g., req.body.username)
    for pattern in _USER_INPUT_PATTERNS:
        if node_text.startswith(pattern + ".") or node_text.startswith(pattern + "["):
            return True

    # Check for process.argv access
    if "process.argv" in node_text:
        return True

    # Check for common parameter names in function signatures
    # In MCP handlers, the first parameter (usually 'args') is user input
    if node.type == "identifier":
        identifier_text = node_text
        if identifier_text in {"args", "input", "userInput", "params", "payload"}:
            return True

    # Member expressions like obj.field where obj is user-controlled
    if node.type == "member_expression":
        obj_node = node.child_by_field_name("object")
        if obj_node is not None:
            return is_user_controlled(obj_node, ast)

    # Subscript expressions like obj[key] where obj is user-controlled
    if node.type == "subscript_expression":
        obj_node = node.child_by_field_name("object")
        if obj_node is not None:
            return is_user_controlled(obj_node, ast)

    return False


# ---------------------------------------------------------------------------
# MCP tool description extraction
# ---------------------------------------------------------------------------


def extract_tool_description(node: ts.Node, ast: ParsedAST) -> str:
    """Extract the description string from a server.tool() call node.

    Given a ``call_expression`` node representing a ``server.tool()`` call
    (as used in the MCP SDK / FastMCP), extract the second argument which
    is typically the tool's description string.

    MCP tool registration follows this pattern::

        server.tool(
          'tool_name',           // 1st arg: name
          "Tool description",    // 2nd arg: description
          { ...schema },         // 3rd arg: Zod schema
          async (args) => { },   // 4th arg: handler
        );

    Args:
        node: A ``call_expression`` node.
        ast: The ParsedAST containing the node.

    Returns:
        The description string content (without quotes), or an empty
        string if the description could not be extracted.
    """
    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return ""

    # Collect named (non-punctuation) arguments
    named_args: list[ts.Node] = [
        child for child in args_node.children if child.is_named
    ]

    if len(named_args) < 2:
        return ""

    desc_node = named_args[1]
    return _extract_string_value(desc_node, ast)


def extract_tool_descriptions(
    ast: ParsedAST,
    engine: ASTEngine,
) -> list[MCPToolDefinition]:
    """Extract all MCP tool definitions from the given AST.

    Searches for ``server.tool()`` call patterns and extracts the
    name, description, schema, and handler for each registered tool.

    Args:
        ast: The parsed AST to search.
        engine: The ASTEngine for query execution.

    Returns:
        A list of ``MCPToolDefinition`` objects, one per tool found.
    """
    pattern = """
    (call_expression
      function: (member_expression
        object: (_) @server_obj
        property: (property_identifier) @method_name)
      arguments: (arguments) @args
      (#eq? @method_name "tool")) @call
    """

    tools: list[MCPToolDefinition] = []

    try:
        matches = engine.query(ast, pattern.strip())
    except ts.QueryError as exc:
        logger.warning("Failed to query for MCP tools: %s", exc)
        return tools

    for match in matches:
        call_nodes = match.captures.get("call", [])
        args_nodes = match.captures.get("args", [])

        if not call_nodes or not args_nodes:
            continue

        call_node = call_nodes[0]
        args_node = args_nodes[0]

        # Extract named children from arguments
        named_args: list[ts.Node] = [
            child for child in args_node.children if child.is_named
        ]

        tool_name = ""
        description = ""
        schema_text = ""
        handler_text = ""

        if len(named_args) >= 1:
            tool_name = _extract_string_value(named_args[0], ast)
        if len(named_args) >= 2:
            description = _extract_string_value(named_args[1], ast)
        if len(named_args) >= 3:
            schema_text = ast.get_text(named_args[2])
        if len(named_args) >= 4:
            handler_text = ast.get_text(named_args[3])

        tools.append(
            MCPToolDefinition(
                tool_name=tool_name,
                description=description,
                schema_text=schema_text,
                handler_text=handler_text,
                line=call_node.start_point.row + 1,
                column=call_node.start_point.column,
                node=call_node,
            )
        )

    return tools


# ---------------------------------------------------------------------------
# Pattern execution and finding generation
# ---------------------------------------------------------------------------


def run_pattern_against_ast(
    pattern: SecurityPattern,
    ast: ParsedAST,
    engine: ASTEngine,
    file_path: str = "<unknown>",
) -> list[SecurityFinding]:
    """Execute a single security pattern against an AST and return findings.

    This function handles both tree-sitter-query-based detection and
    any required post-processing (e.g., Unicode checks for PI-002,
    length checks for PI-004).

    Args:
        pattern: The security pattern to execute.
        ast: The parsed AST to analyze.
        engine: The ASTEngine for query execution.
        file_path: Path to the source file (for reporting).

    Returns:
        A list of ``SecurityFinding`` objects for each match.
    """
    findings: list[SecurityFinding] = []
    query_text = pattern.tree_sitter_query.strip()

    if not query_text:
        return findings

    try:
        matches = engine.query(ast, query_text)
    except ts.QueryError as exc:
        logger.debug(
            "Query failed for pattern %s: %s", pattern.rule_id, exc
        )
        return findings

    for match in matches:
        # Determine the primary node for location reporting
        primary_node = _get_primary_node(match)
        if primary_node is None:
            continue

        line = primary_node.start_point.row + 1
        column = primary_node.start_point.column
        code_snippet = ast.get_text(primary_node)

        # Apply pattern-specific post-processing
        if not _passes_post_processing(pattern, match, ast):
            continue

        findings.append(
            SecurityFinding(
                rule_id=pattern.rule_id,
                severity=pattern.severity.value.lower(),
                category=pattern.category.value.lower().replace(" ", "_"),
                title=pattern.name,
                description=pattern.description,
                file_path=file_path,
                line=line,
                column=column,
                code_snippet=_truncate(code_snippet, 500),
                recommendation=pattern.remediation,
                confidence=_determine_confidence(pattern, match, ast),
                cwe_id=pattern.cwe_ids[0] if pattern.cwe_ids else None,
            )
        )

    return findings


def run_all_patterns(
    ast: ParsedAST,
    engine: ASTEngine,
    file_path: str = "<unknown>",
    categories: list[str] | None = None,
    min_severity: Severity = Severity.LOW,
) -> list[SecurityFinding]:
    """Run all (or filtered) security patterns against an AST.

    Args:
        ast: The parsed AST to analyze.
        engine: The ASTEngine for query execution.
        file_path: Path to the source file (for reporting).
        categories: Optional list of category names to run. If ``None``,
            all categories are run.
        min_severity: Minimum severity level to include in results.

    Returns:
        A list of ``SecurityFinding`` objects, sorted by severity
        (critical first) then line number.
    """
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    min_order = severity_order.get(min_severity, 3)

    patterns_to_run: list[SecurityPattern]
    if categories is not None:
        patterns_to_run = []
        for cat_name in categories:
            cat_patterns = _CATEGORY_MAP.get(cat_name.upper(), [])
            patterns_to_run.extend(cat_patterns)
    else:
        patterns_to_run = ALL_PATTERNS

    # Filter by minimum severity
    patterns_to_run = [
        p for p in patterns_to_run
        if severity_order.get(p.severity, 4) <= min_order
    ]

    all_findings: list[SecurityFinding] = []
    for pattern in patterns_to_run:
        try:
            findings = run_pattern_against_ast(
                pattern, ast, engine, file_path
            )
            all_findings.extend(findings)
        except Exception:
            logger.debug(
                "Error running pattern %s against %s",
                pattern.rule_id,
                file_path,
                exc_info=True,
            )

    # Sort by severity (critical first), then by line number
    all_findings.sort(
        key=lambda f: (
            severity_order.get(
                Severity(f.severity.upper()), 4
            ),
            f.line,
        )
    )

    return all_findings


# ---------------------------------------------------------------------------
# MCP-specific analysis helpers
# ---------------------------------------------------------------------------


def analyze_mcp_tool_descriptions(
    ast: ParsedAST,
    engine: ASTEngine,
    file_path: str = "<unknown>",
) -> list[SecurityFinding]:
    """Analyze all MCP tool descriptions for prompt injection risks.

    This function extracts tool definitions and runs all prompt injection
    patterns against their descriptions, plus additional heuristic checks
    that go beyond what tree-sitter queries alone can detect:

    - Hidden Unicode characters (PI-002)
    - Excessive description length (PI-004)
    - Suspicious instruction patterns in parameter descriptions (PI-007)

    Args:
        ast: The parsed AST containing MCP tool definitions.
        engine: The ASTEngine for query execution.
        file_path: Path to the source file (for reporting).

    Returns:
        A list of ``SecurityFinding`` objects for any detected issues.
    """
    findings: list[SecurityFinding] = []
    tools = extract_tool_descriptions(ast, engine)

    for tool in tools:
        # Check for hidden Unicode characters (PI-002)
        unicode_issues = contains_suspicious_unicode(tool.description)
        if unicode_issues:
            chars_desc = ", ".join(
                f"U+{issue['codepoint']:04X} ({issue['category']})"
                for issue in unicode_issues
            )
            findings.append(
                SecurityFinding(
                    rule_id="PI-002",
                    severity="high",
                    category="prompt_injection_in_mcp_tools",
                    title="Hidden Unicode characters in tool description",
                    description=(
                        f"Tool '{tool.tool_name}' description contains "
                        f"invisible Unicode characters that could hide "
                        f"malicious instructions: {chars_desc}"
                    ),
                    file_path=file_path,
                    line=tool.line,
                    column=tool.column,
                    code_snippet=_truncate(tool.description, 200),
                    recommendation=(
                        "Strip all non-printable and zero-width Unicode "
                        "characters from tool descriptions."
                    ),
                    confidence="high",
                    cwe_id="CWE-74",
                )
            )

        # Check for excessive description length (PI-004)
        if len(tool.description) > MAX_DESCRIPTION_LENGTH:
            findings.append(
                SecurityFinding(
                    rule_id="PI-004",
                    severity="medium",
                    category="prompt_injection_in_mcp_tools",
                    title="Excessively long tool description",
                    description=(
                        f"Tool '{tool.tool_name}' has a description of "
                        f"{len(tool.description)} characters (threshold: "
                        f"{MAX_DESCRIPTION_LENGTH}). Long descriptions may "
                        f"hide malicious instructions."
                    ),
                    file_path=file_path,
                    line=tool.line,
                    column=tool.column,
                    code_snippet=_truncate(tool.description, 200) + "...",
                    recommendation=(
                        "Keep tool descriptions under 500 characters. "
                        "Review long descriptions for hidden instructions."
                    ),
                    confidence="medium",
                    cwe_id="CWE-74",
                )
            )

        # Check for instruction override patterns in description (PI-001)
        injection_patterns = [
            (
                r"(?i)(ignore|disregard|forget)\s+(all\s+)?"
                r"(previous|prior|above)\s+(instructions?|rules?|context)",
                "instruction override",
            ),
            (
                r"(?i)(you must|you should always|you are required to)",
                "behavioral directive",
            ),
            (
                r"(?i)^(system:|assistant:|human:|user:|\[INST\])",
                "role boundary marker",
            ),
            (
                r"(?i)<\|?(system|endoftext|startoftext)\|?>",
                "special token attempt",
            ),
            (
                r"(?i)IMPORTANT:\s*(override|ignore|always|never)",
                "importance-prefixed override",
            ),
        ]

        for regex, desc_label in injection_patterns:
            if re.search(regex, tool.description):
                findings.append(
                    SecurityFinding(
                        rule_id="PI-001",
                        severity="critical",
                        category="prompt_injection_in_mcp_tools",
                        title=f"Instruction override in tool description ({desc_label})",
                        description=(
                            f"Tool '{tool.tool_name}' description contains "
                            f"a {desc_label} pattern that could manipulate "
                            f"LLM behavior."
                        ),
                        file_path=file_path,
                        line=tool.line,
                        column=tool.column,
                        code_snippet=_truncate(tool.description, 200),
                        recommendation=(
                            "Remove instruction-like language from tool "
                            "descriptions. Descriptions should only describe "
                            "the tool's functionality."
                        ),
                        confidence="high",
                        cwe_id="CWE-74",
                    )
                )
                break  # One finding per tool for PI-001

        # Check for tool-chaining instructions (PI-005)
        chaining_pattern = (
            r"(?i)(after|before|then|also|must)\s+"
            r"(call|invoke|use|execute|run)\s+"
            r"(the\s+)?([\w_]+)\s+(tool|function|command)"
        )
        if re.search(chaining_pattern, tool.description):
            findings.append(
                SecurityFinding(
                    rule_id="PI-005",
                    severity="high",
                    category="prompt_injection_in_mcp_tools",
                    title="Tool description instructs calling other tools",
                    description=(
                        f"Tool '{tool.tool_name}' description contains "
                        f"instructions for the LLM to call other tools, "
                        f"which enables tool-chaining attacks."
                    ),
                    file_path=file_path,
                    line=tool.line,
                    column=tool.column,
                    code_snippet=_truncate(tool.description, 200),
                    recommendation=(
                        "Tool descriptions should not instruct the LLM "
                        "to call other tools. Tool orchestration should be "
                        "handled by application logic."
                    ),
                    confidence="high",
                    cwe_id="CWE-74",
                )
            )

        # Check for external URL references for instructions (PI-003)
        url_instruction_pattern = (
            r"(?i)(https?://|ftp://)\S+"
            r".*(instructions?|config|rules?|prompts?|behaviors?)"
        )
        if re.search(url_instruction_pattern, tool.description):
            findings.append(
                SecurityFinding(
                    rule_id="PI-003",
                    severity="high",
                    category="prompt_injection_in_mcp_tools",
                    title="External URL reference in tool description",
                    description=(
                        f"Tool '{tool.tool_name}' description references "
                        f"an external URL in the context of instructions "
                        f"or configuration, enabling dynamic injection."
                    ),
                    file_path=file_path,
                    line=tool.line,
                    column=tool.column,
                    code_snippet=_truncate(tool.description, 200),
                    recommendation=(
                        "Tool descriptions must be self-contained. Do not "
                        "reference external URLs for behavioral instructions."
                    ),
                    confidence="high",
                    cwe_id="CWE-74",
                )
            )

        # Check for embedded structured data (PI-006)
        structured_patterns = [
            (r'\{\s*"(role|system|instruction|prompt|action)"', "embedded JSON"),
            (r"<(system|instruction|config|rules)>", "embedded XML"),
            (r"^---\s*\n", "embedded YAML frontmatter"),
        ]
        for regex, struct_type in structured_patterns:
            if re.search(regex, tool.description):
                findings.append(
                    SecurityFinding(
                        rule_id="PI-006",
                        severity="high",
                        category="prompt_injection_in_mcp_tools",
                        title=f"Embedded structured data in tool description ({struct_type})",
                        description=(
                            f"Tool '{tool.tool_name}' description contains "
                            f"{struct_type} that could be interpreted as "
                            f"structured instructions by the LLM."
                        ),
                        file_path=file_path,
                        line=tool.line,
                        column=tool.column,
                        code_snippet=_truncate(tool.description, 200),
                        recommendation=(
                            "Tool descriptions should be plain text without "
                            "embedded JSON, XML, or YAML structures."
                        ),
                        confidence="medium",
                        cwe_id="CWE-74",
                    )
                )
                break  # One finding per tool for PI-006

    return findings


def analyze_tool_handler_security(
    ast: ParsedAST,
    engine: ASTEngine,
    file_path: str = "<unknown>",
) -> list[SecurityFinding]:
    """Analyze MCP tool handler functions for security issues.

    Checks handler bodies for:
    - Network calls that could indicate data exfiltration
    - File operations that could access unexpected paths
    - Missing authorization checks before sensitive operations
    - Environment variable access for secrets

    Args:
        ast: The parsed AST containing MCP tool definitions.
        engine: The ASTEngine for query execution.
        file_path: Path to the source file (for reporting).

    Returns:
        A list of ``SecurityFinding`` objects.
    """
    findings: list[SecurityFinding] = []
    tools = extract_tool_descriptions(ast, engine)

    # Network function patterns (exfiltration indicators)
    network_re = re.compile(
        r"\b(fetch|axios|got|request|http\.request|https\.request"
        r"|net\.connect|dgram\.createSocket)\s*\("
    )

    # Authorization check patterns
    auth_re = re.compile(
        r"(?i)(auth|permission|isAdmin|isAuthorized|checkAuth"
        r"|verifyToken|requireAuth|authorize|forbidden|unauthorized"
        r"|context\.user|context\.auth)"
    )

    # Sensitive operations that should have auth checks
    sensitive_op_re = re.compile(
        r"\b(unlink|rmdir|writeFile|exec|spawn|fork)\s*\("
    )

    # Secret env var access
    secret_env_re = re.compile(
        r"process\.env\.(.*?(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE).*?)\b"
    )

    for tool in tools:
        handler = tool.handler_text
        if not handler:
            continue

        # Check for network calls in handler (EXFIL-001 refinement)
        network_match = network_re.search(handler)
        if network_match:
            findings.append(
                SecurityFinding(
                    rule_id="EXFIL-001",
                    severity="high",
                    category="data_exfiltration",
                    title=f"Network call in tool handler '{tool.tool_name}'",
                    description=(
                        f"Tool '{tool.tool_name}' handler makes a network "
                        f"call ({network_match.group(1)}), which could be "
                        f"used for data exfiltration."
                    ),
                    file_path=file_path,
                    line=tool.line,
                    code_snippet=_truncate(handler, 300),
                    recommendation=(
                        "Review network calls in tool handlers. If "
                        "necessary, use domain allowlists."
                    ),
                    confidence="medium",
                    cwe_id="CWE-200",
                )
            )

        # Check for sensitive ops without auth (UA-001 refinement)
        if sensitive_op_re.search(handler) and not auth_re.search(handler):
            findings.append(
                SecurityFinding(
                    rule_id="UA-001",
                    severity="high",
                    category="unauthorized_access",
                    title=f"Missing auth check in tool '{tool.tool_name}'",
                    description=(
                        f"Tool '{tool.tool_name}' performs sensitive "
                        f"operations without visible authorization checks."
                    ),
                    file_path=file_path,
                    line=tool.line,
                    code_snippet=_truncate(handler, 300),
                    recommendation=(
                        "Add authorization checks before sensitive "
                        "operations in tool handlers."
                    ),
                    confidence="medium",
                    cwe_id="CWE-862",
                )
            )

        # Check for secret env var access (UA-003 refinement)
        env_match = secret_env_re.search(handler)
        if env_match:
            var_name = env_match.group(1)
            findings.append(
                SecurityFinding(
                    rule_id="UA-003",
                    severity="high",
                    category="unauthorized_access",
                    title=f"Secret access in tool '{tool.tool_name}'",
                    description=(
                        f"Tool '{tool.tool_name}' handler accesses "
                        f"secret environment variable '{var_name}'."
                    ),
                    file_path=file_path,
                    line=tool.line,
                    code_snippet=_truncate(handler, 300),
                    recommendation=(
                        "Tool handlers should not access secrets directly. "
                        "Use a configuration layer with least privilege."
                    ),
                    confidence="high",
                    cwe_id="CWE-798",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _extract_string_value(node: ts.Node, ast: ParsedAST) -> str:
    """Extract the string content from a string node, stripping quotes.

    Handles both regular strings and template strings (without
    substitutions).
    """
    if node.type == "string":
        # Find the string_fragment child
        for child in node.children:
            if child.type == "string_fragment":
                return ast.get_text(child)
        # Fallback: strip surrounding quotes
        text = ast.get_text(node)
        if len(text) >= 2 and text[0] in ('"', "'", "`"):
            return text[1:-1]
        return text

    if node.type == "template_string":
        # For template strings without substitutions, concatenate fragments
        parts: list[str] = []
        for child in node.children:
            if child.type == "string_fragment":
                parts.append(ast.get_text(child))
            elif child.type == "template_substitution":
                # Has interpolation -- return raw text
                text = ast.get_text(node)
                return text[1:-1] if text.startswith("`") else text
        return "".join(parts)

    # Not a string node -- return raw text
    return ast.get_text(node)


def _extract_variable_names(
    ast: ParsedAST, node: ts.Node
) -> list[str]:
    """Extract variable names referenced by a node.

    For identifiers, returns the name directly. For member expressions
    like ``req.body``, returns both ``req`` and ``req.body``. For
    destructuring, returns all extracted names.
    """
    names: list[str] = []
    text = ast.get_text(node)

    if node.type == "identifier":
        names.append(text)
    elif node.type == "member_expression":
        names.append(text)
        # Also track the full chain and the leaf
        parts = text.split(".")
        for i in range(1, len(parts) + 1):
            names.append(".".join(parts[:i]))
    elif node.type == "subscript_expression":
        obj_node = node.child_by_field_name("object")
        if obj_node:
            names.append(ast.get_text(obj_node))
    else:
        # Fallback: use full text as a name
        if text and not text.startswith(("(", "{", "[")):
            names.append(text)

    return names


def _in_same_function_scope(
    node_a: ts.Node, node_b: ts.Node
) -> bool:
    """Check if two nodes are in the same function scope."""
    scope_a = _find_enclosing_function(node_a)
    scope_b = _find_enclosing_function(node_b)
    if scope_a is None or scope_b is None:
        # If either is at module level, consider them in same scope
        return scope_a is scope_b
    return scope_a.id == scope_b.id


def _find_enclosing_function(node: ts.Node) -> ts.Node | None:
    """Walk up the AST to find the nearest enclosing function node."""
    function_types = frozenset({
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
    })
    current = node.parent
    while current is not None:
        if current.type in function_types:
            return current
        current = current.parent
    return None


def _find_common_scope(
    node_a: ts.Node, node_b: ts.Node
) -> ts.Node | None:
    """Find the nearest common ancestor that is a function or the root."""
    ancestors_a: set[int] = set()
    current: ts.Node | None = node_a
    while current is not None:
        ancestors_a.add(current.id)
        current = current.parent

    current = node_b
    while current is not None:
        if current.id in ancestors_a:
            return current
        current = current.parent

    return None


def _collect_user_input_nodes(
    ast: ParsedAST, out: list[ts.Node]
) -> None:
    """Collect all AST nodes that represent user-controlled input."""

    def _visitor(node: ts.Node, _depth: int) -> None:
        if is_user_controlled(node, ast):
            out.append(node)

    ast.walk(_visitor)


def _collect_dangerous_sink_nodes(
    ast: ParsedAST,
    engine: ASTEngine,
    out: list[ts.Node],
) -> None:
    """Collect all AST nodes that represent dangerous operation sinks."""
    calls = engine.find_function_calls(ast)
    for call in calls:
        if call.name in _SENSITIVE_OPERATIONS:
            # We need the original node -- find it by position
            nodes = engine.find_nodes_by_type(ast, "call_expression")
            for node in nodes:
                if (
                    node.start_point.row + 1 == call.line
                    and node.start_point.column == call.column
                ):
                    out.append(node)
                    break


def _get_primary_node(match: QueryMatch) -> ts.Node | None:
    """Determine the primary reporting node from a query match.

    Prefers nodes captured as @call, @func_name, @method, or the
    first available capture.
    """
    preferred_captures = [
        "call", "func_name", "method", "method_name",
        "constructor_name", "obj", "suspicious_path",
        "tool_description", "tool_name",
    ]
    for name in preferred_captures:
        nodes = match.captures.get(name, [])
        if nodes:
            return nodes[0]

    # Fallback: return first capture
    for nodes in match.captures.values():
        if nodes:
            return nodes[0]
    return None


def _passes_post_processing(
    pattern: SecurityPattern,
    match: QueryMatch,
    ast: ParsedAST,
) -> bool:
    """Apply pattern-specific post-processing checks.

    Some patterns require additional validation beyond what tree-sitter
    queries can express. This function implements those checks.

    Returns ``True`` if the match should be reported, ``False`` to
    suppress it.
    """
    # PI-002: Check for actual Unicode issues in description
    if pattern.rule_id == "PI-002":
        desc_nodes = match.captures.get("tool_description", [])
        if desc_nodes:
            desc_text = ast.get_text(desc_nodes[0])
            return len(contains_suspicious_unicode(desc_text)) > 0
        return False

    # PI-004: Check for excessive length
    if pattern.rule_id == "PI-004":
        desc_nodes = match.captures.get("tool_description", [])
        if desc_nodes:
            desc_text = ast.get_text(desc_nodes[0])
            return len(desc_text) > MAX_DESCRIPTION_LENGTH
        return False

    return True


def _determine_confidence(
    pattern: SecurityPattern,
    match: QueryMatch,
    ast: ParsedAST,
) -> str:
    """Determine confidence level for a finding.

    Higher confidence is assigned when:
    - The sink uses user-controlled input (verified taint)
    - The pattern is specific (e.g., exact function name match)

    Lower confidence when:
    - The match could be a false positive (generic patterns)
    """
    # EXFIL and IPC patterns are often context-dependent
    if pattern.rule_id in {"EXFIL-006", "DESER-005"}:
        return "low"

    # Direct eval/exec with non-literal input is high confidence
    if pattern.rule_id in {"RCE-001", "RCE-002", "RCE-003", "RCE-004"}:
        return "high"

    # Prototype pollution patterns are high confidence
    if pattern.rule_id in {"DESER-003", "DESER-004"}:
        return "high"

    # Prompt injection patterns detected via regex are high confidence
    if pattern.category == PatternCategory.PROMPT_INJECTION:
        return "high"

    return "medium"


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len characters, adding ellipsis if needed."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
