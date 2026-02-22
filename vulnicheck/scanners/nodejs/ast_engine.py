"""Core AST parsing engine for TypeScript and JavaScript analysis.

This module provides a high-level interface around tree-sitter for parsing
TS/JS source code into ASTs and querying them for specific patterns. It is
the foundation that all downstream security analyzers build on.

Usage::

    engine = ASTEngine()
    ast = engine.parse("const x = require('child_process');", language="typescript")
    imports = engine.find_imports(ast)
    calls = engine.find_function_calls(ast, function_name="exec")
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

import tree_sitter as ts
import tree_sitter_javascript as ts_js
import tree_sitter_typescript as ts_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes for structured query results
# ---------------------------------------------------------------------------


@dataclass
class FunctionCall:
    """Represents a function or method call found in the AST.

    Attributes:
        name: The function/method name (e.g., "exec", "execSync").
        arguments: Text representation of each argument.
        line: 1-based line number.
        column: 0-based column offset.
        full_text: Complete source text of the call expression.
        receiver: Object the method is called on, if any.
            For ``child_process.exec()`` the receiver is ``"child_process"``.
    """

    name: str
    arguments: list[str] = field(default_factory=list)
    line: int = 0
    column: int = 0
    full_text: str = ""
    receiver: str | None = None


@dataclass
class ImportStatement:
    """Represents an import or require() statement.

    Attributes:
        module: The module specifier string (e.g., ``"child_process"``).
        imported_names: List of named imports. Empty for default/namespace
            imports.
        is_default: ``True`` when the import is a default import
            (``import foo from 'bar'``).
        is_dynamic: ``True`` for ``require()`` calls rather than static
            ``import`` statements.
        line: 1-based line number.
    """

    module: str
    imported_names: list[str] = field(default_factory=list)
    is_default: bool = False
    is_dynamic: bool = False
    line: int = 0


@dataclass
class StringLiteral:
    """A string literal found in the AST.

    Attributes:
        value: The string content *without* surrounding quotes.
        line: 1-based line number.
        column: 0-based column offset.
    """

    value: str
    line: int = 0
    column: int = 0


@dataclass
class ObjectProperty:
    """An object property definition (key/value pair).

    Attributes:
        key: The property key name.
        value_text: Source text of the property value.
        line: 1-based line number.
        object_name: Name of the variable the enclosing object is assigned
            to, if determinable.
    """

    key: str
    value_text: str
    line: int = 0
    object_name: str | None = None


@dataclass
class FunctionDefinition:
    """A function, method, or arrow-function definition.

    Attributes:
        name: Declared name (may be the variable name for arrow functions).
        parameters: List of parameter name strings.
        line: 1-based line number.
        kind: One of ``"function"``, ``"arrow"``, ``"method"``, or
            ``"generator"``.
        is_async: ``True`` when the function uses the ``async`` keyword.
        body_text: Full source text of the function body.
    """

    name: str
    parameters: list[str] = field(default_factory=list)
    line: int = 0
    kind: str = "function"
    is_async: bool = False
    body_text: str = ""


@dataclass
class QueryMatch:
    """A single match returned by an S-expression query.

    Attributes:
        pattern_index: Index of the matched pattern in the query.
        captures: Mapping from capture names to lists of matched nodes.
    """

    pattern_index: int
    captures: dict[str, list[ts.Node]]


# ---------------------------------------------------------------------------
# ParsedAST wrapper
# ---------------------------------------------------------------------------


class ParsedAST:
    """Wrapper around a tree-sitter parse tree with convenience methods.

    Attributes:
        tree: The underlying ``tree_sitter.Tree``.
        source_code: Original source string that was parsed.
        language: Language identifier (``"javascript"``, ``"typescript"``,
            or ``"tsx"``).
    """

    __slots__ = ("tree", "source_code", "language", "_source_bytes")

    def __init__(
        self,
        tree: ts.Tree,
        source_code: str,
        language: str,
    ) -> None:
        self.tree = tree
        self.source_code = source_code
        self.language = language
        self._source_bytes: bytes = source_code.encode("utf-8")

    @property
    def root_node(self) -> ts.Node:
        """Return the root node of the parse tree."""
        return self.tree.root_node

    @property
    def has_errors(self) -> bool:
        """Return ``True`` if the tree contains any parse errors."""
        return self.tree.root_node.has_error

    def get_text(self, node: ts.Node) -> str:
        """Extract the source text spanned by *node*.

        Args:
            node: Any node within this parse tree.

        Returns:
            The corresponding source substring.
        """
        return self._source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8", errors="replace"
        )

    def walk(self, visitor: Callable[[ts.Node, int], bool | None]) -> None:
        """Depth-first walk of the AST using a visitor callback.

        The *visitor* is called with ``(node, depth)`` for every node.
        If the visitor returns ``False`` explicitly, the subtree rooted
        at that node is skipped.

        Args:
            visitor: Callable receiving ``(node, depth)``. Return ``False``
                to skip children.
        """
        self._walk_recursive(self.tree.root_node, visitor, depth=0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _walk_recursive(
        self,
        node: ts.Node,
        visitor: Callable[[ts.Node, int], bool | None],
        depth: int,
    ) -> None:
        result = visitor(node, depth)
        if result is False:
            return
        for child in node.children:
            self._walk_recursive(child, visitor, depth + 1)


# ---------------------------------------------------------------------------
# Supported languages
# ---------------------------------------------------------------------------

_SUPPORTED_LANGUAGES = frozenset({"javascript", "typescript", "tsx"})


# ---------------------------------------------------------------------------
# ASTEngine
# ---------------------------------------------------------------------------


class ASTEngine:
    """Core AST parsing engine for TypeScript and JavaScript.

    Initialises tree-sitter ``Language`` objects lazily on first use and
    caches them for the lifetime of the engine instance.

    Example::

        engine = ASTEngine()
        ast = engine.parse(source, language="typescript")
        for imp in engine.find_imports(ast):
            print(imp.module, imp.imported_names)
    """

    def __init__(self) -> None:
        self._languages: dict[str, ts.Language] = {}
        self._parsers: dict[str, ts.Parser] = {}

    # ------------------------------------------------------------------
    # Language / parser initialisation
    # ------------------------------------------------------------------

    def _get_language(self, language: str) -> ts.Language:
        """Return (and cache) the tree-sitter ``Language`` for *language*.

        Args:
            language: One of ``"javascript"``, ``"typescript"``, ``"tsx"``.

        Raises:
            ValueError: If *language* is not supported.
        """
        if language not in _SUPPORTED_LANGUAGES:
            raise ValueError(
                f"Unsupported language: {language!r}. "
                f"Supported: {', '.join(sorted(_SUPPORTED_LANGUAGES))}"
            )

        if language not in self._languages:
            if language == "javascript":
                self._languages[language] = ts.Language(ts_js.language())
            elif language == "typescript":
                self._languages[language] = ts.Language(
                    ts_ts.language_typescript()
                )
            else:  # tsx
                self._languages[language] = ts.Language(
                    ts_ts.language_tsx()
                )

        return self._languages[language]

    def _get_parser(self, language: str) -> ts.Parser:
        """Return (and cache) a ``Parser`` configured for *language*."""
        if language not in self._parsers:
            lang = self._get_language(language)
            self._parsers[language] = ts.Parser(language=lang)
        return self._parsers[language]

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse(
        self, source_code: str, language: str = "typescript"
    ) -> ParsedAST:
        """Parse *source_code* into a ``ParsedAST``.

        Args:
            source_code: The full file contents to parse.
            language: One of ``"javascript"``, ``"typescript"``, or
                ``"tsx"``.

        Returns:
            A ``ParsedAST`` wrapping the parse tree.

        Raises:
            ValueError: If *language* is not supported.
        """
        parser = self._get_parser(language)
        tree = parser.parse(source_code.encode("utf-8"))
        return ParsedAST(tree=tree, source_code=source_code, language=language)

    # ------------------------------------------------------------------
    # Generic query interface
    # ------------------------------------------------------------------

    def query(self, ast: ParsedAST, pattern: str) -> list[QueryMatch]:
        """Execute a tree-sitter S-expression *pattern* against *ast*.

        Args:
            ast: A previously parsed AST.
            pattern: A tree-sitter query string in S-expression syntax.
                See https://tree-sitter.github.io/tree-sitter/using-parsers/queries
                for the full syntax reference.

        Returns:
            A list of ``QueryMatch`` objects, one per match.

        Raises:
            ts.QueryError: If *pattern* is syntactically invalid.
        """
        lang = self._get_language(ast.language)
        query_obj = ts.Query(lang, pattern)
        cursor = ts.QueryCursor(query_obj)
        raw_matches = cursor.matches(ast.root_node)

        results: list[QueryMatch] = []
        for pattern_index, captures_dict in raw_matches:
            results.append(
                QueryMatch(
                    pattern_index=pattern_index,
                    captures=dict(captures_dict),
                )
            )
        return results

    # ------------------------------------------------------------------
    # Structured finders
    # ------------------------------------------------------------------

    def find_function_calls(
        self,
        ast: ParsedAST,
        function_name: str | None = None,
    ) -> list[FunctionCall]:
        """Find function/method calls in the AST.

        Args:
            ast: A previously parsed AST.
            function_name: If given, only return calls whose name matches
                this value exactly.

        Returns:
            A list of ``FunctionCall`` objects.
        """
        calls: list[FunctionCall] = []
        self._collect_calls(ast, ast.root_node, calls)

        if function_name is not None:
            calls = [c for c in calls if c.name == function_name]

        return calls

    def find_imports(self, ast: ParsedAST) -> list[ImportStatement]:
        """Find all import and require() statements.

        Detects:
        - ``import ... from '...'`` (static ES module imports)
        - ``import('...')`` (dynamic imports)
        - ``require('...')`` (CommonJS require calls)

        Args:
            ast: A previously parsed AST.

        Returns:
            A list of ``ImportStatement`` objects.
        """
        imports: list[ImportStatement] = []
        self._collect_static_imports(ast, imports)
        self._collect_require_imports(ast, imports)
        self._collect_dynamic_imports(ast, imports)
        return imports

    def find_string_literals(self, ast: ParsedAST) -> list[StringLiteral]:
        """Find all string literals in the code.

        Captures both single-quoted and double-quoted strings. Template
        literal *fragments* (the static parts of template strings) are
        also included.

        Args:
            ast: A previously parsed AST.

        Returns:
            A list of ``StringLiteral`` objects.
        """
        literals: list[StringLiteral] = []

        def _visitor(node: ts.Node, _depth: int) -> None:
            if node.type == "string_fragment":
                literals.append(
                    StringLiteral(
                        value=ast.get_text(node),
                        line=node.start_point.row + 1,
                        column=node.start_point.column,
                    )
                )
            elif node.type == "template_string":
                # Collect static fragments inside template literals
                for child in node.children:
                    if child.type == "string_fragment":
                        literals.append(
                            StringLiteral(
                                value=ast.get_text(child),
                                line=child.start_point.row + 1,
                                column=child.start_point.column,
                            )
                        )

        ast.walk(_visitor)
        return literals

    def find_object_properties(
        self,
        ast: ParsedAST,
        object_name: str | None = None,
    ) -> list[ObjectProperty]:
        """Find object property definitions.

        Args:
            ast: A previously parsed AST.
            object_name: If given, only return properties belonging to an
                object assigned to a variable with this name.

        Returns:
            A list of ``ObjectProperty`` objects.
        """
        properties: list[ObjectProperty] = []

        # Use a query that captures object properties within variable
        # declarators so we can resolve the variable name.
        lang = self._get_language(ast.language)

        # Pattern 1: properties inside a named variable assignment
        named_pattern = """
        (variable_declarator
          name: (identifier) @obj_name
          value: (object
            (pair
              key: (property_identifier) @key
              value: (_) @value)))
        """

        try:
            q = ts.Query(lang, named_pattern)
            cursor = ts.QueryCursor(q)
            for _pi, captures in cursor.matches(ast.root_node):
                obj_name_node = captures["obj_name"][0]
                key_node = captures["key"][0]
                value_node = captures["value"][0]
                resolved_name = ast.get_text(obj_name_node)

                if object_name is not None and resolved_name != object_name:
                    continue

                properties.append(
                    ObjectProperty(
                        key=ast.get_text(key_node),
                        value_text=ast.get_text(value_node),
                        line=key_node.start_point.row + 1,
                        object_name=resolved_name,
                    )
                )
        except ts.QueryError:
            logger.debug("Named object property query failed, using fallback")

        # Pattern 2: standalone pair nodes not captured above (e.g., nested
        # objects, objects in function arguments, etc.)
        captured_lines: set[tuple[int, int]] = {
            (p.line, hash(p.key)) for p in properties
        }

        def _pair_visitor(node: ts.Node, _depth: int) -> None:
            if node.type != "pair":
                return
            key_node = node.child_by_field_name("key")
            value_node = node.child_by_field_name("value")
            if key_node is None or value_node is None:
                return

            line = key_node.start_point.row + 1
            key_text = ast.get_text(key_node)
            ident = (line, hash(key_text))
            if ident in captured_lines:
                return

            # When filtering by object_name and we couldn't resolve it,
            # skip standalone pairs.
            if object_name is not None:
                return

            properties.append(
                ObjectProperty(
                    key=key_text,
                    value_text=ast.get_text(value_node),
                    line=line,
                    object_name=None,
                )
            )

        ast.walk(_pair_visitor)
        return properties

    def find_function_definitions(
        self, ast: ParsedAST
    ) -> list[FunctionDefinition]:
        """Extract all function, method, and arrow-function definitions.

        Args:
            ast: A previously parsed AST.

        Returns:
            A list of ``FunctionDefinition`` objects.
        """
        definitions: list[FunctionDefinition] = []
        lang = self._get_language(ast.language)

        # 1. Function declarations: function foo(...) { ... }
        self._collect_function_declarations(ast, lang, definitions)

        # 2. Arrow functions assigned to variables: const foo = (...) => ...
        self._collect_arrow_functions(ast, lang, definitions)

        # 3. Method definitions inside classes
        self._collect_method_definitions(ast, lang, definitions)

        # 4. Generator function declarations
        self._collect_generator_declarations(ast, lang, definitions)

        return definitions

    def find_nodes_by_type(
        self, ast: ParsedAST, node_type: str
    ) -> list[ts.Node]:
        """Return all AST nodes matching *node_type*.

        This is a low-level helper. For most use cases the higher-level
        ``find_*`` methods are preferable.

        Args:
            ast: A previously parsed AST.
            node_type: The tree-sitter node type string
                (e.g., ``"call_expression"``).

        Returns:
            A list of matching ``Node`` objects.
        """
        matches: list[ts.Node] = []

        def _visitor(node: ts.Node, _depth: int) -> None:
            if node.type == node_type:
                matches.append(node)

        ast.walk(_visitor)
        return matches

    # ------------------------------------------------------------------
    # Private: call collection
    # ------------------------------------------------------------------

    def _collect_calls(
        self,
        ast: ParsedAST,
        root: ts.Node,
        out: list[FunctionCall],
    ) -> None:
        """Walk *root* and collect every ``call_expression``."""
        def _visitor(node: ts.Node, _depth: int) -> None:
            if node.type != "call_expression":
                return

            fn_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if fn_node is None:
                return

            name: str
            receiver: str | None = None

            if fn_node.type == "identifier":
                name = ast.get_text(fn_node)
            elif fn_node.type == "member_expression":
                prop = fn_node.child_by_field_name("property")
                obj = fn_node.child_by_field_name("object")
                name = ast.get_text(prop) if prop else ast.get_text(fn_node)
                receiver = ast.get_text(obj) if obj else None
            else:
                # E.g., immediately invoked function expressions
                name = ast.get_text(fn_node)

            arguments: list[str] = []
            if args_node is not None:
                for child in args_node.children:
                    # Skip punctuation (parentheses, commas)
                    if child.is_named:
                        arguments.append(ast.get_text(child))

            out.append(
                FunctionCall(
                    name=name,
                    arguments=arguments,
                    line=node.start_point.row + 1,
                    column=node.start_point.column,
                    full_text=ast.get_text(node),
                    receiver=receiver,
                )
            )

        ast.walk(_visitor)

    # ------------------------------------------------------------------
    # Private: import collection
    # ------------------------------------------------------------------

    def _collect_static_imports(
        self, ast: ParsedAST, out: list[ImportStatement]
    ) -> None:
        """Collect ES-module ``import`` statements."""
        lang = self._get_language(ast.language)

        # Match import statements with a source string
        pattern = (
            "(import_statement "
            "  source: (string (string_fragment) @source)"
            ") @import"
        )
        try:
            q = ts.Query(lang, pattern)
            cursor = ts.QueryCursor(q)
            for _pi, captures in cursor.matches(ast.root_node):
                import_node = captures["import"][0]
                source_node = captures["source"][0]
                module = ast.get_text(source_node)

                imported_names: list[str] = []
                is_default = False

                # Walk the import_clause to figure out what is imported
                # In tree-sitter grammar the clause is one of the children
                for child in import_node.children:
                    if child.type == "import_clause":
                        self._parse_import_clause(
                            ast, child, imported_names
                        )
                        # A bare identifier child means default import
                        for sub in child.children:
                            if sub.type == "identifier":
                                is_default = True
                                break

                out.append(
                    ImportStatement(
                        module=module,
                        imported_names=imported_names,
                        is_default=is_default,
                        is_dynamic=False,
                        line=import_node.start_point.row + 1,
                    )
                )
        except ts.QueryError:
            logger.debug("Static import query failed")

    def _parse_import_clause(
        self,
        ast: ParsedAST,
        clause: ts.Node,
        out: list[str],
    ) -> None:
        """Parse an ``import_clause`` node and extract imported names."""
        for child in clause.children:
            if child.type == "identifier":
                out.append(ast.get_text(child))
            elif child.type == "named_imports":
                for spec in child.children:
                    if spec.type == "import_specifier":
                        name_node = spec.child_by_field_name("name")
                        alias_node = spec.child_by_field_name("alias")
                        if alias_node is not None:
                            out.append(ast.get_text(alias_node))
                        elif name_node is not None:
                            out.append(ast.get_text(name_node))
            elif child.type == "namespace_import":
                # import * as name
                for sub in child.children:
                    if sub.type == "identifier":
                        out.append(f"* as {ast.get_text(sub)}")
                        break

    def _collect_require_imports(
        self, ast: ParsedAST, out: list[ImportStatement]
    ) -> None:
        """Collect CommonJS ``require()`` calls."""
        lang = self._get_language(ast.language)

        pattern = (
            "(call_expression "
            '  function: (identifier) @fn (#eq? @fn "require") '
            "  arguments: (arguments (string (string_fragment) @module))"
            ") @call"
        )
        try:
            q = ts.Query(lang, pattern)
            cursor = ts.QueryCursor(q)
            for _pi, captures in cursor.matches(ast.root_node):
                call_node = captures["call"][0]
                module_node = captures["module"][0]
                module = ast.get_text(module_node)

                # Determine imported names from the assignment target
                imported_names, is_default = (
                    self._names_from_require_target(ast, call_node)
                )

                out.append(
                    ImportStatement(
                        module=module,
                        imported_names=imported_names,
                        is_default=is_default,
                        is_dynamic=True,
                        line=call_node.start_point.row + 1,
                    )
                )
        except ts.QueryError:
            logger.debug("Require import query failed")

    def _names_from_require_target(
        self, ast: ParsedAST, call_node: ts.Node
    ) -> tuple[list[str], bool]:
        """Resolve imported names from the LHS of a require() assignment.

        Handles:
        - ``const foo = require('bar')`` -> ``(["foo"], True)``
        - ``const { a, b } = require('bar')`` -> ``(["a", "b"], False)``

        Returns:
            A tuple of ``(imported_names, is_default)``.
        """
        names: list[str] = []
        is_default = True
        parent = call_node.parent
        if parent is None or parent.type != "variable_declarator":
            return names, is_default

        name_node = parent.child_by_field_name("name")
        if name_node is None:
            return names, is_default

        if name_node.type == "identifier":
            names.append(ast.get_text(name_node))
            is_default = True
        elif name_node.type == "object_pattern":
            is_default = False
            for child in name_node.children:
                if child.type == "shorthand_property_identifier_pattern":
                    names.append(ast.get_text(child))
                elif child.type == "pair_pattern":
                    value_node = child.child_by_field_name("value")
                    if value_node is not None:
                        names.append(ast.get_text(value_node))

        return names, is_default

    def _collect_dynamic_imports(
        self, ast: ParsedAST, out: list[ImportStatement]
    ) -> None:
        """Collect dynamic ``import('...')`` expressions."""
        def _visitor(node: ts.Node, _depth: int) -> None:
            # In tree-sitter, dynamic import is modeled as a
            # call_expression with an "import" identifier in some grammars,
            # or as a dedicated "import" node.
            if node.type != "call_expression":
                return
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                return
            # Dynamic import: the function node is the keyword "import"
            if ast.get_text(fn_node) != "import":
                return

            args_node = node.child_by_field_name("arguments")
            if args_node is None:
                return

            for arg in args_node.children:
                if arg.type == "string":
                    for child in arg.children:
                        if child.type == "string_fragment":
                            out.append(
                                ImportStatement(
                                    module=ast.get_text(child),
                                    imported_names=[],
                                    is_default=False,
                                    is_dynamic=True,
                                    line=node.start_point.row + 1,
                                )
                            )
                            return

        ast.walk(_visitor)

    # ------------------------------------------------------------------
    # Private: function definition collection
    # ------------------------------------------------------------------

    def _collect_function_declarations(
        self,
        ast: ParsedAST,
        lang: ts.Language,
        out: list[FunctionDefinition],
    ) -> None:
        """Collect regular function declarations."""
        pattern = (
            "(function_declaration "
            "  name: (identifier) @name "
            "  parameters: (formal_parameters) @params "
            "  body: (statement_block) @body"
            ") @func"
        )
        try:
            q = ts.Query(lang, pattern)
            cursor = ts.QueryCursor(q)
            for _pi, captures in cursor.matches(ast.root_node):
                func_node = captures["func"][0]
                name_text = ast.get_text(captures["name"][0])
                params = self._extract_param_names(
                    ast, captures["params"][0]
                )
                body_text = ast.get_text(captures["body"][0])
                is_async = self._node_has_async(ast, func_node)

                out.append(
                    FunctionDefinition(
                        name=name_text,
                        parameters=params,
                        line=func_node.start_point.row + 1,
                        kind="function",
                        is_async=is_async,
                        body_text=body_text,
                    )
                )
        except ts.QueryError:
            logger.debug("Function declaration query failed")

    def _collect_arrow_functions(
        self,
        ast: ParsedAST,
        lang: ts.Language,
        out: list[FunctionDefinition],
    ) -> None:
        """Collect arrow functions assigned to named variables."""
        pattern = (
            "(variable_declarator "
            "  name: (identifier) @name "
            "  value: (arrow_function) @arrow"
            ")"
        )
        try:
            q = ts.Query(lang, pattern)
            cursor = ts.QueryCursor(q)
            for _pi, captures in cursor.matches(ast.root_node):
                arrow_node = captures["arrow"][0]
                name_text = ast.get_text(captures["name"][0])
                is_async = self._node_has_async(ast, arrow_node)

                params_node = arrow_node.child_by_field_name("parameters")
                if params_node is not None:
                    params = self._extract_param_names(ast, params_node)
                else:
                    # Single-param arrow without parens: x => ...
                    params = []
                    for child in arrow_node.children:
                        if child.type == "identifier":
                            params.append(ast.get_text(child))
                            break

                body_node = arrow_node.child_by_field_name("body")
                body_text = ast.get_text(body_node) if body_node else ""

                out.append(
                    FunctionDefinition(
                        name=name_text,
                        parameters=params,
                        line=arrow_node.start_point.row + 1,
                        kind="arrow",
                        is_async=is_async,
                        body_text=body_text,
                    )
                )
        except ts.QueryError:
            logger.debug("Arrow function query failed")

    def _collect_method_definitions(
        self,
        ast: ParsedAST,
        lang: ts.Language,
        out: list[FunctionDefinition],
    ) -> None:
        """Collect class method definitions."""
        pattern = (
            "(method_definition "
            "  name: (property_identifier) @name "
            "  parameters: (formal_parameters) @params "
            "  body: (statement_block) @body"
            ") @method"
        )
        try:
            q = ts.Query(lang, pattern)
            cursor = ts.QueryCursor(q)
            for _pi, captures in cursor.matches(ast.root_node):
                method_node = captures["method"][0]
                name_text = ast.get_text(captures["name"][0])
                params = self._extract_param_names(
                    ast, captures["params"][0]
                )
                body_text = ast.get_text(captures["body"][0])
                is_async = self._node_has_async(ast, method_node)

                out.append(
                    FunctionDefinition(
                        name=name_text,
                        parameters=params,
                        line=method_node.start_point.row + 1,
                        kind="method",
                        is_async=is_async,
                        body_text=body_text,
                    )
                )
        except ts.QueryError:
            logger.debug("Method definition query failed")

    def _collect_generator_declarations(
        self,
        ast: ParsedAST,
        lang: ts.Language,
        out: list[FunctionDefinition],
    ) -> None:
        """Collect generator function declarations."""
        pattern = (
            "(generator_function_declaration "
            "  name: (identifier) @name "
            "  parameters: (formal_parameters) @params "
            "  body: (statement_block) @body"
            ") @func"
        )
        try:
            q = ts.Query(lang, pattern)
            cursor = ts.QueryCursor(q)
            for _pi, captures in cursor.matches(ast.root_node):
                func_node = captures["func"][0]
                name_text = ast.get_text(captures["name"][0])
                params = self._extract_param_names(
                    ast, captures["params"][0]
                )
                body_text = ast.get_text(captures["body"][0])
                is_async = self._node_has_async(ast, func_node)

                out.append(
                    FunctionDefinition(
                        name=name_text,
                        parameters=params,
                        line=func_node.start_point.row + 1,
                        kind="generator",
                        is_async=is_async,
                        body_text=body_text,
                    )
                )
        except ts.QueryError:
            logger.debug("Generator declaration query failed")

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_param_names(
        ast: ParsedAST, params_node: ts.Node
    ) -> list[str]:
        """Extract parameter name strings from a ``formal_parameters`` node.

        Handles plain identifiers, typed parameters (TypeScript), default
        values, destructuring, and rest parameters.
        """
        names: list[str] = []
        for child in params_node.children:
            if child.type == "identifier":
                names.append(ast.get_text(child))
            elif child.type in (
                "required_parameter",
                "optional_parameter",
            ):
                id_node = child.child_by_field_name("pattern")
                if id_node is None:
                    # Try first named child as fallback
                    for sub in child.children:
                        if sub.type == "identifier":
                            id_node = sub
                            break
                if id_node is not None:
                    names.append(ast.get_text(id_node))
            elif child.type == "rest_parameter":
                for sub in child.children:
                    if sub.type == "identifier":
                        names.append(f"...{ast.get_text(sub)}")
                        break
            elif child.type == "assignment_pattern":
                left = child.child_by_field_name("left")
                if left is not None:
                    names.append(ast.get_text(left))
        return names

    @staticmethod
    def _node_has_async(ast: ParsedAST, node: ts.Node) -> bool:
        """Check whether a function/method node has the ``async`` keyword."""
        for child in node.children:
            if ast.get_text(child) == "async":
                return True
            # Stop checking after we hit the function keyword or name
            if child.type in ("function", "identifier", "property_identifier"):
                break
        return False
