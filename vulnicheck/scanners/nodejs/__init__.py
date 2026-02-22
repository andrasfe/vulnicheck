"""Node.js / TypeScript / JavaScript static analysis scanners.

This package provides AST-based analysis of TypeScript and JavaScript source
code using tree-sitter.  The ``ASTEngine`` is the foundational component that
all higher-level security analyzers build on.

Quick start::

    from vulnicheck.scanners.nodejs import ASTEngine

    engine = ASTEngine()
    ast = engine.parse("const x = require('child_process');")
    for imp in engine.find_imports(ast):
        print(imp.module)
"""

from .ast_engine import (
    ASTEngine,
    FunctionCall,
    FunctionDefinition,
    ImportStatement,
    ObjectProperty,
    ParsedAST,
    QueryMatch,
    StringLiteral,
)
from .models import AnalysisResult, SecurityFinding

__all__ = [
    "ASTEngine",
    "AnalysisResult",
    "FunctionCall",
    "FunctionDefinition",
    "ImportStatement",
    "ObjectProperty",
    "ParsedAST",
    "QueryMatch",
    "SecurityFinding",
    "StringLiteral",
]
