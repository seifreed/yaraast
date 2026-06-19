"""Regression tests for the empty package root surface."""

from __future__ import annotations

import yaraast


def test_package_root_does_not_reexport_internal_helpers() -> None:
    removed_names = {
        "CodeGenerator",
        "Parser",
        "YaraLFile",
        "parse_source",
        "YARAAST_VERSION",
        "YARAAST_VERSION_MAJOR",
        "YARAAST_VERSION_MINOR",
        "YARAAST_VERSION_PATCH",
        "YARA_SYNTAX_VERSION",
        "__version__",
        "ASTVisitor",
        "BaseVisitor",
        "CodeGenError",
        "EvaluationError",
        "ILexer",
        "Lexer",
        "LexerError",
        "ParseError",
        "ResolutionError",
        "SemanticError",
        "SerializationError",
        "ValidationError",
        "YaraASTError",
        "YaraDialect",
        "YaraLParser",
        "detect_dialect",
        "get_version_info",
        "get_version_string",
    }

    for name in removed_names:
        assert not hasattr(yaraast, name), name
