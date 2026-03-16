"""Tests for error-tolerant parser (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.parser.error_tolerant_parser import ErrorTolerantParser


def test_error_tolerant_parser_recovers_rules_and_imports() -> None:
    code = """
    import "pe"
    include "common.yar"

    rule good_rule {
        strings:
            $a = "abc"
        condition:
            $a
    }

    rule bad_rule {
        strings:
            $a = "abc"
        condition:
            $a and
    }
    """
    parser = ErrorTolerantParser()
    result = parser.parse(dedent(code))

    assert result.ast.imports
    assert result.ast.includes
    assert len(result.ast.rules) >= 1
    assert parser.get_recovered_rules()


def test_error_tolerant_parser_invalid_lines() -> None:
    code = """
    import bad line
    include bad
    nonsense here
    """
    parser = ErrorTolerantParser()
    result = parser.parse(dedent(code))

    assert parser.has_errors() is True
    assert result.errors
    formatted = parser.format_errors()
    assert "ERROR:" in formatted or "error" in formatted.lower()


def test_error_tolerant_parse_with_errors() -> None:
    code = 'import "bad line'
    parser = ErrorTolerantParser()
    ast, lexer_errors, parser_errors = parser.parse_with_errors(code)

    assert ast is not None
    assert lexer_errors == []
    assert parser_errors
