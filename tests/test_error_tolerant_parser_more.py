"""Tests for error-tolerant parser (no mocks)."""

from __future__ import annotations

from textwrap import dedent

import pytest

from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.parser.parser import Parser


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


def test_error_tolerant_parser_propagates_internal_parser_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_parser_parse(self: Parser, text: str | None = None) -> object:
        raise AttributeError("broken parser internals")

    monkeypatch.setattr(Parser, "parse", fail_parser_parse)

    with pytest.raises(AttributeError, match="broken parser internals"):
        ErrorTolerantParser().parse("rule r { condition: true }")
