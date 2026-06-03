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


def test_error_tolerant_parser_reports_missing_condition() -> None:
    # An empty condition section is a syntax error in real YARA. The recovery
    # path substitutes a placeholder condition, but it must record an error
    # rather than silently returning an always-true rule with no errors.
    code = dedent("""
        rule no_condition {
            strings:
                $a = "abc"
            condition:
        }
        """)
    result = ErrorTolerantParser().parse(code)
    assert any("no condition" in error.message for error in result.errors)


def test_error_tolerant_parser_does_not_report_missing_condition_when_present() -> None:
    code = dedent("""
        rule has_condition {
            strings:
                $a = "abc"
            condition:
                $a
        }
        """)
    result = ErrorTolerantParser().parse(code)
    assert not any("no condition" in error.message for error in result.errors)


def test_error_tolerant_parser_reports_string_without_value() -> None:
    # `$a =` with no value is a syntax error in real YARA. Recovery drops the
    # string; it must record an error rather than silently losing it.
    code = dedent("""
        rule r {
            strings:
                $a =
            condition:
                $a
        }
        """)
    result = ErrorTolerantParser().parse(code)
    assert not result.ast.rules[0].strings
    assert any("Invalid string definition" in error.message for error in result.errors)


def test_error_tolerant_parser_reports_unterminated_regex_string() -> None:
    code = dedent("""
        rule r {
            strings:
                $a = /abc
            condition:
                $a
        }
        """)
    result = ErrorTolerantParser().parse(code)
    assert not result.ast.rules[0].strings
    assert any("Invalid string definition" in error.message for error in result.errors)


def test_error_tolerant_parser_reports_invalid_meta_line() -> None:
    # `author 12345` (missing `=`) is a syntax error in real YARA. Recovery
    # drops the meta entry and must record an error.
    code = dedent("""
        rule r {
            meta:
                author 12345
            condition:
                true
        }
        """)
    result = ErrorTolerantParser().parse(code)
    assert not result.ast.rules[0].meta
    assert any("Invalid meta definition" in error.message for error in result.errors)


def test_error_tolerant_parser_reports_garbage_in_strings_section() -> None:
    code = dedent("""
        rule r {
            strings:
                garbage nonsense
                $a = "x"
            condition:
                $a
        }
        """)
    result = ErrorTolerantParser().parse(code)
    identifiers = [s.identifier for s in result.ast.rules[0].strings]
    assert identifiers == ["$a"]
    assert any("Invalid string definition" in error.message for error in result.errors)


def test_error_tolerant_parser_reports_line_outside_any_section() -> None:
    code = dedent("""
        rule r {
            loose garbage line
            condition:
                true
        }
        """)
    result = ErrorTolerantParser().parse(code)
    assert any("outside any section" in error.message for error in result.errors)
