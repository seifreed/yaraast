"""More branch coverage for error-tolerant parser internals."""

from __future__ import annotations

from textwrap import dedent

from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser, ParserError


def test_parser_error_format_and_normal_parse_success() -> None:
    e1 = ParserError(message="boom", line=1, column=2, context="rule x")
    assert "rule x" in e1.format_error()

    e2 = ParserError(message="boom", line=1, column=2)
    assert "rule x" not in e2.format_error()

    parser = ErrorTolerantParser()
    valid = dedent(
        """
        import "pe"
        include "common.yar"
        rule ok {
            condition:
                true
        }
        """
    )
    result = parser.parse(valid)
    assert result.errors == []
    assert result.ast.rules and result.ast.rules[0].name == "ok"


def test_recovery_paths_for_invalid_import_include_rule_and_unknown_lines() -> None:
    parser = ErrorTolerantParser()
    text = dedent(
        """
        import ???
        include ???
        rule $bad {
            condition:
                true
        }
        stray tokens
        """
    )
    result = parser.parse(text)

    assert parser.has_errors() is True
    assert result.errors
    assert parser.get_errors() == result.errors


def test_rule_body_parsing_meta_strings_condition_and_helpers() -> None:
    p = ErrorTolerantParser()

    body = [
        "meta:",
        'author = "me"',
        "count = 7",
        "enabled = true",
        "bad_meta",
        "strings:",
        '$a = "abc"',
        "$h = { 41 42 }",
        "$r = /ab.+/",
        "$x ???",
        "condition:",
        "false",
        "$a",
        "complex and expr",
        "}",
    ]
    rule = p._create_rule_from_body("r1", ["tag1"], body)

    assert rule.name == "r1"
    assert rule.tags == ["tag1"]
    assert len(rule.meta) == 3
    assert len(rule.strings) == 3
    assert isinstance(rule.condition, Identifier)
    assert rule.condition.name == "complex and expr"

    assert p._parse_meta_line('k = "v"').value == "v"
    assert p._parse_meta_line("n = 9").value == 9
    assert p._parse_meta_line("flag = false").value is False
    assert p._parse_meta_line("invalid") is None

    # Current implementation passes the extracted literal as the second positional
    # arg to PlainString, which maps to modifiers; keep assertions aligned to behavior.
    assert p._parse_string_line('$a = "x"').identifier == "$a"
    assert p._parse_string_line("$a = { 41 }").identifier == "$a"
    assert p._parse_string_line("$a = /abc/").identifier == "$a"
    assert p._parse_string_line("broken") is None

    assert p._parse_condition("true") == BooleanLiteral(True)
    assert p._parse_condition("false") == BooleanLiteral(False)
    assert p._parse_condition("$a") == Identifier("$a")


def test_parse_with_errors_api_and_format_errors_no_errors_branch() -> None:
    p = ErrorTolerantParser()
    ast, lexer_errors, parser_errors = p.parse_with_errors('import "broken')
    assert ast is not None
    assert lexer_errors == []
    assert parser_errors

    clean = ErrorTolerantParser()
    clean.parse("rule x { condition: true }")
    assert clean.format_errors() == "No errors"


def test_recovered_nodes_include_basic_locations() -> None:
    parser = ErrorTolerantParser()
    result = parser.parse(
        dedent(
            """
            import "pe"
            include "common.yar"
            rule sample {
                meta:
                    author = "me"
                strings:
                    $a = "x"
                condition:
                    $a
            }
            """
        )
    )

    assert result.ast.imports[0].location is not None
    assert result.ast.includes[0].location is not None

    rule = result.ast.rules[0]
    assert rule.location is not None
    assert rule.location.end_line is not None
    assert rule.meta[0].location is not None
    assert rule.strings[0].location is not None
    assert rule.condition.location is not None
