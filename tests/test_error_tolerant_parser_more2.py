"""More branch coverage for error-tolerant parser internals."""

from __future__ import annotations

from textwrap import dedent

from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.parser.error_tolerant_types import ParserError


def test_parser_error_format_and_normal_parse_success() -> None:
    e1 = ParserError(message="boom", line=1, column=2, context="rule x")
    assert "rule x" in e1.format_error()

    e2 = ParserError(message="boom", line=1, column=2)
    assert "rule x" not in e2.format_error()

    parser = ErrorTolerantParser()
    valid = dedent("""
        import "pe"
        include "common.yar"
        rule ok {
            condition:
                true
        }
        """)
    result = parser.parse(valid)
    assert result.errors == []
    assert result.ast.rules and result.ast.rules[0].name == "ok"


def test_recovery_paths_for_invalid_import_include_rule_and_unknown_lines() -> None:
    parser = ErrorTolerantParser()
    text = dedent("""
        import ???
        include ???
        rule $bad {
            condition:
                true
        }
        stray tokens
        """)
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
    assert [tag.name for tag in rule.tags] == ["tag1"]
    assert len(rule.meta) == 3
    assert len(rule.strings) == 3
    assert isinstance(rule.strings[0], PlainString)
    assert isinstance(rule.strings[1], HexString)
    assert isinstance(rule.strings[2], RegexString)
    assert isinstance(rule.condition, Identifier)
    assert rule.condition.name == "complex and expr"

    string_meta = p._parse_meta_line('k = "v"')
    integer_meta = p._parse_meta_line("n = 9")
    boolean_meta = p._parse_meta_line("flag = false")
    assert string_meta is not None
    assert integer_meta is not None
    assert boolean_meta is not None
    assert string_meta.value == "v"
    assert integer_meta.value == 9
    assert boolean_meta.value is False
    assert p._parse_meta_line("invalid") is None

    plain_string = p._parse_string_line('$a = "x"')
    hex_string = p._parse_string_line("$a = { 41 }")
    regex_string = p._parse_string_line("$a = /abc/")
    regex_with_flags = p._parse_string_line("$a = /abc/im")
    assert isinstance(plain_string, PlainString)
    assert isinstance(hex_string, HexString)
    assert isinstance(regex_string, RegexString)
    assert isinstance(regex_with_flags, RegexString)
    assert plain_string.identifier == "$a"
    assert hex_string.identifier == "$a"
    assert regex_string.identifier == "$a"
    assert len(hex_string.tokens) == 1
    assert regex_string.regex == "abc"
    assert [modifier.name for modifier in regex_with_flags.modifiers] == ["nocase", "multiline"]
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
    result = parser.parse(dedent("""
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
            """))

    assert result.ast.imports[0].location is not None
    assert result.ast.includes[0].location is not None

    rule = result.ast.rules[0]
    assert rule.location is not None
    assert rule.location.end_line is not None
    assert rule.meta[0].location is not None
    assert rule.strings[0].location is not None
    assert rule.condition is not None
    assert rule.condition.location is not None
