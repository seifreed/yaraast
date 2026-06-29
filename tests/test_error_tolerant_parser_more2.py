"""More branch coverage for error-tolerant parser internals."""

from __future__ import annotations

from textwrap import dedent

import pytest

from yaraast.ast.expressions import BinaryExpression, BooleanLiteral, Identifier, StringIdentifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.parser.error_tolerant_parser import ErrorTolerantParser
from yaraast.parser.error_tolerant_recovery import parse_meta_line, parse_string_line
from yaraast.parser.error_tolerant_types import ParserError
from yaraast.parser.parser import Parser


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

    assert bool(parser.errors) is True
    assert result.errors
    assert parser.errors == result.errors


def test_error_tolerant_parser_returns_error_and_rule_snapshots() -> None:
    parser = ErrorTolerantParser()
    text = dedent("""
        import ???

        rule recovered {
            condition:
                true
        }
        """)
    result = parser.parse(text)

    assert result.errors
    assert parser.errors == result.errors
    result.errors.clear()
    errors = list(parser.errors)
    errors.clear()
    assert bool(parser.errors) is True

    recovered_rules = list(parser.recovered_rules)
    assert recovered_rules
    recovered_rules.clear()
    assert parser.recovered_rules


def test_error_tolerant_parser_preserves_rule_modifiers() -> None:
    parser = ErrorTolerantParser()
    result = parser.parse(
        dedent("""
        private global rule guarded {
            condition:
                true
        }
        """),
    )

    assert result.ast.rules
    rule = result.ast.rules[0]
    assert rule.is_private is True
    assert rule.is_global is True
    assert [str(modifier) for modifier in rule.modifiers] == ["private", "global"]


def test_error_tolerant_recovery_preserves_falsy_present_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FalsyRule(Rule):
        def __bool__(self) -> bool:
            return False

    recovered = FalsyRule(name="recovered", condition=BooleanLiteral(True))
    parser = ErrorTolerantParser()
    parser.lines = dedent("""
        private rule recovered {
            condition:
                true
        }
        """).splitlines()
    monkeypatch.setattr(parser, "_create_rule_from_body", lambda *_args, **_kwargs: recovered)

    ast = parser._parse_with_recovery("\n".join(parser.lines))

    assert ast.rules == [recovered]
    assert parser.recovered_rules == [recovered]
    assert [str(modifier) for modifier in recovered.modifiers] == ["private"]


def test_recovery_preserves_rule_after_regex_with_unbalanced_brace() -> None:
    source = dedent("""
        @@@ forces error-tolerant recovery
        rule First {
            strings:
                $re = /[{]/
            condition:
                $re
        }
        rule Second {
            condition:
                true
        }
        """)

    result = ErrorTolerantParser().parse(source)

    assert [rule.name for rule in result.ast.rules] == ["First", "Second"]


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
    assert isinstance(rule.condition, BinaryExpression)
    assert isinstance(rule.condition.left, Identifier)
    assert rule.condition.left.name == "complex"
    assert isinstance(rule.condition.right, Identifier)
    assert rule.condition.right.name == "expr"

    string_meta = parse_meta_line(p, 'k = "v"')
    integer_meta = parse_meta_line(p, "n = 9")
    boolean_meta = parse_meta_line(p, "flag = false")
    assert string_meta is not None
    assert integer_meta is not None
    assert boolean_meta is not None
    assert string_meta.value == "v"
    assert integer_meta.value == 9
    assert boolean_meta.value is False
    assert parse_meta_line(p, "invalid") is None

    plain_string = parse_string_line(p, '$a = "x"')
    hex_string = parse_string_line(p, "$a = { 41 }")
    regex_string = parse_string_line(p, "$a = /abc/")
    regex_with_flags = parse_string_line(p, "$a = /abc/im")
    xor_string = parse_string_line(p, '$x = "abc" xor(1-2) private')
    base64_string = parse_string_line(
        p, '$b = "abc" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")'
    )
    assert isinstance(plain_string, PlainString)
    assert isinstance(hex_string, HexString)
    assert isinstance(regex_string, RegexString)
    assert isinstance(regex_with_flags, RegexString)
    assert isinstance(xor_string, PlainString)
    assert isinstance(base64_string, PlainString)
    assert plain_string.identifier == "$a"
    assert hex_string.identifier == "$a"
    assert regex_string.identifier == "$a"
    assert len(hex_string.tokens) == 1
    assert regex_string.regex == "abc"
    assert [modifier.name for modifier in regex_with_flags.modifiers] == ["nocase", "multiline"]
    assert [(modifier.name, modifier.value) for modifier in xor_string.modifiers] == [
        ("xor", (1, 2)),
        ("private", None),
    ]
    assert [(modifier.name, modifier.value) for modifier in base64_string.modifiers] == [
        ("base64", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    ]
    assert parse_string_line(p, "broken") is None

    assert p._parse_condition("true") == BooleanLiteral(True)
    assert p._parse_condition("false") == BooleanLiteral(False)
    parsed_string_condition = p._parse_condition("$a")
    assert isinstance(parsed_string_condition, StringIdentifier)
    assert parsed_string_condition.name == "$a"
    parsed_binary_condition = p._parse_condition("$a or true")
    assert isinstance(parsed_binary_condition, BinaryExpression)
    assert isinstance(parsed_binary_condition.left, StringIdentifier)
    assert isinstance(parsed_binary_condition.right, BooleanLiteral)
    assert p._parse_condition("$a or") == Identifier("$a or")


def test_recovered_condition_propagates_internal_parser_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_parser_parse(self: Parser, text: str | None = None) -> object:
        raise AttributeError("broken parser internals")

    monkeypatch.setattr(Parser, "parse", fail_parser_parse)

    with pytest.raises(AttributeError, match="broken parser internals"):
        ErrorTolerantParser()._parse_condition("$a or true")


def test_parse_result_api_and_clean_parse_has_no_errors() -> None:
    p = ErrorTolerantParser()
    result = p.parse('import "broken')
    assert result.ast is not None
    assert result.errors

    clean = ErrorTolerantParser()
    clean.parse("rule x { condition: true }")
    assert clean.errors == []


def test_recovered_nodes_include_basic_locations() -> None:
    parser = ErrorTolerantParser()
    text = dedent("""
            import "pe"
            include "common.yar"
            invalid top level tokens
            rule sample {
                meta:
                    author = "me"
                strings:
                    $a = "x"
                condition:
                    $a
            }
            """)
    result = parser.parse(text)

    assert result.ast.imports[0].location is not None
    assert result.ast.includes[0].location is not None

    rule = result.ast.rules[0]
    assert rule.location is not None
    assert rule.location.end_line is not None
    assert rule.meta[0].location is not None
    assert rule.strings[0].location is not None
    assert rule.condition is not None
    assert rule.condition.location is not None
