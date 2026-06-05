"""Additional tests for small helper modules without mocks."""

from __future__ import annotations

import pytest

from yaraast.ast.modifiers import StringModifier
from yaraast.codegen.generator_helpers import (
    escape_plain_string_value,
    format_integer_literal,
    format_modifiers,
)
from yaraast.dialects import YaraDialect, detect_dialect
from yaraast.lexer.lexer import Lexer
from yaraast.lexer.lexer_helpers import (
    _skip_block_comment,
    _skip_line_comment,
    _skip_line_continuation,
    skip_whitespace_and_comments,
)
from yaraast.lsp.provider_call_helpers import call_range_with_optional_uri, call_with_optional_uri
from yaraast.shared.integer_semantics import INT64_MIN


def test_provider_call_helpers_do_not_mask_internal_type_errors() -> None:
    def accepts_uri(text: str, uri: str) -> str:
        raise TypeError(f"internal failure for {text} at {uri}")

    def accepts_range_uri(text: str, range_: object, uri: str) -> str:
        raise TypeError(f"internal range failure for {text} at {uri} in {range_}")

    try:
        call_with_optional_uri(accepts_uri, "rule a { condition: true }", "file:///a.yar")
    except TypeError as exc:
        assert "internal failure" in str(exc)
    else:
        raise AssertionError("provider TypeError should propagate")

    try:
        call_range_with_optional_uri(
            accepts_range_uri,
            "rule a { condition: true }",
            object(),
            "file:///a.yar",
        )
    except TypeError as exc:
        assert "internal range failure" in str(exc)
    else:
        raise AssertionError("range provider TypeError should propagate")


def test_provider_call_helpers_fall_back_for_legacy_signatures() -> None:
    def legacy(text: str) -> str:
        return text

    def legacy_range(text: str, range_: object) -> tuple[str, object]:
        return text, range_

    range_marker = object()
    assert call_with_optional_uri(legacy, "source", "file:///a.yar") == "source"
    assert call_range_with_optional_uri(legacy_range, "source", range_marker, "file:///a.yar") == (
        "source",
        range_marker,
    )


def test_lexer_helpers_skip_whitespace_comments_and_line_continuation() -> None:
    lex: Lexer[object] = Lexer("  \t\r\n// line comment\n/* block */rule")
    skip_whitespace_and_comments(lex)
    assert lex._current_char() == "r"

    combined: Lexer[object] = Lexer("\\  \n// c\n/* b */x")
    skip_whitespace_and_comments(combined)
    assert combined._current_char() == "x"

    cont: Lexer[object] = Lexer("\\  \r\nx")
    _skip_line_continuation(cont)
    assert cont._current_char() == "x"

    cont_cr: Lexer[object] = Lexer("\\\rx")
    _skip_line_continuation(cont_cr)
    assert cont_cr._current_char() == "x"

    cont_lf: Lexer[object] = Lexer("\\\nx")
    _skip_line_continuation(cont_lf)
    assert cont_lf._current_char() == "x"

    line: Lexer[object] = Lexer("// comment only\nx")
    _skip_line_comment(line)
    assert line._current_char() == "\n"

    block: Lexer[object] = Lexer("/* comment */x")
    _skip_block_comment(block)
    assert block._current_char() == "x"

    unterminated: Lexer[object] = Lexer("/* unterminated")
    _skip_block_comment(unterminated)
    assert unterminated.position == len(unterminated.text)  # Consumes entire unterminated comment


def test_generator_helpers_escape_integer_and_modifiers() -> None:
    escaped = escape_plain_string_value('a\\b"c\n\r\t\x00\x01')
    assert escaped == 'a\\\\b\\"c\\n\\r\\t\\x00\\x01'

    with pytest.raises(TypeError, match="Integer literal value must be an integer"):
        format_integer_literal("not-a-number")
    assert format_integer_literal("1024") == "0x400"
    assert format_integer_literal(0x4D5A) == "0x4D5A"
    assert format_integer_literal(0x30) == "48"
    assert format_integer_literal(0x200) == "0x200"
    assert format_integer_literal(255) == "255"
    assert format_integer_literal(INT64_MIN) == "(-9223372036854775807 - 1)"
    assert format_integer_literal(str(INT64_MIN)) == "(-9223372036854775807 - 1)"
    assert format_integer_literal("-0x8000000000000000") == "(-9223372036854775807 - 1)"
    assert format_integer_literal("-0o1000000000000000000000") == ("(-9223372036854775807 - 1)")
    with pytest.raises(TypeError, match="Integer literal value must be an integer"):
        format_integer_literal(True)

    mod = StringModifier.from_name_value("ascii")
    assert format_modifiers(["wide", mod], lambda node: f"<{node.name}>") == " wide <ascii>"
    with pytest.raises(TypeError, match="String modifiers must contain strings or StringModifier"):
        format_modifiers(["wide", 7], lambda node: f"<{node.name}>")
    assert format_modifiers(("nocase",), lambda node: "") == " nocase"
    invalid_modifier_containers = (None, "private", {"x"}, 123, "", 0, False)
    for invalid_modifiers in invalid_modifier_containers:
        with pytest.raises(TypeError, match="String modifiers must be a list or tuple"):
            format_modifiers(invalid_modifiers, lambda node: "")


def test_detect_dialect_yaral_signals_and_default_yara() -> None:
    structural = """
rule login_event {
  events:
    $e.metadata.event_type = "LOGIN"
  condition:
    $e
}
"""
    assert detect_dialect(structural) == YaraDialect.YARA_L

    udm = 'rule x { condition: $e.principal.hostname == "host" }'
    assert detect_dialect(udm) == YaraDialect.YARA_L

    agg = 'rule x { condition: count_distinct("src") > 2 }'
    assert detect_dialect(agg) == YaraDialect.YARA_L

    plain_yara = 'rule classic { strings: $a = "events:" condition: $a }'
    assert detect_dialect(plain_yara) == YaraDialect.YARA

    empty_function_call = "rule classic { condition: foo() }"
    assert detect_dialect(empty_function_call) == YaraDialect.YARA

    module_array_access = 'rule classic { condition: pe.sections[0].name == "x" }'
    assert detect_dialect(module_array_access) == YaraDialect.YARA


def test_detect_dialect_yarax_signals() -> None:
    yarax_lambda = "rule x { condition: lambda x, y: x + y }"
    assert detect_dialect(yarax_lambda) == YaraDialect.YARA_X

    yarax_match = "rule x { condition: match x { 1 => 2, _ => 3 } }"
    assert detect_dialect(yarax_match) == YaraDialect.YARA_X

    yarax_array_comp = "rule x { condition: [x for x in items if x] }"
    assert detect_dialect(yarax_array_comp) == YaraDialect.YARA_X

    yarax_with = 'rule x { condition: with $a = "test", $b = 2: true }'
    assert detect_dialect(yarax_with) == YaraDialect.YARA_X

    yarax_with_identifier = "rule x { condition: with xs = [1]: true }"
    assert detect_dialect(yarax_with_identifier) == YaraDialect.YARA_X

    yarax_empty_tuple = "rule x { condition: () }"
    assert detect_dialect(yarax_empty_tuple) == YaraDialect.YARA_X

    yarax_nested_empty_tuple = "rule x { condition: ((), 1) }"
    assert detect_dialect(yarax_nested_empty_tuple) == YaraDialect.YARA_X

    yarax_deep_empty_tuple = "rule x { condition: (((), 1), 2) }"
    assert detect_dialect(yarax_deep_empty_tuple) == YaraDialect.YARA_X

    yarax_function_call_indexing = "rule x { condition: foo()[0] }"
    assert detect_dialect(yarax_function_call_indexing) == YaraDialect.YARA_X


def test_detect_dialect_ignores_yarax_signals_inside_regex_literals() -> None:
    regex_string = r"rule classic { strings: $r = /with xs = [1]/ condition: $r }"
    assert detect_dialect(regex_string) == YaraDialect.YARA

    condition_regex = r'rule classic { condition: "abc" matches /lambda x:/ }'
    assert detect_dialect(condition_regex) == YaraDialect.YARA
