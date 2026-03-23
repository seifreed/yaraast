"""Tests for small codegen formatting helper modules."""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import HexByte, HexJump, HexString, PlainString, RegexString
from yaraast.codegen.generator_formatting import (
    escape_string_literal,
    format_boolean_literal,
    format_hex_jump,
    format_meta_value,
    format_regex_literal,
    format_rule_modifiers,
    format_rule_tags,
)
from yaraast.codegen.pretty_printer_helpers import (
    build_hex_pattern,
    calculate_meta_alignment_column,
    calculate_string_alignment_column,
    expression_to_string,
    format_plain_string,
    format_regex_string,
    modifiers_to_string,
)


def test_generator_formatting_helpers_cover_all_branches() -> None:
    assert format_rule_modifiers([]) == ""
    assert format_rule_modifiers(["private", "global"]) == "private global"
    assert format_rule_modifiers("private") == ""  # bare strings no longer accepted
    assert format_rule_modifiers(123) == ""

    assert format_rule_tags([]) == ""
    assert format_rule_tags(["t1", Tag(name="t2")]) == "t1 t2"

    assert format_meta_value("s", "x") == 's = "x"'
    assert format_meta_value("b", True) == "b = true"
    assert format_meta_value("n", 7) == "n = 7"

    assert escape_string_literal('a\\"b') == 'a\\\\\\"b'
    assert format_regex_literal("ab+", "is") == "/ab+/is"
    assert format_boolean_literal(True) == "true"
    assert format_boolean_literal(False) == "false"

    assert format_hex_jump(None, None) == "[-]"
    assert format_hex_jump(3, 3) == "[3]"
    assert format_hex_jump(None, 5) == "[-5]"
    assert format_hex_jump(2, None) == "[2-]"
    assert format_hex_jump(2, 5) == "[2-5]"


def test_pretty_printer_helpers_cover_all_branches() -> None:
    hex_node = HexString(
        "$h",
        tokens=[HexByte(0x4D), HexByte("5a"), HexJump(2, 2), HexJump(1, 3), SimpleNamespace()],
    )
    assert build_hex_pattern(hex_node, hex_uppercase=True, hex_spacing=True) == "4D 5A [2] [1-3] ??"
    assert build_hex_pattern(hex_node, hex_uppercase=False, hex_spacing=False) == "4d5a[2][1-3]??"

    plain = PlainString("$a", value="hello")
    regex = RegexString("$r", regex="ab+")
    assert format_plain_string(plain, '"', 3) == '$a    = "hello"'
    assert format_plain_string(plain, '"', 0) == '$a = "hello"'
    assert format_regex_string(regex, 2) == "$r   = /ab+/"
    assert format_regex_string(regex, 0) == "$r = /ab+/"

    assert modifiers_to_string([]) == ""
    assert (
        modifiers_to_string(
            [StringModifier.from_name_value("ascii"), StringModifier.from_name_value("nocase")]
        )
        == " ascii nocase"
    )

    ast = YaraFile(
        rules=[
            Rule(
                name="r",
                meta={"author": "me", "description": "x"},
                strings=[plain, HexString("$long_identifier", tokens=[]), regex],
                condition=BooleanLiteral(True),
            ),
            Rule(name="r2", meta=[], strings=[], condition=BooleanLiteral(True)),
        ]
    )
    assert calculate_string_alignment_column(ast) == len("$long_identifier") + 1
    # max() ensures alignment is at least min_alignment_column OR wide enough for longest key
    assert calculate_meta_alignment_column(ast, min_alignment_column=50) == 50  # min_alignment wins
    assert (
        calculate_meta_alignment_column(ast, min_alignment_column=5) == len("description =") + 2
    )  # key length wins

    assert expression_to_string(BooleanLiteral(True)) == "true"
    assert expression_to_string(Identifier("abc")) == "abc"
