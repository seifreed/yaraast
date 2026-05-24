"""Tests for small codegen formatting helper modules."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.codegen.generator_formatting import (
    escape_string_literal,
    format_boolean_literal,
    format_hex_jump,
    format_meta_value,
    format_regex_literal,
    format_rule_modifiers,
    format_rule_tags,
)
from yaraast.codegen.generator_helpers import escape_regex_delimiter
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
    with pytest.raises(ValueError, match="Duplicate tag identifier"):
        format_rule_tags(["t1", Tag(name="t1")])

    assert format_meta_value("s", "x") == 's = "x"'
    assert format_meta_value("b", True) == "b = true"
    assert format_meta_value("n", 7) == "n = 7"

    assert escape_string_literal('a\\"b') == 'a\\\\\\"b'
    assert escape_string_literal("a\nb\t\x00") == "a\\nb\\t\\x00"
    assert format_regex_literal("ab+", "is") == "/ab+/is"
    with pytest.raises(ValueError, match="Invalid regex modifier: m"):
        format_regex_literal("ab+", "m")
    with pytest.raises(ValueError, match="Duplicate regex modifier: i"):
        format_regex_literal("ab+", "ii")
    assert escape_regex_delimiter("a/b") == "a\\/b"
    assert escape_regex_delimiter("a\\/b") == "a\\/b"
    assert format_regex_literal("a\\/b", "") == "/a\\/b/"
    assert format_boolean_literal(True) == "true"
    assert format_boolean_literal(False) == "false"

    assert format_hex_jump(None, None) == "[-]"
    assert format_hex_jump(0, 0) == "[0-0]"
    assert format_hex_jump(3, 3) == "[3]"
    assert format_hex_jump(None, 5) == "[0-5]"
    assert format_hex_jump(2, None) == "[2-]"
    assert format_hex_jump(2, 5) == "[2-5]"


def test_pretty_printer_helpers_cover_all_branches() -> None:
    hex_node = HexString(
        "$h",
        tokens=[
            HexByte(0x4D),
            HexByte("5a"),
            HexJump(0, 0),
            HexJump(2, 2),
            HexJump(1, 3),
            SimpleNamespace(),
        ],
    )
    assert (
        build_hex_pattern(hex_node, hex_uppercase=True, hex_spacing=True)
        == "4D 5A [0-0] [2] [1-3] ??"
    )
    assert (
        build_hex_pattern(hex_node, hex_uppercase=False, hex_spacing=False) == "4d5a[0-0][2][1-3]??"
    )

    complex_hex_node = HexString(
        "$complex",
        tokens=[
            HexByte("af"),
            HexNegatedByte(0x4D),
            HexNibble(high=False, value="B"),
            HexAlternative(
                [
                    [HexByte(0x41), HexByte("42")],
                    [HexWildcard()],
                    [HexByte(0x43), HexJump(None, 5), HexByte(0x44)],
                    [HexNibble(high=True, value=0xC)],
                ]
            ),
        ],
    )
    assert (
        build_hex_pattern(complex_hex_node, hex_uppercase=True, hex_spacing=True)
        == "AF ~4D ?B (41 42 | ?? | 43 [0-5] 44 | C?)"
    )
    assert (
        build_hex_pattern(complex_hex_node, hex_uppercase=False, hex_spacing=False)
        == "af~4d?b(4142|??|43[0-5]44|c?)"
    )

    plain = PlainString("$a", value="hello")
    bytes_plain = PlainString("$b", value=b'A"\x00\xff\\\n')
    regex = RegexString("$r", regex="ab+")
    regex_with_slash = RegexString("$s", regex="a\\/b")
    assert format_plain_string(plain, '"', 3) == '$a    = "hello"'
    assert format_plain_string(plain, '"', 0) == '$a = "hello"'
    assert format_plain_string(bytes_plain, '"', 0) == '$b = "A\\"\\x00\\xff\\\\\\n"'
    assert format_regex_string(regex, 2) == "$r   = /ab+/"
    assert format_regex_string(regex, 0) == "$r = /ab+/"
    assert format_regex_string(regex_with_slash, 0) == "$s = /a\\/b/"

    assert modifiers_to_string([]) == ""
    assert (
        modifiers_to_string(
            [StringModifier.from_name_value("ascii"), StringModifier.from_name_value("nocase")]
        )
        == " ascii nocase"
    )
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    assert (
        modifiers_to_string(
            [
                StringModifier.from_name_value("xor", (1, 3)),
                StringModifier.from_name_value("base64", alphabet),
            ]
        )
        == f' xor(1-3) base64("{alphabet}")'
    )
    assert modifiers_to_string([StringModifier.from_name_value("xor", "0x10")]) == " xor(0x10)"
    assert (
        modifiers_to_string([StringModifier.from_name_value("xor", "0x01-0xff")])
        == " xor(0x01-0xff)"
    )
    escaped_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"\\'
    assert (
        modifiers_to_string([StringModifier.from_name_value("base64", escaped_alphabet)])
        == ' base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\\"\\\\")'
    )
    with pytest.raises(TypeError, match="xor value must be a byte"):
        modifiers_to_string([StringModifier.from_name_value("xor", True)])
    with pytest.raises(TypeError, match="xor range value must contain byte bounds"):
        modifiers_to_string([StringModifier.from_name_value("xor", (True, 3))])
    with pytest.raises(TypeError, match="xor range value must be ascending"):
        modifiers_to_string([StringModifier.from_name_value("xor", (4, 3))])
    with pytest.raises(TypeError, match="base64wide value must be a string"):
        modifiers_to_string([StringModifier.from_name_value("base64wide", True)])
    for value in ("custom", "A" * 63, "A" * 65):
        with pytest.raises(TypeError, match="base64 alphabet must be 64 bytes"):
            modifiers_to_string([StringModifier.from_name_value("base64", value)])
    with pytest.raises(ValueError, match="Duplicate string modifier"):
        modifiers_to_string(
            [
                StringModifier.from_name_value("ascii"),
                StringModifier.from_name_value("ascii"),
            ]
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


@pytest.mark.parametrize(
    ("token", "message"),
    [
        (HexByte(True), "HexByte value must be a byte"),
        (HexByte(-1), "HexByte value must be a byte"),
        (HexNegatedByte(True), "HexNegatedByte value must be a byte"),
        (HexNibble(high=True, value=True), "HexNibble value must be a nibble"),
        (HexNibble(high=False, value=0x10), "HexNibble value must be a nibble"),
        (HexJump(True, 1), "HexJump min_jump must be a non-negative integer"),
        (HexJump(2, 1), "HexJump min_jump cannot exceed max_jump"),
    ],
)
def test_pretty_printer_helpers_reject_invalid_direct_hex_tokens(
    token: object,
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        build_hex_pattern(HexString("$h", tokens=[token]), hex_uppercase=True, hex_spacing=True)


def test_pretty_printer_helpers_reject_invalid_hex_alternative_scalar() -> None:
    with pytest.raises(TypeError, match="HexByte value must be a byte"):
        build_hex_pattern(
            HexString("$h", tokens=[HexAlternative([True])]),
            hex_uppercase=True,
            hex_spacing=True,
        )


@pytest.mark.parametrize(
    ("tokens", "message"),
    [
        ([], "Hex string must contain at least one token"),
        ([HexJump(0, 1), HexByte(0x41)], "HexJump cannot appear"),
        ([HexByte(0x41), HexJump(0, 1)], "HexJump cannot appear"),
        ([HexAlternative([])], "HexAlternative must contain at least one branch"),
        ([HexAlternative([[]])], "HexAlternative branches must not be empty"),
        (
            [HexAlternative([[HexByte(0x41), HexJump(1, None), HexByte(0x42)]])],
            "Unbounded HexJump is not allowed inside hex alternatives",
        ),
    ],
)
def test_pretty_printer_helpers_reject_invalid_hex_string_structure(
    tokens: list[object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        build_hex_pattern(HexString("$h", tokens=tokens), hex_uppercase=True, hex_spacing=True)
