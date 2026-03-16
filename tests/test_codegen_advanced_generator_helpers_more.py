"""More coverage for advanced code generator helpers."""

from __future__ import annotations

from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.codegen.advanced_generator_helpers import (
    _format_hex_jump,
    collect_string_definitions,
    format_hex_string,
    format_hex_token,
    get_tag_string,
)
from yaraast.codegen.formatting import FormattingConfig, HexStyle, StringStyle


class _TagObj:
    def __init__(self, name: str) -> None:
        self.name = name


def test_collect_string_definitions_supports_all_string_types() -> None:
    config = FormattingConfig(hex_style=HexStyle.UPPERCASE, hex_group_size=2)
    mod1 = StringModifier(StringModifierType.NOCASE)
    mod2 = StringModifier(StringModifierType.XOR, value=3)

    plain = PlainString(identifier="$a", value="hello", modifiers=[mod1])
    hexs = HexString(
        identifier="$b",
        tokens=[
            HexByte(0xAA),
            HexWildcard(),
            HexJump(1, 3),
            HexAlternative(alternatives=[[HexByte(0x10)], [HexNibble(high=False, value=0xF)]]),
            HexNibble(high=True, value=0xC),
        ],
        modifiers=[mod2],
    )
    regex = RegexString(identifier="$c", regex="ab+", modifiers=[])
    unknown = StringDefinition(identifier="$d", modifiers=[])

    collected = collect_string_definitions([plain, hexs, regex, unknown], config)

    assert collected[0] == ("$a", '"hello"', ["nocase"])
    assert collected[1][0] == "$b"
    assert collected[1][1].startswith("{ ")
    assert "AA??" in collected[1][1]
    assert "xor(3)" in collected[1][2]
    assert collected[2] == ("$c", "/ab+/", [])
    assert collected[3] == ("$d", "", [])


def test_format_hex_string_grouping_and_token_rendering() -> None:
    config = FormattingConfig(hex_style=HexStyle.UPPERCASE, hex_group_size=3)
    node = HexString(
        identifier="$x",
        tokens=[
            HexByte(0xAB),
            HexWildcard(),
            HexJump(None, None),
            HexJump(None, 5),
            HexJump(2, None),
            HexJump(7, 7),
            HexAlternative(alternatives=[[HexByte(0x0F)], [HexWildcard()]]),
            HexNibble(high=False, value=0xE),
            HexNibble(high=True, value=0xD),
        ],
    )

    out = format_hex_string(node, config)

    assert out.startswith("{ ") and out.endswith(" }")
    assert "AB??[-]" in out
    assert "[-5][2-][7]" in out
    assert "(0F | ??)" in out
    assert "?E" in out and "D?" in out


def test_format_hex_string_no_grouping_and_single_token_formatting() -> None:
    lower = FormattingConfig(hex_style=HexStyle.LOWERCASE, hex_group_size=0)
    upper = FormattingConfig(hex_style=HexStyle.UPPERCASE, hex_group_size=0)

    assert format_hex_token(HexByte(0xAF), lower) == "af"
    assert format_hex_token(HexByte(0xAF), upper) == "AF"
    assert format_hex_token(HexWildcard(), lower) == "??"
    assert format_hex_token(HexJump(1, 2), lower) == ""

    hs = HexString(identifier="$h", tokens=[HexByte(0x01), HexWildcard()])
    assert format_hex_string(hs, lower) == "{ 01 ?? }"


def test_get_tag_string_and_hex_jump_ranges() -> None:
    compact_cfg = FormattingConfig(string_style=StringStyle.COMPACT)
    aligned_cfg = FormattingConfig(string_style=StringStyle.ALIGNED)

    assert get_tag_string([], compact_cfg) == ""
    assert get_tag_string([_TagObj("alpha"), "beta"], compact_cfg) == "alpha beta"
    assert get_tag_string([_TagObj("x"), "y"], aligned_cfg) == "x y"

    assert _format_hex_jump(HexJump(None, None)) == "[-]"
    assert _format_hex_jump(HexJump(None, 4)) == "[-4]"
    assert _format_hex_jump(HexJump(3, None)) == "[3-]"
    assert _format_hex_jump(HexJump(6, 6)) == "[6]"
    assert _format_hex_jump(HexJump(2, 9)) == "[2-9]"
