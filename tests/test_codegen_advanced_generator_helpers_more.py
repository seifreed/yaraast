"""More coverage for advanced code generator helpers."""

from __future__ import annotations

from typing import Any

import pytest

from yaraast.ast.modifiers import StringModifier, StringModifierType
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
    mod2 = StringModifier(StringModifierType.PRIVATE)

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
    collected = collect_string_definitions([plain, hexs, regex], config)

    assert collected[0] == ("$a", '"hello"', ["nocase"])
    assert collected[1][0] == "$b"
    assert collected[1][1].startswith("{ ")
    assert "AA??" in collected[1][1]
    assert "private" in collected[1][2]
    assert collected[2] == ("$c", "/ab+/", [])


def test_collect_string_definitions_rejects_unsupported_string_type() -> None:
    config = FormattingConfig(hex_style=HexStyle.UPPERCASE, hex_group_size=2)

    with pytest.raises(TypeError, match="Unsupported string definition"):
        collect_string_definitions([StringDefinition(identifier="$d", modifiers=[])], config)


def test_collect_string_definitions_rejects_unsupported_regex_multiline_modifier() -> None:
    config = FormattingConfig()
    regex = RegexString(
        identifier="$r",
        regex="^line",
        modifiers=[StringModifier(StringModifierType.MULTILINE)],
    )

    with pytest.raises(ValueError, match="Unsupported regex modifier"):
        collect_string_definitions([regex], config)


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
    assert "[0-5][2-][7]" in out
    assert "(0F | ??)" in out
    assert "?E" in out and "D?" in out


def test_format_hex_string_no_grouping_and_single_token_formatting() -> None:
    lower = FormattingConfig(hex_style=HexStyle.LOWERCASE, hex_group_size=0)
    upper = FormattingConfig(hex_style=HexStyle.UPPERCASE, hex_group_size=0)

    assert format_hex_token(HexByte(0xAF), lower) == "af"
    assert format_hex_token(HexByte(0xAF), upper) == "AF"
    assert format_hex_token(HexByte("af"), upper) == "AF"
    assert format_hex_token(HexWildcard(), lower) == "??"
    assert format_hex_token(HexJump(1, 2), lower) == "[1-2]"
    assert format_hex_token(HexNibble(high=True, value=0xA), lower) == "a?"
    assert format_hex_token(HexNibble(high=False, value="B"), lower) == "?b"
    assert format_hex_token(HexNegatedByte(0xAF), lower) == "~af"

    hs = HexString(
        identifier="$h",
        tokens=[HexByte(0x01), HexWildcard(), HexNegatedByte(0x40), HexByte("af")],
    )
    assert format_hex_string(hs, lower) == "{ 01 ?? ~40 af }"

    scalar_alt = HexString(identifier="$s", tokens=[HexAlternative([0x90, "91"])])
    assert format_hex_string(scalar_alt, upper) == "{ (90 | 91) }"

    complex_alt = HexString(
        identifier="$complex",
        tokens=[
            HexAlternative(
                [
                    [HexNibble(high=True, value=0x4)],
                    [HexNegatedByte(0x41)],
                    [HexByte(0x41), HexJump(1, 2), HexByte(0x42)],
                    [HexWildcard()],
                ]
            )
        ],
    )
    assert format_hex_string(complex_alt, upper) == "{ (4? | ~41 | 41 [1-2] 42 | ??) }"


@pytest.mark.parametrize(
    ("token", "message"),
    [
        (HexByte(True), "HexByte value must be a byte"),
        (HexByte(0x100), "HexByte value must be a byte"),
        (HexNegatedByte(True), "HexNegatedByte value must be a byte"),
        (HexNibble(high=True, value=True), "HexNibble value must be a nibble"),
        (HexNibble(high=False, value=0x10), "HexNibble value must be a nibble"),
        (HexJump(True, 1), "HexJump min_jump must be a non-negative integer"),
        (HexJump(2, 1), "HexJump min_jump cannot exceed max_jump"),
        (object(), "Unsupported hex token"),
    ],
)
def test_advanced_generator_helpers_reject_invalid_direct_hex_tokens(
    token: object,
    message: str,
) -> None:
    config = FormattingConfig(hex_style=HexStyle.UPPERCASE, hex_group_size=0)

    with pytest.raises(TypeError, match=message):
        format_hex_string(HexString("$h", tokens=[token]), config)


def test_advanced_generator_helpers_reject_unsupported_hex_token_formatting() -> None:
    config = FormattingConfig(hex_style=HexStyle.UPPERCASE, hex_group_size=0)
    token: Any = object()

    with pytest.raises(TypeError, match="Unsupported hex token"):
        format_hex_token(token, config)


def test_advanced_generator_helpers_reject_invalid_hex_alternative_scalar() -> None:
    config = FormattingConfig(hex_style=HexStyle.UPPERCASE, hex_group_size=0)

    with pytest.raises(TypeError, match="HexByte value must be a byte"):
        format_hex_string(HexString("$h", tokens=[HexAlternative([True])]), config)


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
def test_advanced_generator_helpers_reject_invalid_hex_string_structure(
    tokens: list[object],
    message: str,
) -> None:
    config = FormattingConfig(hex_style=HexStyle.UPPERCASE, hex_group_size=0)

    with pytest.raises(ValueError, match=message):
        format_hex_string(HexString("$h", tokens=tokens), config)


def test_get_tag_string_and_hex_jump_ranges() -> None:
    compact_cfg = FormattingConfig(string_style=StringStyle.COMPACT)
    aligned_cfg = FormattingConfig(string_style=StringStyle.ALIGNED)

    assert get_tag_string([], compact_cfg) == ""
    assert get_tag_string([_TagObj("alpha"), "beta"], compact_cfg) == "alpha beta"
    assert get_tag_string([_TagObj("x"), "y"], aligned_cfg) == "x y"

    assert _format_hex_jump(HexJump(None, None)) == "[-]"
    assert _format_hex_jump(HexJump(None, 4)) == "[0-4]"
    assert _format_hex_jump(HexJump(3, None)) == "[3-]"
    assert _format_hex_jump(HexJump(0, 0)) == "[0-0]"
    assert _format_hex_jump(HexJump(6, 6)) == "[6]"
    assert _format_hex_jump(HexJump(2, 9)) == "[2-9]"
