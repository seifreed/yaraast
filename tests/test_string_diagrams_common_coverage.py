"""Coverage for the shared string-diagram hex-token formatting helpers."""

from __future__ import annotations

import pytest

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexWildcard,
)
from yaraast.metrics.string_diagrams_common import (
    _format_hex_alternative_branch,
    _format_hex_jump,
    _format_hex_nibble_value,
    _format_hex_value,
    format_hex_token_for_diagram,
)


def test_format_hex_token_for_each_type() -> None:
    assert format_hex_token_for_diagram(HexByte(value=0x4D)) == "4D"
    assert format_hex_token_for_diagram(HexWildcard()) == "??"
    assert format_hex_token_for_diagram(HexNegatedByte(value=0x90)) == "~90"
    assert format_hex_token_for_diagram(HexNibble(high=True, value=0xA)) == "A?"
    assert format_hex_token_for_diagram(HexNibble(high=False, value=0xB)) == "?B"
    assert format_hex_token_for_diagram(HexJump(min_jump=2, max_jump=2)) == "[2]"
    alt = HexAlternative(alternatives=[[HexByte(value=0x50)], [HexByte(value=0x4E)]])
    assert format_hex_token_for_diagram(alt) == "(50|4E)"


def test_format_hex_token_unknown_falls_back_to_str() -> None:
    assert format_hex_token_for_diagram("raw") == "raw"


@pytest.mark.parametrize(
    ("min_jump", "max_jump", "expected"),
    [
        (None, None, "[-]"),
        (None, 4, "[0-4]"),
        (2, None, "[2-]"),
        (0, 0, "[0-0]"),
        (3, 3, "[3]"),
        (3, 5, "[3-5]"),
    ],
)
def test_format_hex_jump_variants(min_jump, max_jump, expected) -> None:
    assert _format_hex_jump(HexJump(min_jump=min_jump, max_jump=max_jump)) == expected


def test_format_hex_value_int_and_string() -> None:
    assert _format_hex_value(0x4D) == "4D"
    assert _format_hex_value("4d") == "4D"
    assert _format_hex_nibble_value(0xA) == "A"
    assert _format_hex_nibble_value("a") == "A"


def test_format_hex_value_rejects_boolean() -> None:
    with pytest.raises(TypeError, match="Hex value cannot be boolean"):
        _format_hex_value(True)
    with pytest.raises(TypeError, match="Hex nibble value cannot be boolean"):
        _format_hex_nibble_value(False)


def test_format_hex_alternative_branch_list_and_scalar() -> None:
    assert _format_hex_alternative_branch([HexByte(value=0x50), HexByte(value=0x45)]) == "50 45"
    assert _format_hex_alternative_branch(0x50) == "50"
