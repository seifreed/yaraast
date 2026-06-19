"""Additional real coverage for string diagram render helpers."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.modifiers import StringModifier
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
from yaraast.metrics import (
    string_diagram_primitives as primitives,
    string_diagrams_render as render,
)
from yaraast.metrics.string_diagrams_render import StringDiagramRenderMixin


class _NamedModifier:
    def __init__(self, name: str) -> None:
        self.name = name


class _Renderer(StringDiagramRenderMixin):
    pass


def test_render_mixin_object_modifiers_and_short_prefix_paths() -> None:
    r = _Renderer()

    plain = PlainString(identifier="$a", value="abx", modifiers=[_NamedModifier("ascii")])
    parameterized_plain = PlainString(
        identifier="$x",
        value="abc",
        modifiers=[StringModifier.from_name_value("xor", (1, 3))],
    )
    hexs = HexString(
        identifier="$h",
        tokens=[HexByte(value=0x41), HexJump(min_jump=1, max_jump=3)],
        modifiers=[_NamedModifier("wide")],
    )
    regex = RegexString(identifier="$r", regex="abc", modifiers=[_NamedModifier("nocase")])

    assert "Modifiers: ascii" in r._generate_plain_diagram(plain)
    assert "Modifiers: xor(1-3)" in r._generate_plain_diagram(parameterized_plain)
    assert "Modifiers: wide" in r._generate_hex_diagram(hexs)
    assert "Modifiers: nocase" in r._generate_regex_diagram(regex)

    analysis = render.analyze_string_patterns(
        [
            plain,
            PlainString(identifier="$b", value="aby", modifiers=[]),
        ]
    )
    assert analysis["patterns"]["common_prefixes"] == []
    assert analysis["patterns"]["duplicates"] == []


def test_render_pattern_analysis_reports_common_suffixes() -> None:
    strings = [
        PlainString(identifier="$a", value="red_tail", modifiers=[]),
        PlainString(identifier="$b", value="blue_tail", modifiers=[]),
        PlainString(identifier="$c", value="green_tail", modifiers=[]),
    ]

    render_analysis = render.analyze_string_patterns(strings)
    assert "_tail" in render_analysis["patterns"]["common_suffixes"]


def test_render_pattern_report_counts_triplicate_plain_value_as_one_unique() -> None:
    strings = [
        PlainString(identifier="$a", value="same", modifiers=[]),
        PlainString(identifier="$b", value="same", modifiers=[]),
        PlainString(identifier="$c", value="same", modifiers=[]),
    ]

    assert render.analyze_string_patterns(strings)["patterns"]["duplicates"] == ["same"]


def test_render_regex_hex_reports_cover_remaining_branches() -> None:
    jump_tokens = [
        HexByte(value=0xAA),
        HexJump(min_jump=0, max_jump=0),
        HexJump(min_jump=2, max_jump=5),
        HexAlternative(alternatives=[0x01, 0x02]),
    ]
    assert primitives.create_hex_diagram(jump_tokens) == "AA [0-0] [2-5] (01|02)"

    complex_tokens = [
        HexByte(value="af"),
        HexNegatedByte(value=0x4D),
        HexNibble(high=False, value="B"),
        HexAlternative(
            alternatives=[
                [HexByte(value=0x41)],
                [HexWildcard()],
                [HexNibble(high=True, value=0xC)],
                [HexJump(min_jump=None, max_jump=5)],
            ]
        ),
    ]
    expected_complex = "AF ~4D ?B (41|??|C?|[0-5])"
    assert primitives.create_hex_diagram(complex_tokens) == expected_complex
    assert expected_complex in _Renderer()._generate_hex_diagram(
        HexString(identifier="$complex", tokens=complex_tokens)
    )

    groups_only = primitives.create_regex_diagram("(ab)")
    assert "Capture groups:" in groups_only
    assert "Quantifiers:" not in groups_only
    assert "Anchors:" not in groups_only
    assert "Character classes:" not in groups_only

    quantifiers_only = primitives.create_regex_diagram("ab+")
    assert "Quantifiers:" in quantifiers_only

    anchors_only = primitives.create_regex_diagram("^ab$")
    assert "Anchors:" in anchors_only

    classes_only = primitives.create_regex_diagram("[0-9]")
    assert "Character classes:" in classes_only

    alphabet = "A" * 64
    strings = [
        PlainString(
            identifier="$a",
            value="one",
            modifiers=[StringModifier.from_name_value("base64", alphabet)],
        ),
        RegexString(identifier="$r", regex="ab+", modifiers=[_NamedModifier("nocase")]),
        HexString(
            identifier="$h", tokens=[HexByte(value=0x41)], modifiers=[_NamedModifier("wide")]
        ),
    ]

    analysis = render.analyze_string_patterns(strings)
    assert analysis["types"]["plain"] == 1
    assert analysis["types"]["regex"] == 1
    assert analysis["types"]["hex"] == 1


def test_hex_diagrams_reject_boolean_hex_values() -> None:
    invalid_tokens = [
        HexByte(value=cast(Any, True)),
        HexNegatedByte(value=cast(Any, False)),
        HexNibble(high=True, value=cast(Any, True)),
        HexAlternative(alternatives=[cast(Any, False)]),
    ]

    for token in invalid_tokens:
        with pytest.raises(TypeError, match="boolean"):
            primitives.create_hex_diagram([token])
