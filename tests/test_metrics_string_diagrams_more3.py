"""Additional real coverage for string diagram render/helpers."""

from __future__ import annotations

import importlib

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    PlainString,
    RegexString,
)
from yaraast.metrics import string_diagrams as _string_diagrams  # noqa: F401
from yaraast.metrics import string_diagrams_render as render
from yaraast.metrics.string_diagrams_render import StringDiagramRenderMixin

helpers = importlib.import_module("yaraast.metrics.string_diagrams_helpers")


class _NamedModifier:
    def __init__(self, name: str) -> None:
        self.name = name


class _Renderer(StringDiagramRenderMixin):
    pass


def test_render_mixin_object_modifiers_and_short_prefix_paths() -> None:
    r = _Renderer()

    plain = PlainString(identifier="$a", value="abx", modifiers=[_NamedModifier("ascii")])
    hexs = HexString(
        identifier="$h",
        tokens=[HexByte(value=0x41), HexJump(min_jump=1, max_jump=3)],
        modifiers=[_NamedModifier("wide")],
    )
    regex = RegexString(identifier="$r", regex="abc", modifiers=[_NamedModifier("nocase")])

    assert "Modifiers: ascii" in r._generate_plain_diagram(plain)
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


def test_render_and_helpers_regex_hex_reports_cover_remaining_branches() -> None:
    jump_tokens = [
        HexByte(value=0xAA),
        HexJump(min_jump=2, max_jump=5),
        HexAlternative(alternatives=[0x01, 0x02]),
    ]
    assert render.create_hex_diagram(jump_tokens) == "AA [2-5] (01|02)"
    assert helpers.create_hex_diagram(jump_tokens) == "AA [2-5] (01|02)"

    groups_only = helpers.create_regex_diagram("(ab)")
    assert "Capture groups:" in groups_only
    assert "Quantifiers:" not in groups_only
    assert "Anchors:" not in groups_only
    assert "Character classes:" not in groups_only

    quantifiers_only = helpers.create_regex_diagram("ab+")
    assert "Quantifiers:" in quantifiers_only

    anchors_only = helpers.create_regex_diagram("^ab$")
    assert "Anchors:" in anchors_only

    classes_only = helpers.create_regex_diagram("[0-9]")
    assert "Character classes:" in classes_only

    strings = [
        PlainString(identifier="$a", value="one", modifiers=[_NamedModifier("ascii")]),
        RegexString(identifier="$r", regex="ab+", modifiers=[_NamedModifier("nocase")]),
        HexString(
            identifier="$h", tokens=[HexByte(value=0x41)], modifiers=[_NamedModifier("wide")]
        ),
    ]

    render_report = render.generate_pattern_report(strings)
    helper_report = helpers.generate_pattern_report(strings)
    assert render_report["details"][1]["pattern"] == "ab+"
    assert helper_report["details"][1]["pattern"] == "ab+"
    assert render_report["details"][2]["tokens"] == 1
    assert helper_report["details"][2]["tokens"] == 1

    one_plain = helpers.analyze_string_patterns(
        [PlainString(identifier="$x", value="solo", modifiers=[])]
    )
    assert one_plain["patterns"]["common_prefixes"] == []
    assert one_plain["patterns"]["duplicates"] == []
