"""Extra branch coverage for metrics/string_diagrams_render.py."""

from __future__ import annotations

from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.metrics.string_diagrams_render import (
    StringDiagramRenderMixin,
    analyze_string_patterns,
    create_hex_diagram,
    create_regex_diagram,
    generate_pattern_report,
    generate_string_diagram,
)


class _Renderer(StringDiagramRenderMixin):
    pass


def test_render_mixin_branches_plain_hex_regex() -> None:
    r = _Renderer()

    plain = PlainString(identifier="$a", value="abc", modifiers=[])
    assert "Length: 3" in r._generate_plain_diagram(plain)

    plain_mod = PlainString(identifier="$am", value="abc", modifiers=["ascii"])
    assert "Modifiers: ascii" in r._generate_plain_diagram(plain_mod)

    hx = HexString(
        identifier="$h",
        tokens=[
            HexByte(value=0x41),
            HexWildcard(),
            HexJump(min_jump=2, max_jump=2),
            HexJump(min_jump=1, max_jump=3),
            HexAlternative(alternatives=[0x90, 0x91]),
        ],
        modifiers=["wide"],
    )
    hex_diag = r._generate_hex_diagram(hx)
    assert "41" in hex_diag
    assert "??" in hex_diag
    assert "[2]" in hex_diag
    assert "[1-3]" in hex_diag
    assert "(90|91)" in hex_diag
    assert "Modifiers: wide" in hex_diag

    rg = RegexString(identifier="$r", regex="^(ab)+$", modifiers=["nocase"])
    rg_diag = r._generate_regex_diagram(rg)
    assert "Capture Groups:" in rg_diag
    assert "Quantifiers:" in rg_diag
    assert "Modifiers: nocase" in rg_diag

    rg_simple = RegexString(identifier="$r2", regex="abc", modifiers=[])
    rg_simple_diag = r._generate_regex_diagram(rg_simple)
    assert "Capture Groups:" not in rg_simple_diag
    assert "Quantifiers:" not in rg_simple_diag


def test_render_convenience_functions_and_reports() -> None:
    plain = PlainString(identifier="$a", value="abc", modifiers=[])
    conv = generate_string_diagram(plain)
    assert "PlainString" in conv

    hex_line = create_hex_diagram(
        [
            HexByte(value=0xAA),
            HexWildcard(),
            HexJump(min_jump=2, max_jump=2),
            HexAlternative(alternatives=[0x01, 0x02]),
        ]
    )
    assert hex_line == "AA ?? [2] (01|02)"

    regex_diag = create_regex_diagram("^(ab)+[0-9]$")
    assert "Pattern:" in regex_diag
    assert "Capture groups:" in regex_diag
    assert "Quantifiers:" in regex_diag
    assert "Anchors:" in regex_diag
    assert "Character classes:" in regex_diag

    strings = [
        PlainString(identifier="$a", value="one", modifiers=["ascii"]),
        PlainString(identifier="$b", value="one", modifiers=[]),
        RegexString(identifier="$r", regex="ab+", modifiers=[]),
        HexString(identifier="$h", tokens=[HexByte(value=0x41)], modifiers=[]),
    ]

    analysis = analyze_string_patterns(strings)
    assert analysis["types"]["plain"] == 2
    assert analysis["types"]["regex"] == 1
    assert analysis["types"]["hex"] == 1
    assert "one" in analysis["patterns"]["duplicates"]

    report = generate_pattern_report(strings)
    assert report["summary"]["total"] == 4
    assert report["summary"]["unique_patterns"] == 3
    assert len(report["details"]) == 4
