"""Additional tests for string diagram render helpers without mocks."""

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
from yaraast.metrics.string_diagrams import (
    StringDiagramGenerator,
    analyze_string_patterns,
    create_hex_diagram,
    create_regex_diagram,
    generate_pattern_report,
    generate_string_diagram,
)


def test_render_mixin_and_convenience_functions() -> None:
    plain = PlainString(identifier="$a", value="foobar", modifiers=["ascii"])
    regex = RegexString(identifier="$b", regex="^(ab)+$", modifiers=["nocase"])
    hexs = HexString(
        identifier="$c",
        tokens=[
            HexByte(value=0x6A),
            HexWildcard(),
            HexJump(min_jump=2, max_jump=2),
            HexAlternative(alternatives=[0x90, 0x91]),
        ],
        modifiers=["wide"],
    )

    gen = StringDiagramGenerator()
    assert "PlainString: $a" in gen.generate(plain)
    assert "RegexString: $b" in gen.generate(regex)
    assert "HexString: $c" in gen.generate(hexs)
    assert "Unknown string type" in gen.generate(object())

    assert "6A ?? [2] (90|91)" in create_hex_diagram(hexs.tokens)
    regex_diag = create_regex_diagram("^[ab]+(cd)?$")
    assert "Pattern:" in regex_diag and "Capture groups" in regex_diag

    conv = generate_string_diagram(plain)
    assert 'Value: "foobar"' in conv


def test_analyze_and_report_patterns() -> None:
    strings = [
        PlainString(identifier="$a", value="abc-common", modifiers=["ascii"]),
        PlainString(identifier="$b", value="abc-other", modifiers=["ascii"]),
        PlainString(identifier="$c", value="abc-common", modifiers=["wide"]),
        RegexString(identifier="$r", regex="ab+", modifiers=[]),
        HexString(identifier="$h", tokens=[HexByte(value=0x41)], modifiers=[]),
    ]

    analysis = analyze_string_patterns(strings)
    assert analysis["total_strings"] == 5
    assert analysis["types"]["plain"] == 3
    assert "abc-" in analysis["patterns"]["common_prefixes"]
    assert "abc-common" in analysis["patterns"]["duplicates"]

    report = generate_pattern_report(strings)
    assert report["summary"]["total"] == 5
    assert len(report["details"]) == 5
