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
    assert "PlainString: $a" in gen._generate_plain_diagram(plain)
    assert "RegexString: $b" in gen._generate_regex_diagram(regex)
    assert "HexString: $c" in gen._generate_hex_diagram(hexs)

    assert "6A ?? [2] (90|91)" in create_hex_diagram(hexs.tokens)
    regex_diag = create_regex_diagram("^[ab]+(cd)?$")
    assert "Pattern:" in regex_diag and "Capture groups" in regex_diag

    assert 'Value: "foobar"' in gen._generate_plain_diagram(plain)


def test_render_helpers_handle_byte_plain_strings() -> None:
    strings = [
        PlainString(identifier="$a", value=b"abc-common", modifiers=[]),
        PlainString(identifier="$b", value=b"abc-other", modifiers=[]),
        PlainString(identifier="$c", value=b"abc-common", modifiers=[]),
        PlainString(identifier="$np", value=b"ab\x00", modifiers=[]),
    ]

    diagram = StringDiagramGenerator()._generate_plain_diagram(strings[-1])
    assert 'Value: "ab\\x00"' in diagram

    analysis = analyze_string_patterns(strings)
    assert "abc-" in analysis["patterns"]["common_prefixes"]
    assert "abc-common" in analysis["patterns"]["duplicates"]


def test_plain_string_metrics_use_utf8_byte_length_for_text_values() -> None:
    strings = [PlainString(identifier="$u", value="á", modifiers=[])]

    diagram = StringDiagramGenerator()._generate_plain_diagram(strings[0])

    assert "Length: 2" in diagram


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

    assert analysis["patterns"]["common_prefixes"] == ["abc-"]
