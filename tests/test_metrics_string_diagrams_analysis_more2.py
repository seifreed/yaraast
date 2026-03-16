"""Extra coverage for metrics.string_diagrams_analysis mixin."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexJump, HexString, HexWildcard, PlainString, RegexString
from yaraast.metrics.string_diagrams import StringDiagramGenerator


def test_analysis_mixin_core_paths() -> None:
    gen = StringDiagramGenerator()
    ast = YaraFile(
        rules=[
            Rule(
                name="r1",
                strings=[
                    PlainString(identifier="$a", value="abcDEF", modifiers=[]),
                    PlainString(identifier="$b", value="ab\n", modifiers=[]),
                    HexString(
                        identifier="$h",
                        tokens=[
                            HexByte(value=0x41),
                            HexWildcard(),
                            HexJump(min_jump=1, max_jump=3),
                        ],
                        modifiers=[],
                    ),
                    RegexString(identifier="$r", regex="^(ab)+[0-9]$", modifiers=[]),
                ],
            )
        ]
    )

    gen._analyze_patterns(ast)
    assert len(gen.string_patterns) == 4
    assert any(p["type"] == "plain" for p in gen.string_patterns.values())
    assert any(p["type"] == "hex" for p in gen.string_patterns.values())
    assert any(p["type"] == "regex" for p in gen.string_patterns.values())

    # printable ratio
    assert gen._calculate_printable_ratio("") == 0.0
    assert 0.0 < gen._calculate_printable_ratio("abc\n") < 1.0

    # hex token analysis
    empty_hex = gen._analyze_hex_tokens([])
    assert empty_hex["wildcard_ratio"] == 0.0
    rich_hex = gen._analyze_hex_tokens(
        [HexByte(value=0x41), HexWildcard(), HexJump(min_jump=1, max_jump=2)]
    )
    assert rich_hex["bytes"] == 1 and rich_hex["wildcards"] == 1 and rich_hex["jumps"] == 1

    # regex analysis
    ra = gen._analyze_regex_pattern("^(ab)+[0-9]$")
    assert ra["groups"] >= 1 and ra["quantifiers"] >= 1


def test_analysis_similarity_and_grouping_paths() -> None:
    gen = StringDiagramGenerator()
    gen.string_patterns = {
        "p1": {
            "type": "plain",
            "length": 5,
            "value": "abcde",
            "printable_ratio": 1.0,
            "modifiers": [],
        },
        "p2": {
            "type": "plain",
            "length": 20,
            "value": "abcdef" * 3,
            "printable_ratio": 1.0,
            "modifiers": ["ascii"],
        },
        "p3": {
            "type": "plain",
            "length": 60,
            "value": "x" * 60,
            "printable_ratio": 0.5,
            "modifiers": [],
        },
        "h1": {
            "type": "hex",
            "token_analysis": {"wildcard_ratio": 0.1, "complexity_score": 2},
            "modifiers": [],
        },
        "h2": {
            "type": "hex",
            "token_analysis": {"wildcard_ratio": 0.8, "complexity_score": 4},
            "modifiers": [],
        },
        "r1": {
            "type": "regex",
            "pattern": "ab+",
            "regex_analysis": {"complexity_score": 3},
            "modifiers": [],
        },
        "r2": {
            "type": "regex",
            "pattern": "",
            "regex_analysis": {"complexity_score": 1},
            "modifiers": [],
        },
    }

    groups = gen._find_similar_patterns()
    assert "Short Plain" in groups
    assert "Medium Plain" in groups
    assert "Long Plain" in groups
    assert "Precise Hex" in groups
    assert "Flexible Hex" in groups
    assert "Regex" in groups

    # complexity calculator by type
    assert gen._calculate_pattern_complexity(gen.string_patterns["p3"]) > 1
    assert gen._calculate_pattern_complexity(gen.string_patterns["h1"]) > 1
    assert gen._calculate_pattern_complexity(gen.string_patterns["r1"]) > 1

    # similarity
    assert gen._calculate_similarity(gen.string_patterns["p1"], gen.string_patterns["h1"]) == 0.0
    assert (
        gen._calculate_similarity(
            gen.string_patterns["p1"], {"type": "plain", "value": "", "modifiers": []}
        )
        == 0.0
    )
    assert (
        0.0
        <= gen._calculate_similarity(gen.string_patterns["p1"], gen.string_patterns["p2"])
        <= 1.0
    )
    assert (
        0.0
        <= gen._calculate_similarity(gen.string_patterns["h1"], gen.string_patterns["h2"])
        <= 1.0
    )
    assert gen._calculate_similarity(gen.string_patterns["r2"], gen.string_patterns["r1"]) == 0.0
    assert (
        0.0
        <= gen._calculate_similarity(
            gen.string_patterns["r1"], {"type": "regex", "pattern": "ac+", "modifiers": []}
        )
        <= 1.0
    )
