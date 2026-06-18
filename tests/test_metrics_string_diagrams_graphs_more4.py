"""Additional real coverage for string diagram graph/stats/label helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import graphviz
import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexJump, HexString, HexWildcard, PlainString, RegexString
from yaraast.metrics.string_diagrams import StringDiagramGenerator
from yaraast.metrics.string_diagrams_graphs import StringDiagramGraphsMixin


class _DotFail:
    def __init__(self, source: str) -> None:
        self.source = source

    def render(self, *_args: object, **_kwargs: object) -> None:
        raise RuntimeError("failed to execute PosixPath('dot')")


class _DotBroken:
    source = "digraph { a }"

    def render(self, *_args: object, **_kwargs: object) -> None:
        raise AttributeError("render state missing")


def test_graph_helpers_fallbacks_and_empty_hex_source(tmp_path: Path) -> None:
    out = tmp_path / "fallback.svg"
    result = StringDiagramGraphsMixin._render_or_write_dot(
        _DotFail("digraph { a }"), str(out), "svg"
    )
    assert result.endswith(".svg")
    assert Path(result).read_text(encoding="utf-8") == "digraph { a }"

    real_dot = graphviz.Digraph(comment="ok")
    real_dot.node("a")
    real_svg = StringDiagramGraphsMixin._render_or_write_dot(
        real_dot,
        str(tmp_path / "ok.svg"),
        "svg",
    )
    assert real_svg.endswith(".svg")
    assert Path(real_svg).exists()

    ast = YaraFile(
        rules=[
            Rule(
                name="plain_only", strings=[PlainString(identifier="$a", value="abc", modifiers=[])]
            )
        ]
    )
    gen = StringDiagramGenerator()
    source = gen.generate_hex_pattern_diagram(ast)
    assert "No Hex Patterns Found" in source


def test_graph_helpers_propagate_non_graphviz_render_errors(tmp_path: Path) -> None:
    with pytest.raises(AttributeError, match="render state missing"):
        StringDiagramGraphsMixin._render_or_write_dot(
            _DotBroken(),
            str(tmp_path / "broken.svg"),
            "svg",
        )


@pytest.mark.parametrize("format", [None, 123])
def test_string_diagram_render_rejects_non_string_formats(
    tmp_path: Path,
    format: object,
) -> None:
    with pytest.raises(TypeError, match="graph format must be a string"):
        StringDiagramGraphsMixin._render_or_write_dot(
            _DotFail("digraph { a }"),
            str(tmp_path / "broken"),
            cast(Any, format),
        )


def test_string_diagram_render_rejects_empty_format(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="graph format must not be empty"):
        StringDiagramGraphsMixin._render_or_write_dot(
            _DotFail("digraph { a }"),
            str(tmp_path / "broken"),
            "",
        )


def test_string_diagram_render_rejects_empty_output_path() -> None:
    with pytest.raises(ValueError, match="output_path must not be empty"):
        StringDiagramGraphsMixin._render_or_write_dot(_DotFail("digraph { a }"), "", "dot")


def test_string_diagram_render_rejects_directory_output_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="output_path must not be a directory"):
        StringDiagramGraphsMixin._render_or_write_dot(_DotFail("digraph { a }"), tmp_path, "dot")


@pytest.mark.parametrize("output_path", [False, 0, object()])
def test_string_diagram_render_rejects_invalid_output_path_types(output_path: Any) -> None:
    with pytest.raises(TypeError, match="output_path must be a file path"):
        StringDiagramGraphsMixin._render_or_write_dot(
            _DotFail("digraph { a }"),
            cast(Any, output_path),
            "dot",
        )


def test_string_diagram_generators_reject_empty_output_path() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="plain_only", strings=[PlainString(identifier="$a", value="abc", modifiers=[])]
            )
        ]
    )

    with pytest.raises(ValueError, match="output_path must not be empty"):
        StringDiagramGenerator().generate_pattern_flow_diagram(ast, "", format="dot")


def test_graph_stats_and_labels_high_complexity_paths(tmp_path: Path) -> None:
    gen = StringDiagramGenerator()
    gen.string_patterns = {
        "p1": {
            "identifier": "$p1",
            "type": "plain",
            "value": "x" * 30,
            "length": 30,
            "rule": "r1",
            "modifiers": ["ascii"],
            "printable_ratio": 1.0,
        },
        "p2": {
            "identifier": "$p2",
            "type": "plain",
            "value": "x" * 30,
            "length": 30,
            "rule": "r1",
            "modifiers": [],
            "printable_ratio": 1.0,
        },
        "h1": {
            "identifier": "$h1",
            "type": "hex",
            "tokens": 60,
            "length": 60,
            "rule": "r1",
            "modifiers": ["wide"],
            "token_analysis": {
                "bytes": 10,
                "wildcards": 5,
                "jumps": 2,
                "alternatives": 1,
                "wildcard_ratio": 0.5,
                "complexity_score": 8,
            },
        },
        "r1": {
            "identifier": "$r1",
            "type": "regex",
            "pattern": "a" * 40,
            "length": 40,
            "rule": "r1",
            "modifiers": ["nocase"],
            "regex_analysis": {"groups": 2, "complexity_score": 7},
        },
    }

    # labels
    assert "..." in gen._create_pattern_label(gen.string_patterns["p1"])
    assert gen._create_hex_pattern_label(gen.string_patterns["h1"]).startswith("$h1")
    assert "..." in gen._create_regex_pattern_label(gen.string_patterns["r1"])
    assert gen._get_pattern_shape("other") == "ellipse"

    # stats
    stats = gen.get_pattern_statistics()
    assert stats["complexity_distribution"]["high"] >= 1
    assert stats["pattern_lengths"]["max"] == 60
    assert stats["modifiers_usage"]["ascii"] == 1
    assert gen._get_length_statistics() == {
        "min": 30,
        "max": 60,
        "avg": 40.0,
        "median": 35.0,
    }

    empty_gen = StringDiagramGenerator()
    assert empty_gen.get_pattern_statistics() == {
        "total_patterns": 0,
        "by_type": {"plain": 0, "hex": 0, "regex": 0},
        "complexity_distribution": {"low": 0, "medium": 0, "high": 0},
        "common_patterns": [],
        "pattern_lengths": {},
        "modifiers_usage": {},
    }
    assert empty_gen._get_length_statistics() == {}

    ast = YaraFile(
        rules=[
            Rule(
                name="r1",
                strings=[
                    PlainString(identifier="$p1", value="abcdefghijklmnopqrstuvwx", modifiers=[]),
                    PlainString(identifier="$p2", value="abcdefghijklmnopqrstuvwy", modifiers=[]),
                    HexString(
                        identifier="$h1",
                        tokens=[
                            HexByte(value=0x41),
                            HexWildcard(),
                            HexJump(min_jump=1, max_jump=4),
                            HexWildcard(),
                            HexJump(min_jump=2, max_jump=5),
                            HexWildcard(),
                        ],
                        modifiers=[],
                    ),
                    RegexString(identifier="$r1", regex="^(ab)+[0-9]{2,4}$", modifiers=[]),
                ],
            )
        ]
    )

    # graphs
    complexity_src = gen.generate_pattern_complexity_diagram(ast, format="dot")
    assert "lightcoral" in complexity_src
    assert "cluster_legend" in complexity_src

    similarity_src = gen.generate_pattern_similarity_diagram(ast, format="dot")
    assert "dashed" in similarity_src

    flow_src = gen.generate_pattern_flow_diagram(ast, format="dot")
    assert "Rule: r1" in flow_src
    assert "dotted" in flow_src

    hex_src = gen.generate_hex_pattern_diagram(ast, format="dot")
    assert "tokens" in hex_src
    assert "metrics" in hex_src

    out = tmp_path / "similarity.svg"
    svg_fallback = gen.generate_pattern_similarity_diagram(ast, str(out), format="svg")
    assert Path(svg_fallback).exists()


def test_pattern_length_statistics_uses_standard_even_median() -> None:
    gen = StringDiagramGenerator()
    gen.string_patterns = {
        "short": {"length": 10},
        "long": {"length": 20},
    }

    assert gen._get_length_statistics()["median"] == 15.0


def test_similarity_diagram_orders_patterns_within_groups() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="r1",
                strings=[
                    PlainString(identifier=f"$s{i}", value=f"alpha{i}", modifiers=[])
                    for i in range(10)
                ],
            )
        ]
    )

    source = StringDiagramGenerator().generate_pattern_similarity_diagram(ast, format="dot")

    positions = [source.index(f"\n\t\tpattern_{i} [") for i in range(1, 11)]
    assert positions == sorted(positions)

    edge_positions = [source.index(f"\tpattern_1 -> pattern_{i} [") for i in range(2, 11)]
    assert edge_positions == sorted(edge_positions)
