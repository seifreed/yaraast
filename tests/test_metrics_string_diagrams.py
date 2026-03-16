"""Tests for string diagram generator (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.metrics.string_diagrams import StringDiagramGenerator
from yaraast.parser import Parser


def _parse_yara(code: str):
    parser = Parser()
    return parser.parse(dedent(code))


def test_string_diagram_generators(tmp_path) -> None:
    code = """
    rule patterns {
        strings:
            $a = "hello"
            $b = "hELLo!"
            $c = /ab+c/
            $d = { 6A 40 ?? 0F }
        condition:
            any of them
    }
    """
    ast = _parse_yara(code)
    gen = StringDiagramGenerator()

    flow_path = tmp_path / "flow.dot"
    flow = gen.generate_pattern_flow_diagram(ast, str(flow_path), format="dot")
    assert flow.endswith(".dot")
    assert flow_path.exists()

    complexity_path = tmp_path / "complexity.dot"
    comp = gen.generate_pattern_complexity_diagram(ast, str(complexity_path), format="dot")
    assert comp.endswith(".dot")
    assert complexity_path.exists()

    similarity_path = tmp_path / "similarity.dot"
    sim = gen.generate_pattern_similarity_diagram(ast, str(similarity_path), format="dot")
    assert sim.endswith(".dot")
    assert similarity_path.exists()

    hex_path = tmp_path / "hex.dot"
    hex_out = gen.generate_hex_pattern_diagram(ast, str(hex_path), format="dot")
    assert hex_out.endswith(".dot")
    assert hex_path.exists()

    stats = gen.get_pattern_statistics()
    assert stats["total_patterns"] >= 4
    assert stats["by_type"]["plain"] >= 2
    assert stats["by_type"]["regex"] >= 1
    assert stats["by_type"]["hex"] >= 1


def test_hex_diagram_empty(tmp_path) -> None:
    code = """
    rule no_hex {
        strings:
            $a = "plain"
        condition:
            $a
    }
    """
    ast = _parse_yara(code)
    gen = StringDiagramGenerator()
    out = tmp_path / "no_hex.dot"
    result = gen.generate_hex_pattern_diagram(ast, str(out), format="dot")
    assert result.endswith(".dot")
    assert out.exists()
