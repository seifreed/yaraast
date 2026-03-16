"""Extra real coverage for condition builder, hex builder, and HTML tree nodes."""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import Identifier
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.metrics.html_tree import HtmlTreeGenerator


def test_condition_builder_n_of_them_and_empty_arithmetic_error() -> None:
    expr = ConditionBuilder().n_of(2, "them").build()
    assert isinstance(expr.string_set, Identifier)
    assert expr.string_set.name == "them"

    with pytest.raises(ValueError, match="Cannot apply \\+ to empty expression"):
        ConditionBuilder().add(1)


def test_hex_string_builder_invalid_low_nibble_and_unknown_pattern_part() -> None:
    with pytest.raises(ValueError, match="Invalid nibble pattern: \\?G"):
        HexStringBuilder().nibble("?G")

    builder = HexStringBuilder()
    builder.pattern("XYZ")
    assert builder.build() == []


def test_html_tree_nodes_condition_section_none() -> None:
    gen = HtmlTreeGenerator()
    assert gen._condition_section(None) is None


def test_html_tree_nodes_write_meta_and_string_helpers(tmp_path) -> None:
    gen = HtmlTreeGenerator()
    out = tmp_path / "tree.html"
    gen._write_output(str(out), "<html>ok</html>")
    assert out.read_text(encoding="utf-8") == "<html>ok</html>"

    meta = gen._meta_section({"author": "unit", "score": 5})
    assert meta is not None
    assert meta["label"] == "Meta"
    assert len(meta["children"]) == 2

    string_node = gen._string_node(
        "Plain String: $a",
        value='"abc"',
        details="3 bytes",
        children=[{"id": "node_x", "label": "child", "node_class": "child"}],
    )
    assert string_node["details"] == "3 bytes"
    assert string_node["children"][0]["label"] == "child"
