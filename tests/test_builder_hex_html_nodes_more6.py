"""Extra real coverage for condition builder, hex builder, and HTML tree nodes."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.builder.condition_builder import ConditionBuilder
from yaraast.builder.hex_string_builder import HexStringBuilder
from yaraast.errors import ValidationError
from yaraast.metrics.html_tree import HtmlTreeGenerator


def test_condition_builder_n_of_them_and_empty_arithmetic_error() -> None:
    expr = ConditionBuilder().n_of(2, "them").build()
    assert isinstance(expr, OfExpression)
    assert isinstance(expr.string_set, Identifier)
    assert expr.string_set.name == "them"

    with pytest.raises(ValidationError, match="Cannot apply \\+ to empty expression"):
        ConditionBuilder().add(1)


def test_hex_string_builder_invalid_low_nibble_and_unknown_pattern_part() -> None:
    with pytest.raises(TypeError, match="Nibble pattern must be a string"):
        HexStringBuilder().nibble(cast(Any, True))

    with pytest.raises(TypeError, match="Hex pattern must be a string"):
        HexStringBuilder().pattern(cast(Any, True))

    with pytest.raises(TypeError, match="Hex string must be a string"):
        HexStringBuilder.from_hex_string(cast(Any, True))

    with pytest.raises(TypeError, match="Raw byte data must be bytes"):
        HexStringBuilder.from_bytes(cast(Any, "AB"))

    with pytest.raises(ValidationError, match="Invalid nibble pattern: \\?G"):
        HexStringBuilder().nibble("?G")

    with pytest.raises(ValidationError, match="Invalid hex value: GG"):
        HexStringBuilder().pattern("GG")

    with pytest.raises(ValidationError, match="Invalid pattern part: XYZ"):
        HexStringBuilder().pattern("XYZ")

    with pytest.raises(ValidationError, match="Invalid pattern part: XYZ"):
        HexStringBuilder().pattern("AA XYZ BB")


def test_html_tree_nodes_condition_section_none() -> None:
    gen = HtmlTreeGenerator()
    assert gen._condition_section(None) is None


def test_html_tree_nodes_condition_section_preserves_falsy_present_condition() -> None:
    class FalsyBooleanLiteral(BooleanLiteral):
        def __bool__(self) -> bool:
            return False

    gen = HtmlTreeGenerator()

    section = gen._condition_section(FalsyBooleanLiteral(value=False))

    assert section is not None
    assert section["label"] == "Condition"
    assert section["children"][0]["label"] == "Boolean Literal"


def test_html_tree_nodes_write_meta_and_string_helpers(tmp_path: Path) -> None:
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
