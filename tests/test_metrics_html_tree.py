"""Tests for HTML tree generator (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any, cast

import pytest

from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source


def test_html_tree_generation(tmp_path: Path) -> None:
    code = """
    import "pe"

    rule tree_rule {
        strings:
            $a = "abc"
        condition:
            $a and pe.number_of_sections > 0
    }
    """
    parser = Parser()
    ast = parser.parse(dedent(code))

    generator = HtmlTreeGenerator(include_metadata=True)
    html_path = tmp_path / "tree.html"
    html = generator.generate_html(ast, str(html_path), title="Tree Title")

    assert html_path.exists()
    assert "<title>Tree Title</title>" in html

    interactive_path = tmp_path / "tree_interactive.html"
    interactive = generator.generate_interactive_html(
        ast,
        str(interactive_path),
        title="Interactive Title",
    )

    assert interactive_path.exists()
    assert "<title>Interactive Title</title>" in interactive


def test_html_tree_generation_accepts_yarax_nodes() -> None:
    ast = parse_yara_source("""
        rule native_yarax {
            condition:
                with xs = [1]: match xs { _ => true }
        }
        """)

    html = HtmlTreeGenerator().generate_html(ast)

    assert "With Statement" in html
    assert "Pattern Match" in html


def test_html_tree_rejects_empty_output_path() -> None:
    ast = Parser().parse("rule tree { condition: true }")

    with pytest.raises(ValueError, match="output_path must not be empty"):
        HtmlTreeGenerator().generate_html(ast, "")


def test_html_tree_rejects_directory_output_path(tmp_path: Path) -> None:
    ast = Parser().parse("rule tree { condition: true }")

    with pytest.raises(ValueError, match="output_path must not be a directory"):
        HtmlTreeGenerator().generate_interactive_html(ast, str(tmp_path))


@pytest.mark.parametrize("output_path", [False, 0, object()])
def test_html_tree_rejects_invalid_output_path_types(output_path: Any) -> None:
    ast = Parser().parse("rule tree { condition: true }")

    with pytest.raises(TypeError, match="output_path must be a file path"):
        HtmlTreeGenerator().generate_html(ast, cast(Any, output_path))
