"""Tests for HTML tree generator (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.metrics.html_tree import HtmlTreeGenerator
from yaraast.parser import Parser


def test_html_tree_generation(tmp_path) -> None:
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
