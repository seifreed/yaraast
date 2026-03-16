"""Real tests for CLI simple differ (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.cli.simple_differ import (
    SimpleASTDiffer,
    SimpleDiffer,
    diff_ast,
    diff_lines,
    diff_tokens,
    format_diff,
    get_diff_summary,
)
from yaraast.parser import Parser


def test_simple_differ_line_changes() -> None:
    d = SimpleDiffer()
    content1 = "a\nb\nc"
    content2 = "a\nx\nc\nd"

    result = d.diff(content1, content2)
    assert result.has_changes is True
    summary = get_diff_summary(result)
    assert summary["added"] == 1
    assert summary["modified"] == 1

    formatted = format_diff(result)
    assert "+ d" in formatted
    assert "~ x" in formatted


def test_simple_ast_differ_files_and_ast(tmp_path) -> None:
    rule1 = dedent(
        """
        rule r1 { condition: true }
        """,
    )
    rule2 = dedent(
        """
        rule r1 { condition: false }
        rule r2 { condition: true }
        """,
    )

    p1 = tmp_path / "a.yar"
    p2 = tmp_path / "b.yar"
    p1.write_text(rule1)
    p2.write_text(rule2)

    differ = SimpleASTDiffer()
    result = differ.diff_files(p1, p2)

    assert result.has_changes is True
    assert "r2" in result.added_rules
    assert "r1" in result.modified_rules

    ast1 = Parser().parse(rule1)
    ast2 = Parser().parse(rule2)
    diff_result = diff_ast(ast1, ast2)
    assert diff_result.has_changes is True

    changes = differ.get_changes(rule1, rule2)
    assert any(line.startswith("+") or line.startswith("~") for line in changes)


def test_diff_lines_and_tokens() -> None:
    lines = diff_lines(["a", "b"], ["a", "c"])
    assert any(line.content.startswith("~") for line in lines)

    tokens = diff_tokens("a b c", "a b d")
    assert "- c" in tokens
    assert "+ d" in tokens
