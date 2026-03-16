"""Additional tests for simple differ utilities (no mocks)."""

from __future__ import annotations

from pathlib import Path

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
    differ = SimpleDiffer()
    result = differ.diff("rule a { condition: true }", "rule a { condition: false }")

    assert result.has_changes is True
    summary = get_diff_summary(result)
    assert summary["modified"] >= 1
    assert summary["total_changes"] == summary["added"] + summary["removed"] + summary["modified"]

    formatted = format_diff(result)
    assert "~" in formatted


def test_simple_ast_differ_files(tmp_path: Path) -> None:
    file1 = tmp_path / "a.yar"
    file2 = tmp_path / "b.yar"

    file1.write_text("rule r1 { condition: true }")
    file2.write_text("rule r2 { condition: true }")

    differ = SimpleASTDiffer()
    result = differ.diff_files(file1, file2)

    assert result.has_changes is True
    assert result.added_rules == ["r2"]
    assert result.removed_rules == ["r1"]


def test_simple_ast_differ_modified_rule(tmp_path: Path) -> None:
    file1 = tmp_path / "a.yar"
    file2 = tmp_path / "b.yar"

    file1.write_text("rule r1 { condition: true }")
    file2.write_text("rule r1 { condition: false }")

    differ = SimpleASTDiffer()
    result = differ.diff_files(file1, file2)

    assert result.modified_rules == ["r1"]


def test_diff_ast_and_helpers() -> None:
    parser = Parser()
    ast1 = parser.parse("rule r1 { condition: true }")
    ast2 = parser.parse("rule r1 { condition: true }")
    ast3 = parser.parse("rule r1 { condition: false }")

    same = diff_ast(ast1, ast2)
    changed = diff_ast(ast1, ast3)

    assert same.has_changes is False
    assert changed.has_changes is True

    lines = diff_lines(["a", "b"], ["a", "c"])
    assert any(line.content.startswith("~") for line in lines)

    tokens = diff_tokens("a b c", "a c d")
    assert "- b" in tokens and "+ d" in tokens
