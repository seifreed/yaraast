"""Real tests for CLI simple differ (no mocks)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from typing import Any, cast

import pytest

from yaraast.cli.simple_differ import (
    SimpleASTDiffer,
    SimpleDiffer,
)


def test_simple_differ_line_changes() -> None:
    d = SimpleDiffer()
    content1 = "a\nb\nc"
    content2 = "a\nx\nc\nd"

    result = d.diff(content1, content2)
    assert result.has_changes is True
    summary = result.summary
    assert summary["added"] == 1
    assert summary["modified"] == 1


def test_simple_ast_differ_files_and_ast(tmp_path: Path) -> None:
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
    p1.write_text(rule1, encoding="utf-8")
    p2.write_text(rule2, encoding="utf-8")

    differ = SimpleASTDiffer()
    result = differ.diff_files(p1, p2)

    assert result.has_changes is True
    assert "r2" in result.added_rules
    assert "r1" in result.modified_rules


def test_simple_differ_does_not_expose_dead_change_wrapper() -> None:
    assert not hasattr(SimpleDiffer(), "get_changes")


def test_diff_lines_and_tokens() -> None:
    token_result = SimpleDiffer().diff("a b c", "a b d")
    assert token_result.has_changes is True
    assert token_result.summary["modified"] >= 1


@pytest.mark.parametrize(
    ("content1", "content2", "message"),
    [
        (cast(Any, True), "abc", "content1 must be a string"),
        ("abc", cast(Any, True), "content2 must be a string"),
    ],
)
def test_simple_differ_rejects_non_string_contents(
    content1: str,
    content2: str,
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        SimpleDiffer().diff(content1, content2)
