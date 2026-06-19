"""Additional tests for simple differ directory and edge paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.cli.simple_differ import SimpleASTDiffer, SimpleDiffer


def test_simple_differ_removed_line_path() -> None:
    differ = SimpleDiffer()

    result = differ.diff("a\nb\nc", "a\nb")

    assert result.has_changes is True
    assert result.summary["removed"] == 1
    assert any(line.content == "- c" for line in result.lines)


def test_simple_differ_empty_and_added_content_paths() -> None:
    empty_result = SimpleDiffer().diff("", "")
    added_result = SimpleDiffer().diff("", "rule added { condition: true }")

    assert empty_result.has_changes is False
    assert empty_result.summary == {"added": 0, "removed": 0, "modified": 0, "total_changes": 0}
    assert added_result.has_changes is True
    assert added_result.summary["added"] == 1
    assert any(line.content == "+ rule added { condition: true }" for line in added_result.lines)


def test_simple_ast_differ_diff_files_rejects_invalid_utf8(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yar"
    good = tmp_path / "good.yar"
    bad.write_bytes(b"\xff")
    good.write_text("rule good { condition: true }", encoding="utf-8")

    with pytest.raises(ValueError, match="YARA file must contain valid UTF-8 text"):
        SimpleASTDiffer().diff_files(bad, good)
