"""Additional tests for simple differ directory and edge paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from yaraast.cli.simple_differ import (
    DiffResult,
    SimpleASTDiffer,
    SimpleDiffer,
    _diff_result_for_added_file,
    _diff_result_for_removed_file,
    format_diff,
)


def test_simple_differ_removed_line_path() -> None:
    differ = SimpleDiffer()

    result = differ.diff("a\nb\nc", "a\nb")

    assert result.has_changes is True
    assert result.summary["removed"] == 1
    assert any(line.content == "- c" for line in result.lines)


def test_simple_ast_differ_helper_file_results(tmp_path: Path) -> None:
    removed = tmp_path / "removed.yar"
    added = tmp_path / "added.yar"
    removed.write_text("", encoding="utf-8")
    added.write_text("rule added { condition: true }", encoding="utf-8")

    removed_result = _diff_result_for_removed_file(removed)
    added_result = _diff_result_for_added_file(added)

    assert removed_result.summary["removed"] == 1
    assert removed_result.summary["total_changes"] == 1
    assert added_result.summary["added"] == 1
    assert added_result.summary["total_changes"] == 1
    assert format_diff(removed_result) == "- <empty file>"
    assert "+ rule added { condition: true }" in format_diff(added_result)


def test_simple_ast_differ_diff_files_rejects_invalid_utf8(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yar"
    good = tmp_path / "good.yar"
    bad.write_bytes(b"\xff")
    good.write_text("rule good { condition: true }", encoding="utf-8")

    with pytest.raises(ValueError, match="YARA file must contain valid UTF-8 text"):
        SimpleASTDiffer().diff_files(bad, good)


def test_format_diff_no_changes_and_print_diff() -> None:
    result = DiffResult(
        has_changes=False, lines=[], summary={"added": 0, "removed": 0, "modified": 0}
    )

    assert format_diff(result) == "No changes"
    assert not hasattr(SimpleASTDiffer, "diff_directories")
