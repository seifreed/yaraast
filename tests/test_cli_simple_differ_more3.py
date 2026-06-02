"""Additional tests for simple differ directory and edge paths."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.cli.simple_differ import (
    DiffResult,
    SimpleASTDiffer,
    SimpleDiffer,
    format_diff,
    print_diff,
)


def test_simple_differ_removed_line_path() -> None:
    differ = SimpleDiffer()

    result = differ.diff("a\nb\nc", "a\nb")

    assert result.has_changes is True
    assert result.summary["removed"] == 1
    assert any(line.content == "- c" for line in result.lines)


def test_simple_ast_differ_diff_directories_handles_common_added_and_removed_files(
    tmp_path: Path,
) -> None:
    dir1 = tmp_path / "dir1"
    dir2 = tmp_path / "dir2"
    dir1.mkdir()
    dir2.mkdir()

    (dir1 / "common.yar").write_text("rule r1 { condition: true }", encoding="utf-8")
    (dir2 / "common.yar").write_text("rule r1 { condition: false }", encoding="utf-8")

    (dir1 / "removed.yar").write_text("rule removed_rule { condition: true }", encoding="utf-8")
    (dir2 / "added.yar").write_text("rule added_rule { condition: true }", encoding="utf-8")

    differ = SimpleASTDiffer()
    results = differ.diff_directories(dir1, dir2)

    assert set(results) == {"common.yar", "removed.yar", "added.yar"}
    assert results["common.yar"].has_changes is True
    removed = results["removed.yar"]
    added = results["added.yar"]
    assert isinstance(removed, DiffResult)
    assert isinstance(added, DiffResult)
    assert removed.summary["removed"] > 0
    assert added.summary["added"] > 0
    # The summary contract must expose total_changes on every construction path,
    # matching the regular diff() path, so consumers never hit a KeyError.
    assert removed.summary["total_changes"] == removed.summary["removed"]
    assert added.summary["total_changes"] == added.summary["added"]


def test_simple_ast_differ_diff_directories_orders_results(tmp_path: Path) -> None:
    dir1 = tmp_path / "dir1"
    dir2 = tmp_path / "dir2"
    dir1.mkdir()
    dir2.mkdir()
    common_files = [
        "common_z.yar",
        "common_a.yar",
        "common_m.yar",
        "common_b.yar",
        "common_y.yar",
        "common_c.yar",
        "common_x.yar",
        "common_d.yar",
    ]
    removed_files = ["removed_z.yar", "removed_a.yar", "removed_m.yar"]
    added_files = ["added_z.yar", "added_a.yar", "added_m.yar"]

    for file_name in common_files:
        rule_name = file_name.removesuffix(".yar")
        (dir1 / file_name).write_text(
            f"rule {rule_name} {{ condition: true }}",
            encoding="utf-8",
        )
        (dir2 / file_name).write_text(
            f"rule {rule_name} {{ condition: false }}",
            encoding="utf-8",
        )

    for file_name in removed_files:
        rule_name = file_name.removesuffix(".yar")
        (dir1 / file_name).write_text(
            f"rule {rule_name} {{ condition: true }}",
            encoding="utf-8",
        )

    for file_name in added_files:
        rule_name = file_name.removesuffix(".yar")
        (dir2 / file_name).write_text(
            f"rule {rule_name} {{ condition: true }}",
            encoding="utf-8",
        )

    results = SimpleASTDiffer().diff_directories(dir1, dir2)

    assert list(results) == sorted(common_files) + sorted(removed_files) + sorted(added_files)


def test_simple_ast_differ_diff_directories_includes_yara_files(tmp_path: Path) -> None:
    dir1 = tmp_path / "dir1"
    dir2 = tmp_path / "dir2"
    dir1.mkdir()
    dir2.mkdir()

    (dir1 / "common.yara").write_text("rule common { condition: true }", encoding="utf-8")
    (dir2 / "common.yara").write_text("rule common { condition: false }", encoding="utf-8")
    (dir2 / "added.yara").write_text("rule added { condition: true }", encoding="utf-8")

    differ = SimpleASTDiffer()
    results = differ.diff_directories(dir1, dir2)

    assert set(results) == {"common.yara", "added.yara"}
    assert results["common.yara"].has_changes is True
    added = results["added.yara"]
    assert isinstance(added, DiffResult)
    assert added.summary["added"] > 0


@pytest.mark.parametrize("directory", ["", "   ", "\t"])
def test_simple_ast_differ_diff_directories_rejects_empty_directory(
    tmp_path: Path,
    directory: str,
) -> None:
    with pytest.raises(ValueError, match="dir1 must not be empty"):
        SimpleASTDiffer().diff_directories(directory, tmp_path)

    with pytest.raises(ValueError, match="dir2 must not be empty"):
        SimpleASTDiffer().diff_directories(tmp_path, directory)


@pytest.mark.parametrize("directory", [None, False, 123, object(), b"."])
def test_simple_ast_differ_diff_directories_rejects_invalid_directory_types(
    tmp_path: Path,
    directory: Any,
) -> None:
    with pytest.raises(TypeError, match="dir1 must be a directory path"):
        SimpleASTDiffer().diff_directories(cast(Any, directory), tmp_path)


def test_simple_ast_differ_diff_directories_rejects_file_directory(tmp_path: Path) -> None:
    path = tmp_path / "not_a_directory"
    path.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValueError, match="dir1 must not be a file"):
        SimpleASTDiffer().diff_directories(path, tmp_path)


def test_format_diff_no_changes_and_print_diff() -> None:
    result = DiffResult(
        has_changes=False, lines=[], summary={"added": 0, "removed": 0, "modified": 0}
    )

    assert format_diff(result) == "No changes"
    print_diff(result)
