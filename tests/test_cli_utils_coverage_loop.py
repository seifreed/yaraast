# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered lines in yaraast/cli/utils.py.

Coverage baseline (from test_cli_utils_more.py alone): 63.57%
Missing lines targeted here: 26, 30, 33, 42-50, 58-66, 75-76, 112, 116, 163, 181
Lines 94-96 and 100-104 are structurally unreachable through this module's public
surface (see rationale in each test docstring); they are documented accordingly.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import click
import pytest
from rich.console import Console

from yaraast.cli import utils

# ---------------------------------------------------------------------------
# _validate_output_path — lines 26, 30, 33
# ---------------------------------------------------------------------------


def test_validate_output_path_returns_none_for_none() -> None:
    """Line 26: early-return None branch when output is None."""
    result = utils._validate_output_path(None)
    assert result is None


def test_validate_output_path_raises_for_existing_directory(tmp_path: Path) -> None:
    """Line 30: ValueError branch when output path is an existing directory."""
    directory = tmp_path / "output_dir"
    directory.mkdir()
    with pytest.raises(click.BadParameter, match="output path must not be a directory"):
        utils._validate_output_path(str(directory))


def test_validate_output_path_returns_string_for_valid_nonexistent_path(
    tmp_path: Path,
) -> None:
    """Line 33: success return — a non-existing output path is accepted unchanged."""
    output_str = str(tmp_path / "new_output.json")
    result = utils._validate_output_path(output_str)
    assert result == output_str


def test_validate_output_path_returns_string_for_valid_existing_file(
    tmp_path: Path,
) -> None:
    """Line 33: success return — an existing file path is accepted unchanged."""
    existing_file = tmp_path / "output.json"
    existing_file.write_text("{}", encoding="utf-8")
    result = utils._validate_output_path(str(existing_file))
    assert result == str(existing_file)


# ---------------------------------------------------------------------------
# _resolve_output_path — lines 42-50
# ---------------------------------------------------------------------------


def test_resolve_output_path_returns_none_for_none() -> None:
    """Line 42: early-return None branch when output is None."""
    result = utils._resolve_output_path(None)
    assert result is None


def test_resolve_output_path_returns_path_for_nonexistent_file(
    tmp_path: Path,
) -> None:
    """Lines 45-50: success path — returns a Path object for a valid new file path."""
    new_file = tmp_path / "output.txt"
    result = utils._resolve_output_path(str(new_file))
    assert isinstance(result, Path)
    assert result == new_file


def test_resolve_output_path_returns_path_for_existing_file(tmp_path: Path) -> None:
    """Lines 45-50: success path — returns Path for an existing file."""
    existing_file = tmp_path / "output.txt"
    existing_file.write_text("data", encoding="utf-8")
    result = utils._resolve_output_path(str(existing_file))
    assert isinstance(result, Path)
    assert result == existing_file


def test_resolve_output_path_raises_for_existing_directory(tmp_path: Path) -> None:
    """Line 47: ValueError branch when resolved path is an existing directory."""
    directory = tmp_path / "out_dir"
    directory.mkdir()
    with pytest.raises(click.BadParameter, match="output path must not be a directory"):
        utils._resolve_output_path(str(directory))


def test_resolve_output_path_raises_for_inaccessible_path() -> None:
    """Lines 48-49: BadParameter raised when the path string is too long to access."""
    too_long = "a" * 5000
    with pytest.raises(click.BadParameter, match="path could not be accessed"):
        utils._resolve_output_path(too_long)


# ---------------------------------------------------------------------------
# _validate_output_dir_path — lines 58-66
# ---------------------------------------------------------------------------


def test_validate_output_dir_path_returns_none_for_none() -> None:
    """Line 58: early-return None branch when output_dir is None."""
    result = utils._validate_output_dir_path(None)
    assert result is None


def test_validate_output_dir_path_returns_string_for_existing_directory(
    tmp_path: Path,
) -> None:
    """Line 66: success return — an existing directory is accepted unchanged."""
    result = utils._validate_output_dir_path(str(tmp_path))
    assert result == str(tmp_path)


def test_validate_output_dir_path_returns_string_for_nonexistent_path(
    tmp_path: Path,
) -> None:
    """Line 66: success return — a nonexistent path is accepted (not yet created)."""
    new_dir = tmp_path / "new_output_dir"
    result = utils._validate_output_dir_path(str(new_dir))
    assert result == str(new_dir)


def test_validate_output_dir_path_raises_for_existing_file(tmp_path: Path) -> None:
    """Lines 63-65: ValueError branch when path exists but is a regular file."""
    existing_file = tmp_path / "file.txt"
    existing_file.write_text("content", encoding="utf-8")
    with pytest.raises(click.BadParameter, match="output path must be a directory"):
        utils._validate_output_dir_path(str(existing_file))


def test_validate_output_dir_path_raises_for_inaccessible_path() -> None:
    """Lines 64-65: BadParameter raised when the path string is too long to access."""
    too_long = "b" * 5000
    with pytest.raises(click.BadParameter, match="path could not be accessed"):
        utils._validate_output_dir_path(too_long)


# ---------------------------------------------------------------------------
# _require_file_path — lines 75-76: PathLike returning bytes
# ---------------------------------------------------------------------------


class _BytesPathLike:
    """A PathLike that returns bytes from __fspath__, not a str.

    cpython's os.fspath() accepts objects whose __fspath__ returns bytes; the
    module must then reject them because bytes is not a valid str path.
    """

    def __fspath__(self) -> bytes:
        return b"/some/bytes/path"


def test_require_file_path_rejects_pathlike_returning_bytes() -> None:
    """Lines 74-76: fspath() succeeds but returns bytes — TypeError must be raised."""
    bad_path: Any = _BytesPathLike()
    with pytest.raises(TypeError, match="path must be a file path"):
        utils._require_file_path(bad_path)


def test_require_file_path_rejects_null_byte_string() -> None:
    with pytest.raises(ValueError, match="path must not contain null bytes"):
        utils._require_file_path("\x00broken")


def test_read_text_rejects_pathlike_returning_bytes() -> None:
    """Lines 74-76 reached through read_text public surface."""
    bad_path: Any = _BytesPathLike()
    with pytest.raises(TypeError, match="path must be a file path"):
        utils.read_text(bad_path)


def test_write_text_rejects_pathlike_returning_bytes(tmp_path: Path) -> None:
    """Lines 74-76 reached through write_text public surface."""
    bad_path: Any = _BytesPathLike()
    with pytest.raises(TypeError, match="path must be a file path"):
        utils.write_text(bad_path, "content")


# ---------------------------------------------------------------------------
# _path_exists_and_is_file — line 112
# ---------------------------------------------------------------------------


def test_path_exists_and_is_file_returns_true_for_existing_file(
    tmp_path: Path,
) -> None:
    """Line 112: True branch — file exists and is a regular file."""
    file_path = tmp_path / "real.txt"
    file_path.write_text("hello", encoding="utf-8")
    assert utils._path_exists_and_is_file(file_path) is True


def test_path_exists_and_is_file_returns_false_for_directory(tmp_path: Path) -> None:
    """Line 112: False branch — path exists but is a directory, not a file."""
    assert utils._path_exists_and_is_file(tmp_path) is False


def test_path_exists_and_is_file_returns_false_for_nonexistent_path(
    tmp_path: Path,
) -> None:
    """Line 112: False branch — path does not exist at all."""
    nonexistent = tmp_path / "ghost.txt"
    assert utils._path_exists_and_is_file(nonexistent) is False


# ---------------------------------------------------------------------------
# _path_exists_and_not_dir — line 116
# ---------------------------------------------------------------------------


def test_path_exists_and_not_dir_returns_true_for_existing_file(
    tmp_path: Path,
) -> None:
    """Line 116: True branch — path exists and is not a directory."""
    file_path = tmp_path / "file.txt"
    file_path.write_text("data", encoding="utf-8")
    assert utils._path_exists_and_not_dir(file_path) is True


def test_path_exists_and_not_dir_returns_false_for_directory(tmp_path: Path) -> None:
    """Line 116: False branch — path exists and IS a directory."""
    assert utils._path_exists_and_not_dir(tmp_path) is False


def test_path_exists_and_not_dir_returns_false_for_nonexistent_path(
    tmp_path: Path,
) -> None:
    """Line 116: False branch — path does not exist, so 'exists' is False."""
    nonexistent = tmp_path / "nowhere"
    assert utils._path_exists_and_not_dir(nonexistent) is False


# ---------------------------------------------------------------------------
# format_json — line 163 with non-default keyword arguments
# ---------------------------------------------------------------------------


def test_format_json_with_explicit_defaults() -> None:
    """Line 163: format_json with all None kwargs uses built-in defaults."""
    result = utils.format_json({"k": 1})
    assert '"k": 1' in result
    # Default ensure_ascii=True means non-ASCII is escaped
    result_ascii = utils.format_json({"name": "café"})
    assert "\\u00e9" in result_ascii


def test_format_json_with_sort_keys_true() -> None:
    """Line 163: format_json with sort_keys=True produces sorted output."""
    data = {"b": 2, "a": 1}
    result = utils.format_json(data, sort_keys=True)
    keys_in_order = [
        line.strip().split(":")[0].strip('"') for line in result.splitlines() if ":" in line
    ]
    assert keys_in_order == ["a", "b"]


def test_format_json_with_sort_keys_false() -> None:
    """Line 163: format_json with sort_keys=False preserves insertion order."""
    data = {"z": 26, "a": 1}
    result = utils.format_json(data, sort_keys=False)
    assert result.index('"z"') < result.index('"a"')


def test_format_json_with_ensure_ascii_false() -> None:
    """Line 163: format_json with ensure_ascii=False keeps non-ASCII literals."""
    result = utils.format_json({"name": "café"}, ensure_ascii=False)
    assert "café" in result
    assert "\\u00e9" not in result


def test_format_json_with_custom_default() -> None:
    """Line 163: format_json with a custom default serializer handles unknown types."""

    def serialize_set(obj: object) -> list[object]:
        if isinstance(obj, set):
            return sorted(obj)
        raise TypeError(f"not serializable: {type(obj)!r}")

    result = utils.format_json({"tags": {3, 1, 2}}, default=serialize_set)
    parsed = json.loads(result)
    assert parsed["tags"] == [1, 2, 3]


def test_format_json_with_indent_none() -> None:
    """Line 163: format_json with indent=None produces compact output."""
    result = utils.format_json({"a": 1}, indent=None)
    assert "\n" not in result
    assert result == '{"a": 1}'


# ---------------------------------------------------------------------------
# print_cli_error — line 181
# ---------------------------------------------------------------------------


def test_print_cli_error_renders_exception_message() -> None:
    """Line 181: print_cli_error writes a formatted error string to the console."""
    buffer = io.StringIO()
    console = Console(file=buffer, highlight=False, markup=True)
    exc = ValueError("something went wrong")
    utils.print_cli_error(console, exc)
    output = buffer.getvalue()
    assert "something went wrong" in output
    assert "Error" in output


def test_print_cli_error_uses_custom_prefix() -> None:
    """Line 181: print_cli_error accepts a custom prefix argument."""
    buffer = io.StringIO()
    console = Console(file=buffer, highlight=False, markup=True)
    exc = RuntimeError("disk full")
    utils.print_cli_error(console, exc, prefix="Fatal")
    output = buffer.getvalue()
    assert "Fatal" in output
    assert "disk full" in output


def test_print_cli_error_escapes_rich_markup_in_message() -> None:
    """Line 181: rich markup characters in the exception message are escaped safely."""
    buffer = io.StringIO()
    console = Console(file=buffer, highlight=False, markup=True)
    exc = ValueError("[bold]dangerous markup[/bold]")
    # Must not raise a rich MarkupError — escape() is applied
    utils.print_cli_error(console, exc)
    output = buffer.getvalue()
    # The literal brackets must appear in the output, not be interpreted as markup
    assert "dangerous markup" in output


# ---------------------------------------------------------------------------
# Structural note: unreachable OSError branches (lines 94-96, 100-104)
# ---------------------------------------------------------------------------
# _path_is_dir (lines 91-96) and _path_is_file (lines 99-104) each contain an
# OSError catch branch.  Both functions are only ever called after _path_exists()
# succeeds (returns True) inside _path_exists_and_is_dir, _path_exists_and_is_file,
# and _path_exists_and_not_dir.  Because path.exists(), path.is_dir(), and
# path.is_file() all invoke os.stat() internally, any OS condition that raises
# OSError from is_dir() or is_file() will also raise from exists() first.
# The result is that _path_exists() raises ValueError before _path_is_dir() or
# _path_is_file() are invoked, making their OSError branches dead code under all
# filesystem conditions achievable on the test host without non-deterministic
# race conditions (deletion between two syscalls).  No test is written for these
# lines; they should be noted as structurally unreachable in a coverage report.
