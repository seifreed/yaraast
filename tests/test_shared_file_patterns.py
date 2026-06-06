"""Tests for shared file pattern normalization."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.shared.file_patterns import iter_matching_files, normalize_file_patterns


@pytest.mark.parametrize("directory", ["", "   ", "\t"])
def test_iter_matching_files_rejects_empty_directory(directory: str) -> None:
    with pytest.raises(ValueError, match="directory must not be empty"):
        list(iter_matching_files(directory))


@pytest.mark.parametrize("directory", [None, False, 123, object(), b"."])
def test_iter_matching_files_rejects_invalid_directory_types(directory: Any) -> None:
    with pytest.raises(TypeError, match="directory must be a directory path"):
        list(iter_matching_files(cast(Any, directory)))


def test_iter_matching_files_rejects_file_directory(tmp_path: Path) -> None:
    path = tmp_path / "not_a_directory"
    path.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValueError, match="directory must not be a file"):
        list(iter_matching_files(path))


def test_iter_matching_files_rejects_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="directory does not exist"):
        list(iter_matching_files(tmp_path / "missing"))


def test_normalize_file_patterns_rejects_non_string_entries(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="File patterns must be a string or iterable of strings"):
        normalize_file_patterns(cast(Any, [object()]))

    with pytest.raises(TypeError, match="File patterns must be a string or iterable of strings"):
        list(iter_matching_files(tmp_path, cast(Any, b"*.yar")))


@pytest.mark.parametrize("patterns", ["", "   ", ["*.yar", ""], ["\t"]])
def test_normalize_file_patterns_rejects_empty_patterns(
    tmp_path: Path,
    patterns: Any,
) -> None:
    with pytest.raises(ValueError, match="File patterns must not contain empty patterns"):
        normalize_file_patterns(cast(Any, patterns))

    with pytest.raises(ValueError, match="File patterns must not contain empty patterns"):
        list(iter_matching_files(tmp_path, cast(Any, patterns)))


@pytest.mark.parametrize("recursive", [None, 1, "yes", object()])
def test_iter_matching_files_rejects_invalid_recursive_types(
    tmp_path: Path,
    recursive: Any,
) -> None:
    with pytest.raises(TypeError, match="recursive must be a boolean"):
        list(iter_matching_files(tmp_path, recursive=recursive))
