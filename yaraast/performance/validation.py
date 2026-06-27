"""Validation helpers for performance tuning settings."""

from __future__ import annotations

from collections.abc import Sequence
from os import PathLike, fspath
from pathlib import Path

from yaraast.shared.numeric_validation import (
    validate_non_negative_int_setting,
    validate_positive_int_setting,
    validate_positive_number_setting,
)

FILE_PATHS_TYPE_ERROR = "file_paths must be a sequence of paths"
FILE_PATH_ENTRY_TYPE_ERROR = "file_paths must contain path strings or path-like objects"


def _path_access_error(path: Path) -> ValueError:
    msg = f"path could not be accessed: {path}"
    return ValueError(msg)


def path_exists(path: Path) -> bool:
    """Return whether a path exists, converting access failures to ValueError."""
    try:
        return path.exists()
    except OSError as exc:
        raise _path_access_error(path) from exc


def path_is_dir(path: Path) -> bool:
    """Return whether a path is a directory, converting access failures to ValueError."""
    try:
        return path.is_dir()
    except OSError as exc:
        raise _path_access_error(path) from exc


def path_exists_and_is_dir(path: Path) -> bool:
    """Return whether a path exists and is a directory."""
    return path_exists(path) and path_is_dir(path)


def path_exists_and_not_dir(path: Path) -> bool:
    """Return whether a path exists and is not a directory."""
    return path_exists(path) and not path_is_dir(path)


def validate_file_path_sequence(file_paths: object) -> list[str]:
    """Return file paths as strings after rejecting common iterable path mistakes."""
    if isinstance(file_paths, (str, bytes)) or not isinstance(file_paths, Sequence):
        raise TypeError(FILE_PATHS_TYPE_ERROR)

    normalized_paths: list[str] = []
    for file_path in file_paths:
        if isinstance(file_path, bytes) or not isinstance(file_path, (str, PathLike)):
            raise TypeError(FILE_PATH_ENTRY_TYPE_ERROR)
        normalized_path = fspath(file_path)
        if not isinstance(normalized_path, str):
            raise TypeError(FILE_PATH_ENTRY_TYPE_ERROR)
        if not normalized_path.strip():
            msg = "file_paths must not contain empty paths"
            raise ValueError(msg)
        if "\x00" in normalized_path:
            msg = "file_paths must not contain null bytes"
            raise ValueError(msg)
        normalized_paths.append(normalized_path)
    return normalized_paths


__all__ = [
    "path_exists",
    "path_exists_and_is_dir",
    "path_exists_and_not_dir",
    "path_is_dir",
    "validate_file_path_sequence",
    "validate_non_negative_int_setting",
    "validate_positive_int_setting",
    "validate_positive_number_setting",
]
