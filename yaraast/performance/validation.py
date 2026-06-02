"""Validation helpers for performance tuning settings."""

from __future__ import annotations

from collections.abc import Sequence
from os import PathLike, fspath

from yaraast.shared.numeric_validation import (
    validate_non_negative_int_setting,
    validate_positive_int_setting,
    validate_positive_number_setting,
)

FILE_PATHS_TYPE_ERROR = "file_paths must be a sequence of paths"
FILE_PATH_ENTRY_TYPE_ERROR = "file_paths must contain path strings or path-like objects"


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
        normalized_paths.append(normalized_path)
    return normalized_paths


__all__ = [
    "validate_file_path_sequence",
    "validate_non_negative_int_setting",
    "validate_positive_int_setting",
    "validate_positive_number_setting",
]
