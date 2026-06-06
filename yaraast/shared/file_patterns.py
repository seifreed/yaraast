"""Shared file discovery helpers for YARA source files."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from os import PathLike, fspath
from pathlib import Path

DEFAULT_CLASSIC_YARA_FILE_PATTERNS = ("*.yar", "*.yara")
FilePatterns = str | Iterable[str] | None
FILE_PATTERNS_TYPE_ERROR = "File patterns must be a string or iterable of strings"
FILE_PATTERNS_EMPTY_ERROR = "File patterns must not contain empty patterns"
DIRECTORY_TYPE_ERROR = "directory must be a directory path"


def normalize_file_patterns(
    patterns: FilePatterns,
    default: tuple[str, ...] = DEFAULT_CLASSIC_YARA_FILE_PATTERNS,
) -> tuple[str, ...]:
    """Normalize an optional glob pattern or pattern collection."""
    if patterns is None:
        return default
    if isinstance(patterns, str):
        if not patterns.strip():
            raise ValueError(FILE_PATTERNS_EMPTY_ERROR)
        return (patterns,)
    if not isinstance(patterns, Iterable):
        raise TypeError(FILE_PATTERNS_TYPE_ERROR)
    normalized = tuple(patterns)
    if not all(isinstance(pattern, str) for pattern in normalized):
        raise TypeError(FILE_PATTERNS_TYPE_ERROR)
    if any(not pattern.strip() for pattern in normalized):
        raise ValueError(FILE_PATTERNS_EMPTY_ERROR)
    return normalized


def iter_matching_files(
    directory: str | PathLike[str],
    patterns: FilePatterns = None,
    recursive: object = False,
) -> Iterator[Path]:
    """Yield matching files once, preserving pattern and filesystem order."""
    if isinstance(directory, bool | bytes) or not isinstance(directory, str | PathLike):
        raise TypeError(DIRECTORY_TYPE_ERROR)
    raw_path = fspath(directory)
    if not isinstance(raw_path, str):
        raise TypeError(DIRECTORY_TYPE_ERROR)
    if not raw_path.strip():
        msg = "directory must not be empty"
        raise ValueError(msg)
    directory_path = Path(raw_path)
    if not directory_path.exists():
        msg = f"directory does not exist: {directory_path}"
        raise FileNotFoundError(msg)
    if not directory_path.is_dir():
        msg = "directory must not be a file"
        raise ValueError(msg)
    if not isinstance(recursive, bool):
        msg = "recursive must be a boolean"
        raise TypeError(msg)

    seen: set[Path] = set()
    for pattern in normalize_file_patterns(patterns):
        matches = directory_path.rglob(pattern) if recursive else directory_path.glob(pattern)
        for path in matches:
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            yield path
