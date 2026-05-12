"""Shared file discovery helpers for YARA source files."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

DEFAULT_CLASSIC_YARA_FILE_PATTERNS = ("*.yar", "*.yara")
FilePatterns = str | Iterable[str] | None


def normalize_file_patterns(
    patterns: FilePatterns,
    default: tuple[str, ...] = DEFAULT_CLASSIC_YARA_FILE_PATTERNS,
) -> tuple[str, ...]:
    """Normalize an optional glob pattern or pattern collection."""
    if patterns is None:
        return default
    if isinstance(patterns, str):
        return (patterns,)
    return tuple(patterns)


def iter_matching_files(
    directory: Path,
    patterns: FilePatterns = None,
    recursive: bool = False,
) -> Iterator[Path]:
    """Yield matching files once, preserving pattern and filesystem order."""
    seen: set[Path] = set()
    for pattern in normalize_file_patterns(patterns):
        matches = directory.rglob(pattern) if recursive else directory.glob(pattern)
        for path in matches:
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            yield path
