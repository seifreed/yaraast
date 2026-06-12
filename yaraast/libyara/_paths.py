"""Path-argument validation shared across the libyara adapters."""

from __future__ import annotations

from os import PathLike, fspath, stat_result
from pathlib import Path


def _path_access_error(path: Path) -> ValueError:
    msg = f"path could not be accessed: {path}"
    return ValueError(msg)


def require_file_path(filepath: object, name: str) -> Path:
    """Coerce ``filepath`` to a ``Path``, rejecting non-path and empty values."""
    if isinstance(filepath, bool | bytes) or not isinstance(filepath, str | PathLike):
        msg = f"{name} must be a string or path-like object"
        raise TypeError(msg)
    raw_path = fspath(filepath)
    if not isinstance(raw_path, str):
        msg = f"{name} must be a string or path-like object"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = f"{name} must not be empty"
        raise ValueError(msg)
    return Path(raw_path)


def path_exists(path: Path) -> bool:
    """Return whether a path exists, converting access failures to ValueError."""
    try:
        return path.exists()
    except OSError as exc:
        raise _path_access_error(path) from exc


def path_stat(path: Path) -> stat_result:
    """Return path stat data, converting access failures to ValueError."""
    try:
        return path.stat()
    except OSError as exc:
        raise _path_access_error(path) from exc
