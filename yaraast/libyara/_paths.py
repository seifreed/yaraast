"""Path-argument validation shared across the libyara adapters."""

from __future__ import annotations

from os import PathLike, fspath
from pathlib import Path


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
