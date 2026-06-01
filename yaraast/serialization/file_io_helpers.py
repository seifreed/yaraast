"""Small filesystem helpers shared by serializers."""

from __future__ import annotations

from os import PathLike
from pathlib import Path


def _require_file_path(path: object) -> Path:
    if isinstance(path, bool) or not isinstance(path, str | PathLike):
        msg = "path must be a file path"
        raise TypeError(msg)
    if isinstance(path, str) and not path:
        msg = "path must not be empty"
        raise ValueError(msg)
    path_obj = Path(path)
    if path_obj.exists() and path_obj.is_dir():
        msg = "path must not be a directory"
        raise ValueError(msg)
    return path_obj


def read_utf8(path: str | Path) -> str:
    """Read UTF-8 text from disk."""
    with _require_file_path(path).open(encoding="utf-8") as handle:
        return handle.read()


def write_utf8(path: str | Path, text: str) -> None:
    """Write UTF-8 text to disk."""
    with _require_file_path(path).open("w", encoding="utf-8") as handle:
        handle.write(text)
