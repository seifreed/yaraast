"""Small filesystem helpers shared by serializers."""

from __future__ import annotations

from os import PathLike, fspath
from pathlib import Path

from yaraast.shared.path_safety import path_has_symlink_ancestor, path_is_symlink


def _path_access_error(path: Path) -> ValueError:
    msg = f"path could not be accessed: {path}"
    return ValueError(msg)


def _path_exists(path: Path) -> bool:
    try:
        path.stat()
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError as exc:
        raise _path_access_error(path) from exc


def _path_exists_and_is_dir(path: Path) -> bool:
    return _path_exists(path) and _path_is_dir(path)


def _require_file_path(path: object) -> Path:
    if isinstance(path, bool) or not isinstance(path, str | PathLike):
        msg = "path must be a file path"
        raise TypeError(msg)
    raw_path = fspath(path)
    if not isinstance(raw_path, str):
        msg = "path must be a file path"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = "path must not be empty"
        raise ValueError(msg)
    if "\x00" in raw_path:
        msg = "path must not contain null bytes"
        raise ValueError(msg)
    path_obj = Path(raw_path)
    if _path_exists_and_is_dir(path_obj):
        msg = "path must not be a directory"
        raise ValueError(msg)
    if path_is_symlink(path_obj) or path_has_symlink_ancestor(path_obj):
        msg = "path must not traverse a symlink"
        raise ValueError(msg)
    return path_obj


def read_utf8(path: str | Path) -> str:
    """Read UTF-8 text from disk."""
    try:
        with _require_file_path(path).open(encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        msg = f"path could not be accessed: {path}"
        raise ValueError(msg) from exc
    except UnicodeDecodeError as exc:
        msg = "file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


def write_utf8(path: str | Path, text: str) -> None:
    """Write UTF-8 text to disk."""
    if not isinstance(text, str):
        msg = "text must be a string"
        raise TypeError(msg)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        msg = "text must be UTF-8 encodable"
        raise ValueError(msg) from exc
    try:
        path_obj = _require_file_path(path)
        if path_is_symlink(path_obj) or path_has_symlink_ancestor(path_obj):
            raise ValueError("path must not traverse a symlink")
        with path_obj.open("w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as exc:
        msg = f"path could not be accessed: {path}"
        raise ValueError(msg) from exc
