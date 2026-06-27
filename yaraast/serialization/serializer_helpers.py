"""Shared helpers for AST serializers."""

from __future__ import annotations

from os import PathLike, fspath
from pathlib import Path
from typing import Any

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


def build_base_metadata(ast: Any, fmt: str) -> dict[str, Any]:
    """Build base metadata for serialized AST."""
    return {
        "format": fmt,
        "version": "1.0",
        "ast_type": "YaraFile",
        "rules_count": len(ast.rules),
        "imports_count": len(ast.imports),
        "includes_count": len(ast.includes),
    }


def require_bool_option(value: object, name: str) -> bool:
    """Validate a serializer boolean option."""
    if not isinstance(value, bool):
        msg = f"{name} must be a boolean"
        raise TypeError(msg)
    return value


def require_positive_int_option(value: object, name: str) -> int:
    """Validate a positive integer serializer option."""
    if not isinstance(value, int) or isinstance(value, bool):
        msg = f"{name} must be an integer"
        raise TypeError(msg)
    if value < 1:
        msg = f"{name} must be at least 1"
        raise ValueError(msg)
    return value


def require_input_path(value: object, name: str) -> Path:
    """Validate a serializer input path before touching the filesystem."""
    if isinstance(value, bool) or not isinstance(value, str | PathLike):
        msg = f"{name} must be a file path"
        raise TypeError(msg)
    raw_path = fspath(value)
    if not isinstance(raw_path, str):
        msg = f"{name} must be a file path"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = f"{name} must not be empty"
        raise ValueError(msg)
    if "\x00" in raw_path:
        msg = f"{name} must not contain null bytes"
        raise ValueError(msg)
    path = Path(raw_path)
    if _path_exists_and_is_dir(path):
        msg = f"{name} must not be a directory"
        raise ValueError(msg)
    if path_is_symlink(path) or path_has_symlink_ancestor(path):
        msg = f"{name} must not traverse a symlink"
        raise ValueError(msg)
    return path


def require_output_path(value: object, name: str) -> Path:
    """Validate a serializer output path before writing to disk."""
    path = require_input_path(value, name)
    if path_is_symlink(path) or path_has_symlink_ancestor(path):
        msg = f"{name} must not traverse a symlink"
        raise ValueError(msg)
    return path
