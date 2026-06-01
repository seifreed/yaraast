"""Shared helpers for AST serializers."""

from __future__ import annotations

from os import PathLike
from pathlib import Path
from typing import Any

from yaraast.serialization.file_io_helpers import read_utf8, write_utf8


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
    if isinstance(value, str) and not value:
        msg = f"{name} must not be empty"
        raise ValueError(msg)
    return Path(value)


def read_text(path: str | Path) -> str:
    """Read text from a file path."""
    return read_utf8(path)


def write_text(path: str | Path, text: str) -> None:
    """Write text to a file path."""
    write_utf8(path, text)
