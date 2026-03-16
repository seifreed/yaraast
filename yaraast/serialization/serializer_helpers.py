"""Shared helpers for AST serializers."""

from __future__ import annotations

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


def read_text(path: str | Path) -> str:
    """Read text from a file path."""
    return read_utf8(path)


def write_text(path: str | Path, text: str) -> None:
    """Write text to a file path."""
    write_utf8(path, text)
