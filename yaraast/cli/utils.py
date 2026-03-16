"""Shared CLI helpers."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from yaraast.cli.parser_helpers import create_parser


def read_text(path: str | Path) -> str:
    """Read a text file with UTF-8 encoding."""
    return Path(path).read_text(encoding="utf-8")


def write_text(path: str | Path, content: str) -> None:
    """Write a text file with UTF-8 encoding."""
    Path(path).write_text(content, encoding="utf-8")


def write_json(path: str | Path, data: object, indent: int = 2) -> None:
    """Write JSON to disk with UTF-8 encoding."""
    write_text(path, json.dumps(data, indent=indent))


def format_json(
    data: object,
    indent: int | None = 2,
    *,
    sort_keys: bool | None = None,
    default: object | None = None,
    ensure_ascii: bool | None = None,
) -> str:
    """Format data as JSON with shared defaults."""
    kwargs: dict[str, object] = {}
    if sort_keys is not None:
        kwargs["sort_keys"] = sort_keys
    if default is not None:
        kwargs["default"] = default
    if ensure_ascii is not None:
        kwargs["ensure_ascii"] = ensure_ascii
    return json.dumps(data, indent=indent, **kwargs)


def parse_yara_text(source: str) -> object:
    """Parse YARA source into an AST."""
    return create_parser().parse(source)


def parse_yara_file(path: str | Path) -> object:
    """Read + parse a YARA file into an AST."""
    return parse_yara_text(read_text(path))


def print_cli_error(console: Console, exc: Exception, prefix: str = "Error") -> None:
    """Render a CLI error message safely for Rich."""
    console.print(f"[red]{prefix}: {escape(str(exc))}[/red]")
