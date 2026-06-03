"""Shared CLI helpers."""

from __future__ import annotations

import json
from os import PathLike, fspath
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from yaraast.cli.parser_helpers import parse_yara_source


def _validate_output_path(output: str | None) -> str | None:
    """Validate an optional ``--output`` path, returning it unchanged.

    Shared by the CLI commands that accept an optional output file and pass the
    original string through; rejects directories and unusable paths with a
    Click error.
    """
    if output is None:
        return None
    try:
        output_path = _require_file_path(output)
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="--output") from exc
    if output_path.exists() and output_path.is_dir():
        raise click.BadParameter("output path must not be a directory", param_hint="--output")
    return output


def _resolve_output_path(output: str | None) -> Path | None:
    """Validate an optional ``--output`` file path and return it as a ``Path``.

    Like :func:`_validate_output_path` but returns the resolved ``Path`` instead
    of the original string, for commands that operate on the path object.
    """
    if output is None:
        return None
    try:
        output_path = _require_file_path(output)
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="--output") from exc
    if output_path.exists() and output_path.is_dir():
        raise click.BadParameter("output path must not be a directory", param_hint="--output")
    return output_path


def _validate_output_dir_path(output_dir: str | None) -> str | None:
    """Validate an optional ``--output-dir`` path, returning it unchanged.

    Rejects a path that exists but is not a directory with a Click error.
    """
    if output_dir is None:
        return None
    try:
        output_path = _require_file_path(output_dir)
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="--output-dir") from exc
    if output_path.exists() and not output_path.is_dir():
        raise click.BadParameter("output path must be a directory", param_hint="--output-dir")
    return output_dir


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
    return Path(raw_path)


def _require_existing_file_path(path: str | Path) -> Path:
    path_obj = _require_file_path(path)
    if path_obj.exists() and path_obj.is_dir():
        msg = "path must not be a directory"
        raise ValueError(msg)
    return path_obj


def read_text(path: str | Path) -> str:
    """Read a text file with UTF-8 encoding."""
    return _require_existing_file_path(path).read_text(encoding="utf-8")


def write_text(path: str | Path, content: str) -> None:
    """Write a text file with UTF-8 encoding."""
    _require_existing_file_path(path).write_text(content, encoding="utf-8")


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
    return parse_yara_source(source)


def parse_yara_file(path: str | Path) -> object:
    """Read + parse a YARA file into an AST."""
    return parse_yara_text(read_text(path))


def print_cli_error(console: Console, exc: Exception, prefix: str = "Error") -> None:
    """Render a CLI error message safely for Rich."""
    console.print(f"[red]{prefix}: {escape(str(exc))}[/red]")
