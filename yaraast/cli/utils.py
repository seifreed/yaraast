"""Shared CLI helpers."""

from __future__ import annotations

from collections.abc import Callable
import json
from os import PathLike, fspath
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.markup import escape

from yaraast.ast.base import YaraFile


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
        if _path_exists_and_is_dir(output_path):
            raise ValueError("output path must not be a directory")
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="--output") from exc
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
        if _path_exists_and_is_dir(output_path):
            raise ValueError("output path must not be a directory")
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="--output") from exc
    return output_path


def _validate_output_dir_path(output_dir: str | None) -> str | None:
    """Validate an optional ``--output-dir`` path, returning it unchanged.

    Rejects a path that exists but is not a directory with a Click error.
    """
    if output_dir is None:
        return None
    try:
        output_path = _require_file_path(output_dir)
        if _path_exists_and_not_dir(output_path):
            raise ValueError("output path must be a directory")
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="--output-dir") from exc
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


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError as exc:
        msg = f"path could not be accessed: {path}"
        raise ValueError(msg) from exc


def _path_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError as exc:
        msg = f"path could not be accessed: {path}"
        raise ValueError(msg) from exc


def _path_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError as exc:
        msg = f"path could not be accessed: {path}"
        raise ValueError(msg) from exc


def _path_exists_and_is_dir(path: Path) -> bool:
    return _path_exists(path) and _path_is_dir(path)


def _path_exists_and_is_file(path: Path) -> bool:
    return _path_exists(path) and _path_is_file(path)


def _path_exists_and_not_dir(path: Path) -> bool:
    return _path_exists(path) and not _path_is_dir(path)


def _require_existing_file_path(path: str | Path) -> Path:
    path_obj = _require_file_path(path)
    if _path_exists_and_is_dir(path_obj):
        msg = "path must not be a directory"
        raise ValueError(msg)
    return path_obj


def read_text(path: str | Path) -> str:
    """Read a text file with UTF-8 encoding."""
    try:
        return _require_existing_file_path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        msg = "file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


def write_text(path: str | Path, content: str) -> None:
    """Write a text file with UTF-8 encoding."""
    if not isinstance(content, str):
        msg = "content must be a string"
        raise TypeError(msg)
    try:
        content.encode("utf-8")
    except UnicodeEncodeError as exc:
        msg = "content must be UTF-8 encodable"
        raise ValueError(msg) from exc
    _require_existing_file_path(path).write_text(content, encoding="utf-8")


def write_json(path: str | Path, data: object, indent: int = 2) -> None:
    """Write JSON to disk with UTF-8 encoding."""
    write_text(path, json.dumps(data, indent=indent))


def format_json(
    data: object,
    indent: int | None = 2,
    *,
    sort_keys: bool | None = None,
    default: Callable[[Any], Any] | None = None,
    ensure_ascii: bool | None = None,
) -> str:
    """Format data as JSON with shared defaults."""
    return json.dumps(
        data,
        indent=indent,
        sort_keys=False if sort_keys is None else sort_keys,
        default=default,
        ensure_ascii=True if ensure_ascii is None else ensure_ascii,
    )


def parse_yara_file(path: str | Path) -> YaraFile:
    """Read + parse a YARA file into an AST."""
    from yaraast.parser.source import parse_yara_source

    return parse_yara_source(read_text(path))


def print_cli_error(console: Console, exc: Exception, prefix: str = "Error") -> None:
    """Render a CLI error message safely for Rich."""
    console.print(f"[red]{prefix}: {escape(str(exc))}[/red]")
