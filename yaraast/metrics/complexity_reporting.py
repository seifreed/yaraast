"""Reporting helpers for complexity analysis."""

from __future__ import annotations

from os import PathLike, fspath
from pathlib import Path
from typing import Any

from yaraast.metrics.complexity_report_builder import generate_complexity_report
from yaraast.parser.source import parse_yara_source

__all__ = ["analyze_file_complexity", "generate_complexity_report"]


def _require_file_path(file_path: object) -> Path:
    if isinstance(file_path, bool) or not isinstance(file_path, str | PathLike):
        msg = "file_path must be a file path"
        raise TypeError(msg)
    raw_path = fspath(file_path)
    if not isinstance(raw_path, str):
        msg = "file_path must be a file path"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = "file_path must not be empty"
        raise ValueError(msg)
    path = Path(raw_path)
    if path.exists() and path.is_dir():
        msg = "file_path must not be a directory"
        raise ValueError(msg)
    return path


def _read_yara_text_file(file_path: object) -> str:
    path = _require_file_path(file_path)
    try:
        with path.open(encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


def analyze_file_complexity(file_path: str | Path) -> dict[str, Any]:
    """Analyze complexity of a YARA file."""
    path = _require_file_path(file_path)
    content = _read_yara_text_file(path)

    ast = parse_yara_source(content)
    report = generate_complexity_report(ast)

    return {
        "file": str(path),
        "complexity": report,
    }
