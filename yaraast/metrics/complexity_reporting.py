"""Reporting helpers for complexity analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from yaraast.metrics.complexity_report_builder import generate_complexity_report
from yaraast.parser.source import parse_yara_source

__all__ = ["analyze_file_complexity", "generate_complexity_report"]


def _read_yara_text_file(file_path: str | Path) -> str:
    try:
        with open(file_path, encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


def analyze_file_complexity(file_path: str | Path) -> dict[str, Any]:
    """Analyze complexity of a YARA file."""
    content = _read_yara_text_file(file_path)

    ast = parse_yara_source(content)
    report = generate_complexity_report(ast)

    return {
        "file": str(file_path),
        "complexity": report,
    }
