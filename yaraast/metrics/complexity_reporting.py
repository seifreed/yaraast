"""Reporting helpers for complexity analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from yaraast.metrics.complexity_report_builder import generate_complexity_report
from yaraast.parser.parser import Parser

__all__ = ["analyze_file_complexity", "generate_complexity_report"]


def analyze_file_complexity(file_path: str | Path) -> dict[str, Any]:
    """Analyze complexity of a YARA file."""
    parser = Parser()

    with open(file_path, encoding="utf-8") as f:
        content = f.read()

    ast = parser.parse(content)
    report = generate_complexity_report(ast)

    return {
        "file": str(file_path),
        "complexity": report,
    }
