"""Services for AST-based formatting command."""

from __future__ import annotations

from pathlib import Path

from yaraast.cli.utils import read_text
from yaraast.shared.ast_analysis import ASTFormatter


def get_formatter() -> ASTFormatter:
    """Create an AST formatter instance."""
    return ASTFormatter()


def check_format(formatter: ASTFormatter, input_path: Path):
    """Check whether a file needs formatting."""
    return formatter.check_format(input_path)


def format_file(formatter: ASTFormatter, input_path: Path, output_path: Path, style: str):
    """Format a file and return (success, result)."""
    return formatter.format_file(input_path, output_path, style)


def format_for_diff(formatter: ASTFormatter, input_path: Path, style: str):
    """Return original content and formatted output."""
    original = read_text(input_path)
    success, formatted = formatter.format_file(input_path, None, style)
    return original, success, formatted
