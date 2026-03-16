"""Reporting helpers for parse CLI command."""

from __future__ import annotations

from yaraast.cli.parse_output_services import _generate_output_by_format, _report_parsing_errors
from yaraast.cli.utils import print_cli_error


def report_parsing_errors(lexer_errors, parser_errors, ast) -> None:
    """Report parsing errors."""
    _report_parsing_errors(lexer_errors, parser_errors, ast)


def generate_output_by_format(ast, output_format: str, output: str | None) -> None:
    """Generate output for the requested format."""
    _generate_output_by_format(ast, output_format, output)


def display_cli_error(console, error: Exception) -> None:
    """Display CLI error using standard formatting."""
    print_cli_error(console, error)
