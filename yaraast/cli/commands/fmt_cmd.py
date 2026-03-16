"""CLI command for AST-based formatting (like black for Python)."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from yaraast.cli.fmt_reporting import (
    display_format_check,
    display_format_diff,
    display_format_error,
    display_format_result,
)
from yaraast.cli.fmt_services import check_format, format_file, format_for_diff, get_formatter
from yaraast.cli.utils import print_cli_error

console = Console()


@click.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    type=click.Path(),
    help="Output file (default: overwrite input)",
)
@click.option(
    "--style",
    type=click.Choice(["default", "compact", "pretty", "verbose"]),
    default="default",
    help="Formatting style",
)
@click.option(
    "--check",
    is_flag=True,
    help="Check if file needs formatting (don't modify)",
)
@click.option("--diff", "show_diff", is_flag=True, help="Show formatting changes as diff")
def fmt(
    input_file: str,
    output: str | None,
    style: str,
    check: bool,
    show_diff: bool,
) -> None:
    """Format YARA file using AST-based formatting (like black for Python)."""
    try:
        input_path = Path(input_file)
        output_path = Path(output) if output else input_path
        formatter = get_formatter()

        if check:
            _handle_format_check(formatter, input_path)
            return

        if show_diff:
            _show_format_diff(formatter, input_path, style)
            return

        _format_file(formatter, input_path, output_path, style)

    except Exception as e:
        print_cli_error(console, e)
        raise click.Abort from None


def _handle_format_check(formatter, input_path: Path) -> None:
    """Handle format checking mode."""
    needs_format, issues = check_format(formatter, input_path)
    display_format_check(console, input_path, needs_format, issues)
    if needs_format:
        raise click.Abort from None


def _show_format_diff(formatter, input_path: Path, style: str) -> None:
    """Show formatting diff."""
    original, success, formatted = format_for_diff(formatter, input_path, style)
    if not success:
        display_format_error(console, formatted)
        raise click.Abort from None
    display_format_diff(console, input_path, original, formatted)


def _format_file(formatter, input_path: Path, output_path: Path, style: str) -> None:
    """Format file and save result."""
    success, result = format_file(formatter, input_path, output_path, style)
    if not success:
        display_format_error(console, result)
        raise click.Abort from None
    display_format_result(console, input_path, output_path, style)
