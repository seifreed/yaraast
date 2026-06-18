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
from yaraast.cli.fmt_services import check_format, format_file, format_for_diff
from yaraast.cli.utils import _path_exists_and_is_dir, _require_file_path, print_cli_error
from yaraast.shared.ast_analysis import ASTFormatter

console = Console()


def _validate_output_path(input_path: Path, output: str | None) -> Path:
    if output is None:
        return input_path
    try:
        output_path = _require_file_path(output)
        if _path_exists_and_is_dir(output_path):
            raise click.BadParameter("output path must not be a directory", param_hint="--output")
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="--output") from exc
    return output_path


@click.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False))
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
    input_path = Path(input_file)
    output_path = _validate_output_path(input_path, output)
    try:
        formatter = ASTFormatter()

        if check:
            _handle_format_check(formatter, input_path)
            return

        if show_diff:
            _show_format_diff(formatter, input_path, style)
            return

        _format_file(formatter, input_path, output_path, style)

    except Exception as e:
        print_cli_error(console, e)
        raise click.Abort from e


def _handle_format_check(formatter, input_path: Path) -> None:
    """Handle format checking mode."""
    needs_format, issues = check_format(formatter, input_path)
    display_format_check(console, input_path, needs_format, issues)
    if needs_format:
        raise SystemExit(1) from None


def _show_format_diff(formatter, input_path: Path, style: str) -> None:
    """Show formatting diff."""
    original, success, formatted = format_for_diff(formatter, input_path, style)
    if not success:
        display_format_error(console, formatted)
        raise SystemExit(1) from None
    display_format_diff(console, input_path, original, formatted)


def _format_file(formatter, input_path: Path, output_path: Path, style: str) -> None:
    """Format file and save result."""
    success, result = format_file(formatter, input_path, output_path, style)
    if not success:
        display_format_error(console, result)
        raise SystemExit(1) from None
    display_format_result(console, input_path, output_path, style)
