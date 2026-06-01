"""CLI command for formatting YARA files."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from yaraast.cli.format_reporting import (
    display_format_success,
    display_validation_error,
    display_validation_success,
)
from yaraast.cli.format_services import build_format_stats, format_ast
from yaraast.cli.utils import _require_file_path, print_cli_error
from yaraast.parser.source import parse_yara_source_with_comments

console = Console()


def _validate_output_file(output_file: str) -> Path:
    try:
        output_path = _require_file_path(output_file)
    except (TypeError, ValueError) as exc:
        raise click.BadParameter(str(exc), param_hint="OUTPUT_FILE") from exc
    if output_path.exists() and output_path.is_dir():
        raise click.BadParameter(
            "output path must not be a directory",
            param_hint="OUTPUT_FILE",
        )
    return output_path


@click.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
def format_yara(input_file: str, output_file: str) -> None:
    """Format a YARA file with consistent style."""
    output_path = _validate_output_file(output_file)
    try:
        source = Path(input_file).read_text(encoding="utf-8")
        ast = parse_yara_source_with_comments(source)

        formatted = format_ast(ast)

        output_path.write_text(formatted, encoding="utf-8")

        display_format_success(console, str(output_path))

    except Exception as e:
        print_cli_error(console, e)
        raise click.Abort from None


@click.command("validate-syntax")
@click.argument("input_file", type=click.Path(exists=True))
def validate_syntax(input_file: str) -> None:
    """Validate a YARA file for syntax errors."""
    try:
        source = Path(input_file).read_text(encoding="utf-8")
        ast = parse_yara_source_with_comments(source)

        stats = build_format_stats(ast)

        display_validation_success(console, input_file, stats)

    except Exception as e:
        display_validation_error(console, input_file, e)
        raise click.Abort from None
