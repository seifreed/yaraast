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
from yaraast.cli.utils import print_cli_error
from yaraast.parser.comment_aware_parser import CommentAwareParser

console = Console()


@click.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
def format_yara(input_file: str, output_file: str) -> None:
    """Format a YARA file with consistent style."""
    try:
        source = Path(input_file).read_text(encoding="utf-8")
        ast = CommentAwareParser().parse(source)

        formatted = format_ast(ast)

        Path(output_file).write_text(formatted, encoding="utf-8")

        display_format_success(console, output_file)

    except Exception as e:
        print_cli_error(console, e)
        raise click.Abort from None


@click.command("validate-syntax")
@click.argument("input_file", type=click.Path(exists=True))
def validate_syntax(input_file: str) -> None:
    """Validate a YARA file for syntax errors."""
    try:
        source = Path(input_file).read_text(encoding="utf-8")
        ast = CommentAwareParser().parse(source)

        stats = build_format_stats(ast)

        display_validation_success(console, input_file, stats)

    except Exception as e:
        display_validation_error(console, input_file, e)
        raise click.Abort from None
