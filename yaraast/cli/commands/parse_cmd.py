"""CLI command for parsing YARA files."""

from __future__ import annotations

import click
from rich.console import Console

from yaraast.cli.parse_reporting import (
    display_cli_error,
    generate_output_by_format,
    report_parsing_errors,
)
from yaraast.cli.parse_services import parse_content_by_dialect
from yaraast.cli.utils import read_text

console = Console()


@click.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output file (default: stdout)")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["yara", "json", "yaml", "tree"]),
    default="yara",
    help="Output format",
)
@click.option(
    "--dialect",
    type=click.Choice(["auto", "yara", "yara-x", "yara-l"]),
    default="auto",
    help="YARA dialect to use (auto-detect by default)",
)
def parse(input_file: str, output: str | None, output_format: str, dialect: str) -> None:
    """Parse a YARA file and output in various formats. Supports YARA, YARA-X, and YARA-L."""
    try:
        content = read_text(input_file)
        show_status = output_format not in {"json", "yaml"}
        ast, lexer_errors, parser_errors = parse_content_by_dialect(
            content,
            dialect,
            show_status,
            console.print,
        )
        if show_status:
            report_parsing_errors(lexer_errors, parser_errors, ast)
        if lexer_errors or parser_errors:
            raise SystemExit(1)
        generate_output_by_format(ast, output_format, output)

    except Exception as e:
        display_cli_error(console, e)
        raise click.Abort from None
