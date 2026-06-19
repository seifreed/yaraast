"""CLI command for parsing YARA files."""

from __future__ import annotations

import click
from rich.console import Console

from yaraast.cli.parse_output_services import (
    _generate_output_by_format,
    _report_parsing_errors,
)
from yaraast.cli.parse_services import parse_content_by_dialect
from yaraast.cli.utils import _validate_output_path, print_cli_error, read_text

console = Console()
error_console = Console(stderr=True)


@click.command()
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False))
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
    output = _validate_output_path(output)
    try:
        content = read_text(input_file)
        show_status = output_format not in {"json", "yaml"}
        ast, lexer_errors, parser_errors = parse_content_by_dialect(
            content,
            dialect,
            show_status,
            console.print,
        )
        if lexer_errors or parser_errors:
            report_console = console if show_status else error_console
            _report_parsing_errors(lexer_errors, parser_errors, ast, report_console)
            raise SystemExit(1)
        _generate_output_by_format(ast, output_format, output)

    except Exception as e:
        print_cli_error(console, e)
        raise click.Abort from e
