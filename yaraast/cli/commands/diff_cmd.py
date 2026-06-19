"""CLI command for AST-based diff showing logical vs stylistic changes."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from yaraast.cli.diff_reporting import (
    display_diff_header,
    display_no_changes,
    show_change_details,
    show_change_significance,
    show_diff_summary,
    show_rule_changes,
)
from yaraast.cli.simple_differ import SimpleASTDiffer

console = Console()


@click.command()
@click.argument("file1", type=click.Path(exists=True, dir_okay=False))
@click.argument("file2", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--logical-only",
    is_flag=True,
    help="Show only logical changes (ignore style)",
)
@click.option("--summary", is_flag=True, help="Show summary of changes only")
@click.option("--no-style", is_flag=True, help="Don't analyze style changes")
def diff(
    file1: str,
    file2: str,
    logical_only: bool,
    summary: bool,
    no_style: bool,
) -> None:
    """Show AST-based diff highlighting logical vs stylistic changes."""
    try:
        file1_path = Path(file1)
        file2_path = Path(file2)

        result = SimpleASTDiffer().diff_files(file1_path, file2_path)

        if not result.has_changes:
            display_no_changes(file1_path, file2_path)
            return

        display_diff_header(file1_path, file2_path)

        if summary:
            show_diff_summary(result)
            return

        show_rule_changes(result)
        show_change_details(result, logical_only, no_style)
        show_change_significance(result)

    except Exception as e:
        from rich.markup import escape

        console.print(f"[red]Error: {escape(str(e))}[/red]")
        raise click.Abort from e
